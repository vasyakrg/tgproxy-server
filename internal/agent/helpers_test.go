package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

type env struct {
	ca       *pki.CA
	pool     *x509.CertPool
	srvCert  tls.Certificate // сертификат tgproxy-server (клиент агента)
	agCert   tls.Certificate // сертификат агента
	cfg      *config.AgentConfig
	upstream *httptest.Server
	agent    *Agent
	addr     string
	client   *http.Client
}

func newPKI(t *testing.T) (*pki.CA, tls.Certificate, tls.Certificate, string) {
	t.Helper()
	ca, err := pki.NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := pki.IssueServerClient(ca, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := sb.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	csr, key, err := pki.NewAgentCSR("a1")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := pki.IssueAgent(ca, csr, "a1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agCert, err := tls.X509KeyPair(certPEM, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("agent.crt", certPEM)
	write("agent.key", key)
	write("ca.crt", ca.CertPEM())
	return ca, srvCert, agCert, dir
}

// newEnv поднимает агента с mTLS и фейковым Telegram (TLS-сервер).
func newEnv(t *testing.T, tg http.Handler) *env {
	t.Helper()
	e, upPool := newEnvNoAgent(t, tg)
	e.startAgent(t, WithUpstreamRootCAs(upPool))
	return e
}

// newEnvNoAgent готовит PKI, конфиг и фейковый Telegram без запуска агента.
func newEnvNoAgent(t *testing.T, tg http.Handler) (*env, *x509.CertPool) {
	t.Helper()
	ca, srvCert, agCert, dir := newPKI(t)
	e := &env{ca: ca, pool: ca.Pool(), srvCert: srvCert, agCert: agCert}
	e.upstream = httptest.NewTLSServer(tg)
	t.Cleanup(e.upstream.Close)

	cfg := config.DefaultAgent()
	cfg.Listen.API = "127.0.0.1:0"
	cfg.TLS = config.TLSFiles{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	if err := cfg.OverrideTelegramAPIURL(e.upstream.URL); err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg

	upPool := x509.NewCertPool()
	upPool.AddCert(e.upstream.Certificate())
	return e, upPool
}

func (e *env) startAgent(t *testing.T, opts ...Option) {
	t.Helper()
	a, err := New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), opts...)
	if err != nil {
		t.Fatal(err)
	}
	e.agent = a
	ln, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	e.client = e.newClient(t, e.srvCert, true)
}

func (e *env) newClient(t *testing.T, cert tls.Certificate, withCert bool) *http.Client {
	t.Helper()
	cfg, err := pki.ClientTLSConfig(cert, e.pool, pki.VerifyAgentPeer(e.pool, "a1"))
	if err != nil {
		t.Fatal(err)
	}
	if !withCert {
		cfg.Certificates = nil
	}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}

func (e *env) do(t *testing.T, method, path string, hdr map[string]string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "https://"+e.addr+path, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readAll(t, resp.Body), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// closedAddr возвращает адрес, на котором никто не слушает.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	_ = ln.Close()
	return a
}

type prWrap struct{ pr httputil.ProxyRequest }

func proxyRequest(in, out *http.Request) *prWrap {
	return &prWrap{pr: httputil.ProxyRequest{In: in, Out: out}}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func listenLocal() (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
}
