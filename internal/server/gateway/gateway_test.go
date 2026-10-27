package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

type lookup struct {
	mu  sync.Mutex
	ids map[string]string
}

func (l *lookup) Known(id string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.ids[id]
	return m, ok
}

type env struct {
	ca      *pki.CA
	pool    *x509.CertPool
	rp      *transport.ReversePool
	mt      *transport.ReverseStream
	gw      *Gateway
	addr    string
	signals chan int
	down    atomic.Int32
	denied  atomic.Value // *big.Int-строка серийника -> отказ
}

func issueAgent(t *testing.T, ca *pki.CA, id string) tls.Certificate {
	t.Helper()
	csr, key, err := pki.NewAgentCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := pki.IssueAgent(ca, csr, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pki.Bundle{CertPEM: certPEM, KeyPEM: key}.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newEnv(t *testing.T, opts ...Option) *env {
	t.Helper()
	ca, err := pki.NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pki.IssueServerClient(ca, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := b.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{ca: ca, pool: ca.Pool(), signals: make(chan int, 16)}
	e.rp = transport.NewReversePool(transport.WithOnDown(func(string) { e.down.Add(1) }))
	t.Cleanup(func() { _ = e.rp.Close() })
	e.mt = transport.NewReverseStream(transport.WithMTProtoMaxConns(2), transport.WithMTProtoStreamsPerConn(2),
		transport.WithMTProtoSignalInterval(10*time.Millisecond),
		transport.WithMTProtoOnSignal(func(_ string, n int) { e.signals <- n }))
	t.Cleanup(func() { _ = e.mt.Close() })
	deny := func(leaf *x509.Certificate) error {
		if s, _ := e.denied.Load().(string); s != "" && s == leaf.SerialNumber.String() {
			return errors.New("revoked")
		}
		return nil
	}
	opts = append([]Option{WithChecks(deny), WithLogger(slog.New(slog.DiscardHandler))}, opts...)
	gw, err := New(Config{
		Cert: srvCert, CA: e.pool, Pool: e.rp, MTProtoPool: e.mt,
		Lookup: &lookup{ids: map[string]string{"a1": "reverse", "a2": "reverse"}},
	}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.gw, e.addr = gw, ln.Addr().String()
	done := make(chan error, 1)
	go func() { done <- gw.Serve(ln) }()
	for gw.Addr() == nil {
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = gw.Shutdown(ctx)
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve returned %v", err)
		}
	})
	return e
}

func (e *env) clientCfg(cert *tls.Certificate, alpn ...string) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    e.pool,
		NextProtos: alpn,
		//nolint:gosec // идентичность проверяется в VerifyConnection
		InsecureSkipVerify: true,
		VerifyConnection:   pki.VerifyServerPeer(e.pool),
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func (e *env) dialTLS(t *testing.T, cfg *tls.Config) *tls.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*tls.Conn)
}

var echo = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(tgapi.HeaderSource, tgapi.SourceTelegram)
	_, _ = io.Copy(w, r.Body)
})

// connectAgent — фейковый агент: reverse ALPN + http2.Server.ServeConn.
func (e *env) connectAgent(t *testing.T, cert tls.Certificate, h http.Handler) *tls.Conn {
	t.Helper()
	c := e.dialTLS(t, e.clientCfg(&cert, transport.ALPNReverse))
	go (&http2.Server{}).ServeConn(c, &http2.ServeConnOpts{Handler: h}) //nolint:staticcheck // SA1019: ServeConn поверх готового соединения
	return c
}

func (e *env) waitConns(t *testing.T, id string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e.rp.Conns(id) == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("conns(%s)=%d, want %d", id, e.rp.Conns(id), n)
}

func ref(id string) transport.AgentRef {
	return transport.AgentRef{ID: id, Mode: config.AgentModeReverse}
}

func (e *env) post(t *testing.T, id string, body io.Reader) (*http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/tg/bot1:AAA/sendMessage", body)
	resp, err := e.rp.RoundTrip(ctx, ref(id), req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	return resp, err
}

// expectClosed: сервер закрыл соединение, не дав обслужить запрос.
func expectClosed(t *testing.T, c *tls.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection was not closed by the gateway")
	}
}

func TestReverseSendMessageThroughGateway(t *testing.T) {
	e := newEnv(t)
	e.connectAgent(t, issueAgent(t, e.ca, "a1"), echo)
	e.waitConns(t, "a1", 1)
	body := bytes.Repeat([]byte(`{"chat_id":1,"text":"привет"}`), 1000)
	resp, err := e.post(t, "a1", bytes.NewReader(body)) //nolint:bodyclose // закрывается в t.Cleanup
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, body) {
		t.Fatal("body mismatch")
	}
}

func TestReverseStream20MBThroughGateway(t *testing.T) {
	const size = 20 << 20
	e := newEnv(t)
	e.connectAgent(t, issueAgent(t, e.ca, "a1"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(tgapi.HeaderSource, tgapi.SourceTelegram)
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				fl.Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	e.waitConns(t, "a1", 1)
	hs, hr := sha256.New(), sha256.New()
	src := io.NopCloser(io.TeeReader(io.LimitReader(patternReader{}, size), hs))
	resp, err := e.post(t, "a1", src) //nolint:bodyclose // закрывается в t.Cleanup
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(hr, resp.Body)
	if err != nil || n != size || !bytes.Equal(hs.Sum(nil), hr.Sum(nil)) {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

type patternReader struct{}

func (patternReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i * 13)
	}
	return len(b), nil
}

func TestRejectedPeersClosedBeforeFirstRequest(t *testing.T) {
	e := newEnv(t)
	foreign, _ := pki.NewCA("foreign", 24*time.Hour)
	revoked := issueAgent(t, e.ca, "a1")
	leaf, _ := x509.ParseCertificate(revoked.Certificate[0])
	e.denied.Store(leaf.SerialNumber.String())

	tests := []struct {
		name string
		cert *tls.Certificate
	}{
		{"чужой CA", ptr(issueAgent(t, foreign, "a1"))},
		{"denylist", &revoked},
		{"неизвестный агент", ptr(issueAgent(t, e.ca, "ghost"))},
		{"серт сервера вместо агента", func() *tls.Certificate {
			b, _ := pki.IssueServerClient(e.ca, time.Hour)
			c, _ := b.TLSCertificate()
			return &c
		}()},
		{"без сертификата", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := e.dialTLS(t, e.clientCfg(tc.cert, transport.ALPNReverse))
			// клиент мог «закончить» TLS 1.3 раньше сервера — пробуем h2
			go (&http2.Server{}).ServeConn(c, &http2.ServeConnOpts{Handler: echo}) //nolint:staticcheck // SA1019
			expectClosed(t, c)
		})
	}
	for _, id := range []string{"a1", "ghost"} {
		if e.rp.Conns(id) != 0 {
			t.Fatalf("conns(%s)=%d", id, e.rp.Conns(id))
		}
		_, err := e.post(t, id, bytes.NewReader([]byte("x"))) //nolint:bodyclose // закрывается в t.Cleanup
		var pe *transport.PhaseError
		if !errors.As(err, &pe) || pe.Phase != tgapi.PhaseDial {
			t.Fatalf("RoundTrip(%s) = %v, want dial", id, err)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func TestTwoConnsDropOneThenAllThenReconnect(t *testing.T) {
	e := newEnv(t)
	cert := issueAgent(t, e.ca, "a1")
	c1 := e.connectAgent(t, cert, echo)
	c2 := e.connectAgent(t, cert, echo)
	e.waitConns(t, "a1", 2)
	_ = c1.Close()
	for range 100 {
		resp, err := e.post(t, "a1", bytes.NewReader([]byte("hi"))) //nolint:bodyclose // закрывается в t.Cleanup
		if err != nil {
			t.Fatalf("error with live second conn: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	e.waitConns(t, "a1", 1)
	_ = c2.Close()
	e.waitConns(t, "a1", 0)
	deadline := time.Now().Add(5 * time.Second)
	for e.down.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.down.Load() != 1 {
		t.Fatalf("OnDown=%d", e.down.Load())
	}
	e.connectAgent(t, cert, echo)
	e.waitConns(t, "a1", 1)
	if _, err := e.post(t, "a1", bytes.NewReader([]byte("again"))); err != nil { //nolint:bodyclose // закрывается в t.Cleanup
		t.Fatal(err)
	}
}

func TestThirdConnEvictsOldest(t *testing.T) {
	e := newEnv(t)
	cert := issueAgent(t, e.ca, "a1")
	c1 := e.connectAgent(t, cert, echo)
	e.waitConns(t, "a1", 1)
	e.connectAgent(t, cert, echo)
	e.waitConns(t, "a1", 2)
	e.connectAgent(t, cert, echo)
	expectClosed(t, c1)
	e.waitConns(t, "a1", 2)
}

// --- обычный HTTP ---

func (e *env) httpClient(cert *tls.Certificate) *http.Client {
	cfg := e.clientCfg(cert, "h2", "http/1.1")
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}, Timeout: 10 * time.Second}
}

func (e *env) do(t *testing.T, c *http.Client, method, path string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, "https://"+e.addr+path, http.NoBody)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestHTTPDefaultsAre404(t *testing.T) {
	e := newEnv(t)
	c := e.httpClient(nil)
	for _, p := range []string{"/enroll", "/enroll/package/tgproxy_1.0.0_amd64.deb", "/_agent_gw/packages/1.0.0", "/", "/_agent/status"} {
		method := http.MethodPost
		if p != "/enroll" {
			method = http.MethodGet
		}
		if r := e.do(t, c, method, p); r != 404 {
			t.Fatalf("%s: %d", p, r)
		}
	}
}

func TestHTTPEnrollAndPackagesHandlers(t *testing.T) {
	var enrolled atomic.Int32
	var pkgAgent atomic.Value
	e := newEnv(t,
		WithEnrollHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			enrolled.Add(1)
			if _, ok := AgentIDFromContext(r.Context()); ok {
				t.Error("agent id on cert-less request")
			}
			if r.TLS == nil || r.ProtoMajor != 2 {
				t.Errorf("tls=%v proto=%s", r.TLS != nil, r.Proto)
			}
			w.WriteHeader(http.StatusCreated)
		})),
		WithPackagesHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, _ := AgentIDFromContext(r.Context())
			pkgAgent.Store(id)
			_, _ = w.Write([]byte("deb"))
		})))
	anon := e.httpClient(nil)
	if r := e.do(t, anon, http.MethodPost, "/enroll"); r != http.StatusCreated {
		t.Fatalf("enroll: %d", r)
	}
	if r := e.do(t, anon, http.MethodGet, "/enroll"); r != http.StatusMethodNotAllowed {
		t.Fatalf("GET enroll: %d", r)
	}
	if r := e.do(t, anon, http.MethodGet, "/_agent_gw/packages/1.0.0"); r != 200 || pkgAgent.Load() != "" {
		t.Fatalf("anon pkg: %d %v", r, pkgAgent.Load())
	}
	cert := issueAgent(t, e.ca, "a2")
	if r := e.do(t, e.httpClient(&cert), http.MethodGet, "/_agent_gw/packages/1.0.0"); r != 200 || pkgAgent.Load() != "a2" {
		t.Fatalf("agent pkg: %d %v", r, pkgAgent.Load())
	}
	if enrolled.Load() != 1 {
		t.Fatalf("enroll calls=%d", enrolled.Load())
	}
}

func TestHTTPEnrollPackageHandler(t *testing.T) {
	var got atomic.Value
	e := newEnv(t, WithEnrollPackageHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.URL.Path)
		if _, ok := AgentIDFromContext(r.Context()); ok {
			t.Error("agent id on cert-less request")
		}
		_, _ = w.Write([]byte("deb"))
	})))
	if r := e.do(t, e.httpClient(nil), http.MethodGet, "/enroll/package/tgproxy_1.0.0_amd64.deb"); r != 200 || got.Load() != "/enroll/package/tgproxy_1.0.0_amd64.deb" {
		t.Fatalf("pkg: %d %v", r, got.Load())
	}
	// /enroll остаётся независимым (без своего обработчика — 404)
	if r := e.do(t, e.httpClient(nil), http.MethodPost, "/enroll"); r != 404 {
		t.Fatalf("enroll: %d", r)
	}
}

func TestHTTPWithBadCertRejected(t *testing.T) {
	e := newEnv(t, WithPackagesHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler must not run")
	})))
	cert := issueAgent(t, e.ca, "ghost")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+e.addr+"/_agent_gw/packages/x", http.NoBody)
	resp, err := e.httpClient(&cert).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("request from unknown agent must fail")
	}
}

func TestNewValidationAndShutdown(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error")
	}
	e := newEnv(t)
	if e.gw.Addr() == nil {
		t.Fatal("Addr nil")
	}
	g2, _ := New(Config{CA: e.pool, Lookup: &lookup{}, Pool: e.rp})
	if g2.Addr() != nil {
		t.Fatal("Addr before Serve")
	}
	if err := g2.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	ln, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err := g2.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve after Shutdown: %v", err)
	}
	if err := g2.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestListenAndServe(t *testing.T) {
	e := newEnv(t)
	g, _ := New(Config{Cert: tls.Certificate{}, CA: e.pool, Lookup: &lookup{}, Pool: e.rp})
	go func() { _ = g.ListenAndServe("127.0.0.1:0") }()
	deadline := time.Now().Add(5 * time.Second)
	for g.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if g.Addr() == nil {
		t.Fatal("not listening")
	}
	if err := g.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.ListenAndServe("256.0.0.1:1"); err == nil {
		t.Fatal("bad addr must fail")
	}
}

func TestHandshakeFailureAndAttachFailure(t *testing.T) {
	e := newEnv(t, WithHandshakeTimeout(200*time.Millisecond))
	// клиент молчит: рукопожатие обрывается по таймауту
	c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("silent client not dropped")
		}
	}
	// Attach закрыл пул -> соединение закрывается
	_ = e.rp.Close()
	cert := issueAgent(t, e.ca, "a1")
	cc := e.dialTLS(t, e.clientCfg(&cert, transport.ALPNReverse))
	expectClosed(t, cc)
}
