package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

func postCSR(t *testing.T, e *env) []byte {
	t.Helper()
	resp := e.do(t, http.MethodPost, "/_agent/csr", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("csr: %d %s", resp.StatusCode, readAll(t, resp.Body))
	}
	var m map[string]string
	if err := json.Unmarshal(readAll(t, resp.Body), &m); err != nil {
		t.Fatal(err)
	}
	return []byte(m["csr"])
}

func putCert(t *testing.T, e *env, certPEM []byte) int {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"cert": string(certPEM)})
	resp := e.do(t, http.MethodPut, "/_agent/cert", map[string]string{"Content-Type": "application/json"}, bytes.NewReader(b))
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func leafOf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestCSRContent(t *testing.T) {
	e := newEnv(t, tgOK())
	first := postCSR(t, e)
	req, err := x509.ParseCertificateRequest(func() []byte { b, _ := pem.Decode(first); return b.Bytes }())
	if err != nil {
		t.Fatal(err)
	}
	if err := req.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if len(req.URIs) != 1 || req.URIs[0].String() != "spiffe://tgproxy/agent/a1" {
		t.Fatalf("SAN: %v", req.URIs)
	}
	if pub, ok := req.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Fatal("not P-256")
	}
	next := e.cfg.TLS.KeyFile + ".next"
	if m := mode(t, next); m != 0o600 {
		t.Fatalf("pending mode %v", m)
	}
	// ключ не покидает процесс
	resp := e.do(t, http.MethodPost, "/_agent/csr", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if body := string(readAll(t, resp.Body)); strings.Contains(body, "PRIVATE") {
		t.Fatal("private key leaked")
	}
	// повторный вызов заменил pending: сертификат на первый CSR не принимается
	certPEM, err := pki.IssueAgent(e.ca, first, "a1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := putCert(t, e, certPEM); code != 422 {
		t.Fatalf("stale csr: %d", code)
	}
}

func TestCertRotationLiveDial(t *testing.T) {
	e := newEnv(t, tgOK())
	oldSerial := e.agent.certs.get().leaf.SerialNumber

	// Долгоживущее h2-соединение до ротации.
	var reused bool
	do := func() *http.Response { //nolint:bodyclose // тело закрыто внутри
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }})
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+e.addr+"/_agent/healthz", nil)
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	if r := do(); r.StatusCode != 200 || //nolint:bodyclose
		r.TLS.PeerCertificates[0].SerialNumber.Cmp(oldSerial) != 0 {
		t.Fatalf("pre: %d", r.StatusCode)
	}

	csr := postCSR(t, e)
	certPEM, err := pki.IssueAgent(e.ca, csr, "a1", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := putCert(t, e, certPEM); code != 204 {
		t.Fatalf("put: %d", code)
	}
	newLeaf := leafOf(t, certPEM)

	// Старое соединение живо и отдаёт старый серт.
	r := do() //nolint:bodyclose // тело закрыто в do
	if r.StatusCode != 200 || !reused {
		t.Fatalf("old conn: %d reused=%v", r.StatusCode, reused)
	}
	if r.TLS.PeerCertificates[0].SerialNumber.Cmp(oldSerial) != 0 {
		t.Fatal("existing connection changed cert")
	}
	// Новое рукопожатие — с новым сертом.
	c2 := e.newClient(t, e.srvCert, true)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+e.addr+"/_agent/healthz", nil)
	resp, err := c2.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.TLS.PeerCertificates[0].SerialNumber.Cmp(newLeaf.SerialNumber) != 0 {
		t.Fatal("new handshake uses old cert")
	}
	if !e.agent.certNotAfter().Equal(newLeaf.NotAfter) {
		t.Fatal("notAfter not updated")
	}

	// Файлы: 0600 ключ, нет .next, пара грузится, повторный старт агента работает.
	if m := mode(t, e.cfg.TLS.KeyFile); m != 0o600 {
		t.Fatalf("key mode %v", m)
	}
	if _, err := os.Stat(e.cfg.TLS.KeyFile + ".next"); !os.IsNotExist(err) {
		t.Fatal(".next remains")
	}
	if _, err := tls.LoadX509KeyPair(e.cfg.TLS.CertFile, e.cfg.TLS.KeyFile); err != nil {
		t.Fatal(err)
	}
	a2, err := New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || a2.certs.get().leaf.SerialNumber.Cmp(newLeaf.SerialNumber) != 0 {
		t.Fatalf("restart: %v", err)
	}
	// pending сброшен
	if code := putCert(t, e, certPEM); code != 409 {
		t.Fatalf("second put: %d", code)
	}
}

func TestCertRejections(t *testing.T) {
	e := newEnv(t, tgOK())
	good := func() ([]byte, []byte) {
		csr := postCSR(t, e)
		c, err := pki.IssueAgent(e.ca, csr, "a1", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return csr, c
	}
	// нет pending → 409
	_, c0 := func() ([]byte, []byte) {
		csr, _, _ := pki.NewAgentCSR("a1")
		c, _ := pki.IssueAgent(e.ca, csr, "a1", time.Hour)
		return csr, c
	}()
	if code := putCert(t, e, c0); code != 409 {
		t.Fatalf("no pending: %d", code)
	}
	cases := map[string]func(csr []byte) []byte{
		"other key": func([]byte) []byte { return c0 },
		"foreign CA": func(csr []byte) []byte {
			ca2, _ := pki.NewCA("evil", time.Hour)
			c, _ := pki.IssueAgent(ca2, csr, "a1", time.Hour)
			return c
		},
		"other agent id": func(csr []byte) []byte {
			c, _ := pki.IssueAgent(e.ca, csr, "a2", time.Hour)
			return c
		},
		"garbage": func([]byte) []byte { return []byte("nope") },
		"ca cert": func([]byte) []byte { return e.ca.CertPEM() },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			csr, _ := good()
			before := mustRead(t, e.cfg.TLS.CertFile)
			if code := putCert(t, e, mk(csr)); code != 422 {
				t.Fatalf("%s: %d", name, code)
			}
			if !bytes.Equal(before, mustRead(t, e.cfg.TLS.CertFile)) {
				t.Fatal("cert file changed on reject")
			}
		})
	}
	t.Run("expired", func(t *testing.T) {
		_, c := good()
		e.agent.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
		defer func() { e.agent.now = time.Now }()
		if code := putCert(t, e, c); code != 422 {
			t.Fatalf("expired: %d", code)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		resp := e.do(t, http.MethodPut, "/_agent/cert", nil, strings.NewReader("{"))
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 400 {
			t.Fatalf("%d", resp.StatusCode)
		}
	})
	// после всех отказов валидный серт всё ещё принимается
	csr, c := good()
	_ = csr
	if code := putCert(t, e, c); code != 204 {
		t.Fatalf("valid after rejects: %d", code)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPendingSurvivesRestart(t *testing.T) {
	e := newEnv(t, tgOK())
	csr := postCSR(t, e)
	certPEM, err := pki.IssueAgent(e.ca, csr, "a1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// «рестарт»: новый Agent без памяти о pending читает .next
	a2, err := New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.agent.pendMu.Lock()
	e.agent.pending = nil
	e.agent.pendMu.Unlock()
	_ = a2
	if code := putCert(t, e, certPEM); code != 204 {
		t.Fatalf("put after restart: %d", code)
	}
}

func TestLoadKeyPairRecoversInterruptedRotation(t *testing.T) {
	e, _ := newEnvNoAgent(t, tgOK())
	csr, key, _ := pki.NewAgentCSR("a1")
	certPEM, _ := pki.IssueAgent(e.ca, csr, "a1", time.Hour)
	// сбой между rename(crt) и rename(key): новый crt, старый key, новый ключ в .next
	if err := os.WriteFile(e.cfg.TLS.CertFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.cfg.TLS.KeyFile+".next", key, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if a.certs.get().leaf.SerialNumber.Cmp(leafOf(t, certPEM).SerialNumber) != 0 {
		t.Fatal("not recovered")
	}
	if _, err := os.Stat(e.cfg.TLS.KeyFile + ".next"); !os.IsNotExist(err) {
		t.Fatal(".next remains")
	}
	// без .next — исходная ошибка
	_ = os.Remove(e.cfg.TLS.KeyFile)
	if _, err := loadKeyPair(e.cfg.TLS.CertFile, e.cfg.TLS.KeyFile); err == nil {
		t.Fatal("want error")
	}
	// .next не подходит — исходная ошибка
	_, k2, _ := pki.NewAgentCSR("a1")
	_ = os.WriteFile(e.cfg.TLS.KeyFile, k2, 0o600)
	_ = os.WriteFile(e.cfg.TLS.KeyFile+".next", k2, 0o600)
	if _, err := loadKeyPair(e.cfg.TLS.CertFile, e.cfg.TLS.KeyFile); err == nil {
		t.Fatal("want mismatch error")
	}
}

func TestRotationLiveReverse(t *testing.T) {
	r := newRevEnv(t, config.AgentModeReverse, true)
	gc := r.gw.next(t)
	_ = r.gw.next(t) // второй слот
	oldSerial := gc.conn.(*tls.Conn).ConnectionState().PeerCertificates[0].SerialNumber

	// Ротация по самому reverse-каналу; соединение не рвётся.
	resp, body := gc.do(t, http.MethodPost, "/_agent/csr", "")
	if resp.StatusCode != 200 {
		t.Fatalf("csr: %d", resp.StatusCode)
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	certPEM, err := pki.IssueAgent(r.ca, []byte(m["csr"]), "a1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"cert": string(certPEM)})
	if resp, _ := gc.do(t, http.MethodPut, "/_agent/cert", string(b)); resp.StatusCode != 204 {
		t.Fatalf("put: %d", resp.StatusCode)
	}
	if st := status(t, gc); st["reverse_state"] == nil {
		t.Fatal("conn broken")
	}

	// Новое рукопожатие (после обрыва) идёт с новым сертом.
	r.gw.mu.Lock()
	for _, c := range r.gw.all {
		_ = c.conn.Close()
	}
	r.gw.mu.Unlock()
	newLeaf := leafOf(t, certPEM)
	waitFor(t, "reconnect with new cert", func() bool {
		select {
		case c := <-r.gw.cc:
			return c.conn.(*tls.Conn).ConnectionState().PeerCertificates[0].SerialNumber.Cmp(newLeaf.SerialNumber) == 0
		default:
			return false
		}
	})
	if newLeaf.SerialNumber.Cmp(oldSerial) == 0 {
		t.Fatal("serial unchanged")
	}
}

func TestCSRHandlerErrors(t *testing.T) {
	e := newEnv(t, tgOK())
	// нечитаемое место для pending → 500, без утечки деталей
	e.agent.cfg.TLS.KeyFile = e.cfg.TLS.KeyFile + "/nope/key"
	resp := e.do(t, http.MethodPost, "/_agent/csr", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 500 {
		t.Fatalf("%d", resp.StatusCode)
	}
	// агент без распознаваемого id
	e.agent.certs.set(&heldCert{cert: &tls.Certificate{}})
	resp2 := e.do(t, http.MethodPost, "/_agent/csr", nil, nil)
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != 500 {
		t.Fatalf("no id: %d", resp2.StatusCode)
	}
	if code := putCert(t, e, []byte("x")); code != 409 && code != 500 {
		t.Fatalf("put no id: %d", code)
	}
	var h certHolder
	if _, err := h.serverCert(nil); err == nil {
		t.Fatal("want error")
	}
	if _, err := h.clientCert(nil); err == nil {
		t.Fatal("want error")
	}
	if !(&Agent{}).certNotAfter().IsZero() {
		t.Fatal("zero expected")
	}
	if _, err := newHeldCert(tls.Certificate{}); err == nil {
		t.Fatal("want error")
	}
	if _, err := newHeldCert(tls.Certificate{Certificate: [][]byte{{1}}}); err == nil {
		t.Fatal("want parse error")
	}
}
