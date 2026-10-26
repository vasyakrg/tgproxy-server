package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type fixture struct {
	svc   *Service
	st    *memtest.Store
	ca    *pki.Authority
	logs  *syncBuf
	clock *fakeClock
	mu    sync.Mutex
	notif []string
	obs   []string
	n     int
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := memtest.New()
	dir := t.TempDir()
	kp := filepath.Join(dir, "kek")
	if err := pki.GenerateKEK(kp); err != nil {
		t.Fatal(err)
	}
	kek, err := pki.LoadKEK(kp)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadOrInit(context.Background(), st.Certs(), kek, pki.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: st, ca: ca, clock: &fakeClock{t: time.Now()}}
	sb := &syncBuf{}
	f.logs = sb
	logger := slog.New(slog.NewTextHandler(sb, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.svc, err = New(Config{
		Enrollments: st.Enrollments(), Agents: st.Agents(), Audit: st.Audit(), CA: ca,
		GatewayURL: "https://tgp.example.com:8444", Logger: logger, Now: f.clock.now,
		Notify:  func(_ context.Context, id, _ string) { f.mu.Lock(); f.notif = append(f.notif, id); f.mu.Unlock() },
		Observe: func(r string) { f.mu.Lock(); f.obs = append(f.obs, r); f.mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func genCSR(t *testing.T, tmpl *x509.CertificateRequest, key any) string {
	t.Helper()
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func goodCSR(t *testing.T) string {
	return genCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, nil)
}

func (f *fixture) post(t *testing.T, body any, ip string) *httptest.ResponseRecorder {
	t.Helper()
	var buf []byte
	switch b := body.(type) {
	case string:
		buf = []byte(b)
	default:
		buf, _ = json.Marshal(b)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/enroll", bytes.NewReader(buf))
	r.RemoteAddr = ip + ":4444"
	w := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(w, r)
	return w
}

// enroll шлёт запрос с уникального IP, чтобы не упираться в rate-limit.
func (f *fixture) enroll(t *testing.T, token, csr string) *httptest.ResponseRecorder {
	f.n++
	return f.post(t, Request{Token: token, CSR: csr}, net.IPv4(192, 0, byte(f.n>>8), byte(f.n)).String())
}

func TestIssueAndEnrollSuccess(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	is, err := f.svc.IssueFor(ctx, IssueRequest{Name: "Home NAT #1", Weight: 70, CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"printf %s '" + is.Token + "' | sudo tgproxy agent enroll --token-stdin", "--server https://tgp.example.com:8444", "--ca-fingerprint " + f.ca.CAFingerprint()} {
		if !strings.Contains(is.Cmdline, want) {
			t.Errorf("cmdline %q lacks %q", is.Cmdline, want)
		}
	}
	if strings.Contains(is.Cmdline, "TGP_ENROLL_TOKEN") || strings.Contains(is.Cmdline, "--token ") {
		t.Errorf("cmdline must not put the token into sudo argv: %q", is.Cmdline)
	}
	// В БД нет токена в открытом виде.
	pend, _ := f.st.Enrollments().ListPending(ctx, f.clock.now())
	if len(pend) != 1 || len(pend[0].TokenHash) != 32 || strings.Contains(string(pend[0].TokenHash), is.Token) {
		t.Fatalf("pending: %+v", pend)
	}
	w := f.enroll(t, is.Token, goodCSR(t))
	if w.Code != http.StatusOK {
		t.Fatalf("code %d body %s", w.Code, w.Body)
	}
	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AgentID != "home-nat-1" {
		t.Errorf("agent id %q", resp.AgentID)
	}
	blk, _ := pem.Decode([]byte(resp.Cert))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := pki.AgentIDFromCert(cert); err != nil || id != resp.AgentID {
		t.Errorf("san id %q err %v", id, err)
	}
	if resp.CA != string(f.ca.CertPEM()) {
		t.Error("ca mismatch")
	}
	a, err := f.st.Agents().Get(ctx, resp.AgentID)
	if err != nil || a.Mode != store.ModeReverse || a.Weight != 70 || a.Name != "Home NAT #1" {
		t.Fatalf("agent %+v err %v", a, err)
	}
	if len(f.notif) != 1 || f.notif[0] != resp.AgentID {
		t.Errorf("notify %v", f.notif)
	}
	aud, _ := f.st.Audit().List(ctx, store.AuditQuery{})
	var seen bool
	for _, e := range aud {
		if e.Action == "agent.enroll" && e.Target == resp.AgentID && e.IP != "" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("no audit entry: %+v", aud)
	}
	if logs := f.logs.String(); strings.Contains(logs, is.Token) {
		t.Errorf("token leaked into logs: %s", logs)
	}
}

func TestTokenReuseUnauthorized(t *testing.T) {
	f := newFixture(t)
	tok, _, _ := f.svc.Issue(context.Background(), "a", 0)
	if w := f.enroll(t, tok, goodCSR(t)); w.Code != 200 {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	if w := f.enroll(t, tok, goodCSR(t)); w.Code != http.StatusUnauthorized {
		t.Fatalf("reuse: %d", w.Code)
	}
}

func TestExpiredAndUnknownToken(t *testing.T) {
	f := newFixture(t)
	tok, _, _ := f.svc.Issue(context.Background(), "a", time.Minute)
	f.clock.add(2 * time.Minute)
	if w := f.enroll(t, tok, goodCSR(t)); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired: %d", w.Code)
	}
	for _, bad := range []string{"AAAA", "not base64 !!", strings.Repeat("A", 43)} {
		if w := f.enroll(t, bad, goodCSR(t)); w.Code != http.StatusUnauthorized {
			t.Errorf("token %q: %d", bad, w.Code)
		}
	}
	if aud, _ := f.st.Audit().List(context.Background(), store.AuditQuery{}); len(aud) == 0 {
		t.Error("denied attempts not audited")
	}
}

func TestCSRValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ext := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}
	u, _ := url.Parse("spiffe://tgproxy/agent/victim")
	cases := map[string]string{
		"uri san":   genCSR(t, &x509.CertificateRequest{URIs: []*url.URL{u}}, ecKey),
		"dns san":   genCSR(t, &x509.CertificateRequest{DNSNames: []string{"x.example.com"}}, ecKey),
		"ip san":    genCSR(t, &x509.CertificateRequest{IPAddresses: []net.IP{net.IPv4(1, 2, 3, 4)}}, ecKey),
		"email san": genCSR(t, &x509.CertificateRequest{EmailAddresses: []string{"a@b.c"}}, ecKey),
		"p384":      genCSR(t, &x509.CertificateRequest{}, p384),
		"rsa":       genCSR(t, &x509.CertificateRequest{}, rsaKey),
		"basic":     genCSR(t, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{ext}}, ecKey),
		"garbage":   "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
		"not pem":   "hello",
		"wrong typ": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})),
	}
	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			tok, _, _ := f.svc.Issue(ctx, "n-"+strings.ReplaceAll(name, " ", "-"), 0)
			if w := f.enroll(t, tok, csr); w.Code != http.StatusUnprocessableEntity { //nolint:contextcheck // тестовый хелпер
				t.Fatalf("code %d body %s", w.Code, w.Body)
			}
			// токен не сожжён ошибкой CSR
			if w := f.enroll(t, tok, goodCSR(t)); w.Code != 200 { //nolint:contextcheck // тестовый хелпер
				t.Fatalf("retry after bad csr: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestBadCSRSignature(t *testing.T) {
	f := newFixture(t)
	csr := goodCSR(t)
	blk, _ := pem.Decode([]byte(csr))
	blk.Bytes[len(blk.Bytes)-3] ^= 0xff
	tok, _, _ := f.svc.Issue(context.Background(), "x", 0)
	if w := f.enroll(t, tok, string(pem.EncodeToMemory(blk))); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code %d", w.Code)
	}
}

func TestBadRequests(t *testing.T) {
	f := newFixture(t)
	for _, body := range []string{"", "{", `{"token":"x"}`, `{"csr":"x"}`} {
		if w := f.post(t, body, "192.0.2.9"); w.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", body, w.Code)
		}
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/enroll", nil)
	w := httptest.NewRecorder()
	f.svc.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}
	big := `{"token":"` + strings.Repeat("a", maxBodyBytes+10) + `","csr":"x"}`
	if w := f.post(t, big, "192.0.2.10"); w.Code != http.StatusBadRequest {
		t.Errorf("big: %d", w.Code)
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t)
	csr := goodCSR(t)
	for i := 1; i <= 5; i++ {
		if w := f.post(t, Request{Token: "AAAA", CSR: csr}, "198.51.100.7"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := f.post(t, Request{Token: "AAAA", CSR: csr}, "198.51.100.7")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("6th: %d", w.Code)
	}
	// другой IP не затронут
	if w := f.post(t, Request{Token: "AAAA", CSR: csr}, "198.51.100.8"); w.Code != http.StatusUnauthorized {
		t.Fatalf("other ip: %d", w.Code)
	}
	// окно сдвигается
	f.clock.add(61 * time.Second)
	if w := f.post(t, Request{Token: "AAAA", CSR: csr}, "198.51.100.7"); w.Code != http.StatusUnauthorized {
		t.Fatalf("after window: %d", w.Code)
	}
}

func TestLimiterGC(t *testing.T) {
	c := &fakeClock{t: time.Now()}
	l := newLimiter(1, time.Minute, c.now)
	for i := 0; i < 4100; i++ {
		l.allow(net.IPv4(10, byte(i>>8), byte(i), 1).String())
	}
	c.add(2 * time.Minute)
	l.allow("x")
	if len(l.hits) > 2 {
		t.Errorf("gc: %d", len(l.hits))
	}
}

func TestAgentIDConflictGetsSuffix(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.st.Agents().Create(ctx, store.Agent{ID: "dup", Name: "other", Mode: store.ModeReverse, Weight: 1}); err != nil {
		t.Fatal(err)
	}
	tok, _, _ := f.svc.Issue(ctx, "dup", 0)
	w := f.enroll(t, tok, goodCSR(t))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var resp Response
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.HasPrefix(resp.AgentID, "dup-") || !pki.ValidAgentID(resp.AgentID) {
		t.Errorf("id %q", resp.AgentID)
	}
}

type failAgents struct {
	store.AgentRepo
	err error
}

func (f failAgents) Create(context.Context, store.Agent) (store.Agent, error) {
	return store.Agent{}, f.err
}

type failCA struct {
	Authority
}

func (failCA) SignAgentCSR(context.Context, []byte, string, time.Duration) ([]byte, string, error) {
	return nil, "", errors.New("boom")
}

func TestInternalErrors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// ошибка создания агента -> 500
	svc, _ := New(Config{Enrollments: f.st.Enrollments(), Agents: failAgents{f.st.Agents(), errors.New("db down")}, Audit: f.st.Audit(), CA: f.ca, GatewayURL: "https://h:8444", Now: f.clock.now})
	is, _ := svc.IssueFor(ctx, IssueRequest{Name: "e1"})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/enroll", strings.NewReader(mustJSON(Request{Token: is.Token, CSR: goodCSR(t)})))
	r.RemoteAddr = "192.0.2.5:1"
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, r)
	if w.Code != 500 || strings.Contains(w.Body.String(), "db down") {
		t.Fatalf("create err: %d %s", w.Code, w.Body)
	}
	// ошибка подписи -> 500 и агент удалён
	svc2, _ := New(Config{Enrollments: f.st.Enrollments(), Agents: f.st.Agents(), Audit: f.st.Audit(), CA: failCA{Authority: f.ca}, GatewayURL: "https://h:8444", Now: f.clock.now})
	is2, _ := svc2.IssueFor(ctx, IssueRequest{Name: "e2"})
	r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/enroll", strings.NewReader(mustJSON(Request{Token: is2.Token, CSR: goodCSR(t)})))
	r.RemoteAddr = "192.0.2.6:1"
	w = httptest.NewRecorder()
	svc2.Handler().ServeHTTP(w, r)
	if w.Code != 500 {
		t.Fatalf("sign err: %d", w.Code)
	}
	if _, err := f.st.Agents().Get(ctx, "e2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("agent not rolled back: %v", err)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestIssueValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, r := range []IssueRequest{{Name: " "}, {Name: strings.Repeat("a", 65)}, {Name: "ok", TTL: 25 * time.Hour}} {
		if _, err := f.svc.IssueFor(ctx, r); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%+v: %v", r, err)
		}
	}
	if _, _, err := f.svc.Issue(ctx, "", 0); err == nil {
		t.Error("empty name accepted")
	}
	a, _ := f.svc.IssueFor(ctx, IssueRequest{Name: "t1"})
	b, _ := f.svc.IssueFor(ctx, IssueRequest{Name: "t2"})
	if a.Token == b.Token || len(a.Token) != 43 {
		t.Errorf("tokens: %q %q", a.Token, b.Token)
	}
	if d := a.ExpiresAt.Sub(f.clock.now()); d != time.Hour {
		t.Errorf("default ttl %s", d)
	}
}

func TestNewValidation(t *testing.T) {
	f := newFixture(t)
	base := Config{Enrollments: f.st.Enrollments(), Agents: f.st.Agents(), Audit: f.st.Audit(), CA: f.ca, GatewayURL: "https://h:8444"}
	if _, err := New(base); err != nil {
		t.Fatal(err)
	}
	c := base
	c.CA = nil
	if _, err := New(c); err == nil {
		t.Error("nil CA")
	}
	for _, u := range []string{"", "http://h:8444", "https://", "%%"} {
		c = base
		c.GatewayURL = u
		if _, err := New(c); err == nil {
			t.Errorf("url %q accepted", u)
		}
	}
}

func TestAgentSlug(t *testing.T) {
	cases := map[string]string{
		"Home NAT #1": "home-nat-1", "  ": "agent", "---": "agent", "Серверная": "agent",
		strings.Repeat("a", 80): strings.Repeat("a", 48), "a.b_c": "a.b_c",
	}
	for in, want := range cases {
		got := agentSlug(in)
		if got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
		if !pki.ValidAgentID(got) {
			t.Errorf("%q → invalid id %q", in, got)
		}
	}
}
