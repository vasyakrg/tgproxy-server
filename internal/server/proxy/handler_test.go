package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/router"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

const tok = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

var tokRe = regexp.MustCompile(`[0-9]{5,15}:[A-Za-z0-9_-]{30,}`)

type fakeUp struct {
	mu   sync.Mutex
	req  *http.Request
	dl   time.Duration
	fn   func(ctx context.Context, req *http.Request) (*http.Response, error)
	body string
}

func (f *fakeUp) RoundTrip(ctx context.Context, _ string, req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.req = req
	if dl, ok := ctx.Deadline(); ok {
		f.dl = time.Until(dl)
	}
	if f.fn != nil {
		return f.fn(ctx, req)
	}
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		f.body = string(b)
		if err != nil {
			return nil, err
		}
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-TGP-Source", "telegram")
	h.Set("X-TGP-Upstream-Ms", "5")
	h.Set("X-Custom", "yes")
	h.Set("Connection", "close")
	return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
}

type env struct {
	h   http.Handler
	up  *fakeUp
	log *bytes.Buffer
}

func setup(t *testing.T, mut func(*config.ServerConfig)) *env {
	t.Helper()
	k := sha256.Sum256([]byte("k1"))
	cfg := config.DefaultServer()
	cfg.Agents = []config.AgentEndpoint{{ID: "a1"}}
	cfg.WebhookPolicy = config.WebhookDeny
	cfg.AccessRules = []config.AccessRule{
		{Name: "lan", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		{Name: "ext", KeySHA256: "x", KeyHash: k[:]},
		{Name: "both", KeySHA256: "x", KeyHash: func() []byte { s := sha256.Sum256([]byte("k2")); return s[:] }(),
			CIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}},
	}
	if mut != nil {
		mut(cfg)
	}
	chk, err := access.NewStatic(cfg.AccessRules, cfg.TrustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	up := &fakeUp{}
	buf := &bytes.Buffer{}
	log := slog.New(redact.NewHandler(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &env{h: New(chk, router.New(cfg, up, log), cfg, log), up: up, log: buf}
}

func (e *env) do(method, target, remote string, body io.Reader, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, target, body)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func errDesc(t *testing.T, w *httptest.ResponseRecorder, code int, desc string) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("code %d body %s", w.Code, w.Body)
	}
	var env tgapi.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.OK || env.ErrorCode != code || env.Description != desc {
		t.Fatalf("%s %v", w.Body, err)
	}
}

func TestNetworkRuleNoKey(t *testing.T) {
	e := setup(t, nil)
	w := e.do("GET", "/bot"+tok+"/getMe", "10.1.2.3:555", nil, nil)
	if w.Code != 200 || w.Body.String() != `{"ok":true}` {
		t.Fatal(w.Code, w.Body)
	}
	if e.up.req.URL.Path != "/tg/bot"+tok+"/getMe" {
		t.Fatal(e.up.req.URL)
	}
}

func TestForeignNetworkDenied(t *testing.T) {
	e := setup(t, nil)
	errDesc(t, e.do("GET", "/bot"+tok+"/getMe", "8.8.8.8:1", nil, nil), 403, descDenied)
	if e.up.req != nil {
		t.Fatal("reached upstream")
	}
}

func TestKeyInPath(t *testing.T) {
	e := setup(t, nil)
	w := e.do("GET", "/k/k1/bot"+tok+"/getMe?a=b", "8.8.8.8:1", nil, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if strings.Contains(e.up.req.URL.String(), "k1") || e.up.req.URL.RawQuery != "a=b" {
		t.Fatal(e.up.req.URL)
	}
	errDesc(t, e.do("GET", "/k/bad/bot"+tok+"/getMe", "8.8.8.8:1", nil, nil), 403, descDenied)
}

func TestKeyHeader(t *testing.T) {
	e := setup(t, nil)
	w := e.do("GET", "/bot"+tok+"/getMe", "8.8.8.8:1", nil, map[string]string{"X-Proxy-Key": "k1"})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if e.up.req.Header.Get("X-Proxy-Key") != "" {
		t.Fatal("key header leaked")
	}
}

func TestKeyPlusNetwork(t *testing.T) {
	e := setup(t, nil)
	if w := e.do("GET", "/k/k2/bot"+tok+"/getMe", "192.168.1.1:1", nil, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	errDesc(t, e.do("GET", "/k/k2/bot"+tok+"/getMe", "8.8.8.8:1", nil, nil), 403, descDenied)
}

func TestXFFUntrustedIgnored(t *testing.T) {
	e := setup(t, nil)
	w := e.do("GET", "/bot"+tok+"/getMe", "8.8.8.8:1", nil, map[string]string{"X-Forwarded-For": "10.1.1.1"})
	errDesc(t, w, 403, descDenied)
}

func TestXFFTrusted(t *testing.T) {
	e := setup(t, func(c *config.ServerConfig) {
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}
	})
	w := e.do("GET", "/bot"+tok+"/getMe", "172.16.0.1:1", nil, map[string]string{"X-Forwarded-For": "10.1.1.1"})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if e.up.req.Header.Get("X-Forwarded-For") != "" {
		t.Fatal("xff leaked")
	}
}

func TestBadPath404(t *testing.T) {
	e := setup(t, nil)
	errDesc(t, e.do("GET", "/nothing", "10.1.1.1:1", nil, nil), 404, descNotFound)
}

func TestWebhook(t *testing.T) {
	e := setup(t, nil)
	errDesc(t, e.do("POST", "/bot"+tok+"/setWebhook", "10.1.1.1:1", nil, nil), 403, descWebhook)
	if e.up.req != nil {
		t.Fatal("reached upstream")
	}
	e = setup(t, func(c *config.ServerConfig) { c.WebhookPolicy = config.WebhookPassthrough })
	if w := e.do("POST", "/bot"+tok+"/setWebhook", "10.1.1.1:1", nil, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if !strings.Contains(e.log.String(), `"level":"WARN"`) {
		t.Fatal("no warn:", e.log)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestBodyTooLarge(t *testing.T) {
	// известный Content-Length
	e := setup(t, nil)
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/bot"+tok+"/sendDocument", io.LimitReader(zeros{}, 52<<20))
	r.ContentLength = 52 << 20
	r.RemoteAddr = "10.1.1.1:1"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	errDesc(t, w, 413, descTooLarge)
	if e.up.req != nil {
		t.Fatal("reached upstream")
	}
	// chunked: ловим на чтении
	e = setup(t, nil)
	r = httptest.NewRequestWithContext(context.Background(), "POST", "/bot"+tok+"/sendDocument", io.LimitReader(zeros{}, 52<<20))
	r.ContentLength = -1
	r.RemoteAddr = "10.1.1.1:1"
	w = httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	errDesc(t, w, 413, descTooLarge)
}

func TestResponseHeaders(t *testing.T) {
	e := setup(t, nil)
	w := e.do("GET", "/bot"+tok+"/getMe", "10.1.1.1:1", nil, nil)
	id := w.Header().Get("X-Request-ID")
	if _, err := ulid.ParseStrict(id); err != nil {
		t.Fatalf("id %q", id)
	}
	if w.Header().Get("X-Custom") != "yes" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatal(w.Header())
	}
	for k := range w.Header() {
		if strings.HasPrefix(k, "X-Tgp-") || k == "Connection" {
			t.Fatalf("leaked %s", k)
		}
	}
	// ошибки тоже содержат id
	if w := e.do("GET", "/x", "10.1.1.1:1", nil, nil); w.Header().Get("X-Request-ID") == "" {
		t.Fatal("no id on error")
	}
}

func TestRequestIDHandling(t *testing.T) {
	e := setup(t, nil)
	good := ulid.Make().String()
	w := e.do("GET", "/bot"+tok+"/getMe", "10.1.1.1:1", nil, map[string]string{"X-Request-ID": good})
	if w.Header().Get("X-Request-ID") != good || e.up.req.Header.Get("X-Request-ID") != good {
		t.Fatal("valid id not kept")
	}
	w = e.do("GET", "/bot"+tok+"/getMe", "10.1.1.1:1", nil, map[string]string{"X-Request-ID": "evil\tvalue"})
	if got := w.Header().Get("X-Request-ID"); got == "evil\tvalue" {
		t.Fatal("invalid id accepted")
	}
}

func TestRequestHeadersCleaned(t *testing.T) {
	e := setup(t, nil)
	e.do("POST", "/bot"+tok+"/sendMessage", "10.1.1.1:1", strings.NewReader("{}"), map[string]string{
		"Content-Type":    "application/json",
		"X-TGP-Attempt":   "9",
		"X-Tgp-Bot-Id":    "1",
		"X-TGP-Whatever":  "z",
		"Authorization":   "Bearer x",
		"Cookie":          "a=b",
		"Forwarded":       "for=1.1.1.1",
		"X-Forwarded-For": "1.1.1.1",
		"X-Real-IP":       "1.1.1.1",
		"Via":             "1.1 x",
		"Connection":      "X-Hop",
		"X-Hop":           "1",
		"User-Agent":      "bot/1",
	})
	h := e.up.req.Header
	for _, k := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "X-Real-Ip", "Via", "Connection", "X-Hop", "X-Tgp-Whatever"} {
		if h.Get(k) != "" {
			t.Fatalf("%s leaked: %v", k, h)
		}
	}
	if h.Get("X-TGP-Attempt") != "1" || h.Get("X-TGP-Bot-ID") != "123456" {
		t.Fatalf("service headers: %v", h)
	}
	if h.Get("Content-Type") != "application/json" || h.Get("User-Agent") != "bot/1" {
		t.Fatalf("lost headers: %v", h)
	}
	if h.Get("X-TGP-Timeout-Ms") == "" || h.Get("X-Request-ID") == "" {
		t.Fatalf("no service headers: %v", h)
	}
	if e.up.body != "{}" {
		t.Fatal(e.up.body)
	}
}

func TestLongPollDeadline(t *testing.T) {
	e := setup(t, nil)
	e.do("GET", "/bot"+tok+"/getUpdates?timeout=50", "10.1.1.1:1", nil, nil)
	if e.up.dl > 65*time.Second || e.up.dl < 63*time.Second {
		t.Fatal(e.up.dl)
	}
	e.do("GET", "/bot"+tok+"/getUpdates?timeout=5", "10.1.1.1:1", nil, nil)
	if e.up.dl > 20*time.Second || e.up.dl < 18*time.Second {
		t.Fatal(e.up.dl)
	}
}

func TestUpstreamDown(t *testing.T) {
	e := setup(t, nil)
	e.up.fn = func(context.Context, *http.Request) (*http.Response, error) {
		return nil, errors.New("dial https://x/bot" + tok + "/getMe: refused")
	}
	w := e.do("GET", "/bot"+tok+"/getMe", "10.1.1.1:1", nil, nil)
	errDesc(t, w, 502, router.DescNoAgents)
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("not json")
	}
}

func TestNoAgentsAndTimeout(t *testing.T) {
	e := setup(t, func(c *config.ServerConfig) { c.Agents = nil })
	errDesc(t, e.do("GET", "/bot"+tok+"/getMe", "10.1.1.1:1", nil, nil), 502, router.DescNoAgents)

	e = setup(t, func(c *config.ServerConfig) { c.Router.Budget = 20 * time.Millisecond })
	e.up.fn = func(ctx context.Context, _ *http.Request) (*http.Response, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	errDesc(t, e.do("GET", "/bot"+tok+"/getMe", "10.1.1.1:1", nil, nil), 504, router.DescTimeout)
}

type stubRouter struct {
	resp *http.Response
	err  error
}

func (s stubRouter) Do(context.Context, *http.Request, tgapi.Route) (*http.Response, error) {
	return s.resp, s.err
}

func stubHandler(_ *testing.T, r Router) (http.Handler, *bytes.Buffer) {
	cfg := config.DefaultServer()
	chk, _ := access.NewStatic([]config.AccessRule{{Name: "lan", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}, nil)
	buf := &bytes.Buffer{}
	return New(chk, r, cfg, slog.New(slog.NewJSONHandler(buf, nil))), buf
}

func TestGenericRouterErrorAndCancel(t *testing.T) {
	h, buf := stubHandler(t, stubRouter{err: errors.New("boom " + tok)})
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/bot"+tok+"/getMe", nil)
	r.RemoteAddr = "10.1.1.1:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	errDesc(t, w, 502, "tgproxy: no healthy agents")
	if tokRe.MatchString(buf.String()) {
		t.Fatal("token in log:", buf)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = httptest.NewRequestWithContext(context.Background(), "GET", "/bot"+tok+"/getMe", nil).WithContext(ctx)
	r.RemoteAddr = "10.1.1.1:1"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 499 {
		t.Fatal(w.Code)
	}
}

func TestHeadAndStreaming(t *testing.T) {
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("data"))}
	h, _ := stubHandler(t, stubRouter{resp: resp})
	r := httptest.NewRequestWithContext(context.Background(), "HEAD", "/file/bot"+tok+"/a.jpg", nil)
	r.RemoteAddr = "10.1.1.1:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body)
	}

	resp = &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("data"))}
	h, _ = stubHandler(t, stubRouter{resp: resp})
	r = httptest.NewRequestWithContext(context.Background(), "GET", "/file/bot"+tok+"/a.jpg", nil)
	r.RemoteAddr = "10.1.1.1:1"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Body.String() != "data" || !w.Flushed {
		t.Fatal(w.Body, w.Flushed)
	}
}

func TestTokenNeverInLogs(t *testing.T) {
	e := setup(t, nil)
	e.do("GET", "/bot"+tok+"/getMe", "10.1.1.1:1", nil, nil)
	e.do("GET", "/bot"+tok+"/getMe", "8.8.8.8:1", nil, nil)
	e.do("GET", "/k/k1/bot"+tok+"/getMe", "8.8.8.8:1", nil, nil)
	e.do("POST", "/bot"+tok+"/setWebhook", "10.1.1.1:1", nil, nil)
	e.up.fn = func(context.Context, *http.Request) (*http.Response, error) {
		return nil, errors.New("Get \"https://agent/tg/bot" + tok + "/getMe\": refused")
	}
	e.do("GET", "/bot"+tok+"/getMe", "10.1.1.1:1", nil, nil)
	out := e.log.String()
	if out == "" || tokRe.MatchString(out) || strings.Contains(out, "ABCDEFGHIJ") {
		t.Fatalf("token leaked or no logs:\n%s", out)
	}
	if !strings.Contains(out, `"bot_id":123456`) || !strings.Contains(out, `"rule":"lan"`) {
		t.Fatalf("access log fields missing:\n%s", out)
	}
}
