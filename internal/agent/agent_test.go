//nolint:bodyclose // тела ответов закрываются в t.Cleanup внутри env.do
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true,"result":{"id":1}}`)
})

func TestProxyPassThrough(t *testing.T) {
	var gotPath, gotRaw, gotBody, gotHost string
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotRaw, gotHost = r.URL.Path, r.URL.RawQuery, r.Host
		gotBody = string(readAll(t, r.Body))
		okHandler.ServeHTTP(w, r)
	}))
	resp := e.do(t, http.MethodPost, "/tg/bot123:AAAA/sendMessage?x=1&y=2", nil, strings.NewReader("hello"))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if gotPath != "/bot123:AAAA/sendMessage" || gotRaw != "x=1&y=2" || gotBody != "hello" {
		t.Fatalf("upstream saw %q ?%q %q", gotPath, gotRaw, gotBody)
	}
	if gotHost != strings.TrimPrefix(e.upstream.URL, "https://") {
		t.Fatalf("host %q", gotHost)
	}
	if got := resp.Header.Get(tgapi.HeaderSource); got != tgapi.SourceTelegram {
		t.Fatalf("source %q", got)
	}
	if resp.Header.Get(tgapi.HeaderUpstreamMs) == "" {
		t.Fatal("no upstream ms")
	}
	if !strings.Contains(string(readAll(t, resp.Body)), `"ok":true`) {
		t.Fatal("body lost")
	}
}

func TestProxyTelegramErrorsPassThrough(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":429,"parameters":{"retry_after":7}}`)
	}))
	resp := e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil) //nolint:bodyclose // closed in t.Cleanup
	if resp.StatusCode != 429 || resp.Header.Get(tgapi.HeaderSource) != tgapi.SourceTelegram ||
		resp.Header.Get(tgapi.HeaderErrorPhase) != "" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
}

func TestHeadersCleaned(t *testing.T) {
	var seen http.Header
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		h := w.Header()
		h.Set("Set-Cookie", "a=b")
		h.Set("Alt-Svc", `h3=":443"`)
		h.Set("Server", "nginx")
		h.Set("X-Tgp-Source", "spoof")
		h.Set("X-TGP-Error-Phase", "dial")
		h.Set("X-Custom", "keep")
		okHandler.ServeHTTP(w, r)
	}))
	// http/1.1, чтобы проверить hop-by-hop заголовки.
	tr := e.client.Transport.(*http.Transport)
	tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	tr.ForceAttemptHTTP2 = false

	resp := e.do(t, http.MethodGet, "/tg/bot1:a/getMe", map[string]string{
		"X-Forwarded-For":   "1.2.3.4",
		"X-Forwarded-Host":  "h",
		"X-Forwarded-Proto": "https",
		"Forwarded":         "for=1.2.3.4",
		"Via":               "1.1 x",
		"Cookie":            "s=1",
		"Authorization":     "Bearer x",
		"X-Request-ID":      "01ABC",
		"X-TGP-Attempt":     "1",
		"X-TGP-Bot-ID":      "1",
		"X-TGP-Timeout-Ms":  "5000",
		"X-Proxy-Key":       "tgp_secret",
		"Connection":        "X-Hop",
		"X-Hop":             "1",
		"Keep-Alive":        "timeout=5",
		"X-Keep":            "yes",
		"User-Agent":        "bot/1",
	}, nil)
	for _, h := range []string{
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "Via",
		"Cookie", "Authorization", "X-Request-Id", "X-Tgp-Attempt", "X-Tgp-Bot-Id",
		"X-Tgp-Timeout-Ms", "X-Proxy-Key", "X-Hop", "Keep-Alive",
	} {
		if v := seen.Get(h); v != "" {
			t.Errorf("upstream got %s=%q", h, v)
		}
	}
	if seen.Get("X-Keep") != "yes" || seen.Get("User-Agent") != "bot/1" {
		t.Errorf("lost regular headers: %v", seen)
	}
	for _, h := range []string{"Set-Cookie", "Alt-Svc", "Server", tgapi.HeaderErrorPhase} {
		if v := resp.Header.Get(h); v != "" {
			t.Errorf("response has %s=%q", h, v)
		}
	}
	if resp.Header.Get(tgapi.HeaderSource) != tgapi.SourceTelegram || resp.Header.Get("X-Custom") != "keep" {
		t.Errorf("response headers: %v", resp.Header)
	}
}

func TestRewriteNoUserAgentAndRawPath(t *testing.T) {
	e := newEnv(t, okHandler)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tg/bot1:a/getFile%2Fx", nil)
	req.Header.Del("User-Agent")
	out := req.Clone(context.Background())
	e.agent.proxy.rewrite(&proxyRequest(req, out).pr)
	if out.URL.RawPath != "/bot1:a/getFile%2Fx" {
		t.Fatalf("raw path %q", out.URL.RawPath)
	}
	if ua, ok := out.Header["User-Agent"]; !ok || ua[0] != "" {
		t.Fatalf("UA %v", out.Header)
	}
}

func TestPhaseDial(t *testing.T) {
	e := newEnv(t, okHandler)
	e.upstream.Close()
	resp := e.do(t, http.MethodGet, "/tg/bot1:SECRETTOKEN/getMe", nil, nil)
	assertAgentError(t, resp, 502, tgapi.PhaseDial)
	body := string(readAll(t, resp.Body))
	if strings.Contains(body, "SECRETTOKEN") {
		t.Fatalf("token leaked: %s", body)
	}
	var env tgapi.Envelope
	if err := json.Unmarshal([]byte(body), &env); err != nil || env.OK || env.ErrorCode != 502 {
		t.Fatalf("bad envelope %s %v", body, err)
	}
}

func TestPhaseTLS(t *testing.T) {
	e := newEnv(t, okHandler)
	// агент без доверия к сертификату фейкового Telegram (системные корни).
	e.startAgent(t)
	resp := e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil)
	assertAgentError(t, resp, 502, tgapi.PhaseTLS)
}

func TestPhaseRead(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(100 * time.Millisecond)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	resp := e.do(t, http.MethodPost, "/tg/bot1:a/sendMessage", nil, strings.NewReader(`{"chat_id":1}`))
	assertAgentError(t, resp, 502, tgapi.PhaseRead)
}

func TestPhaseTimeout(t *testing.T) {
	release := make(chan struct{})
	// Апстрим молчит до конца теста: выход по r.Context() отдавал бы пустой 200,
	// который при гонке с дедлайном агент законно принимал как ответ.
	e := newEnv(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release) })
	start := time.Now()
	resp := e.do(t, http.MethodGet, "/tg/bot1:a/getUpdates", map[string]string{tgapi.HeaderTimeoutMs: "200"}, nil)
	assertAgentError(t, resp, 504, tgapi.PhaseTimeout)
	if time.Since(start) > 5*time.Second {
		t.Fatal("deadline ignored")
	}
}

func assertAgentError(t *testing.T, resp *http.Response, code int, phase string) {
	t.Helper()
	if resp.StatusCode != code {
		t.Fatalf("status %d, want %d", resp.StatusCode, code)
	}
	if got := resp.Header.Get(tgapi.HeaderErrorPhase); got != phase {
		t.Fatalf("phase %q, want %q", got, phase)
	}
	if got := resp.Header.Get(tgapi.HeaderSource); got != tgapi.SourceAgent {
		t.Fatalf("source %q", got)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name  string
		setup func(tr *phaseTracker)
		err   error
		ctx   error
		want  string
	}{
		{"start", func(*phaseTracker) {}, io.EOF, nil, tgapi.PhaseDial},
		{"dial err", func(tr *phaseTracker) { tr.dialErr.Store(true) }, io.EOF, nil, tgapi.PhaseDial},
		{"tls err", func(tr *phaseTracker) { tr.tlsErr.Store(true) }, io.EOF, nil, tgapi.PhaseTLS},
		{"connected", func(tr *phaseTracker) { tr.advance(stageConnected) }, io.EOF, nil, tgapi.PhasePreSend},
		{"wrote headers", func(tr *phaseTracker) { tr.advance(stageWroteHeaders) }, io.EOF, nil, tgapi.PhaseWrite},
		{"write error", func(tr *phaseTracker) {
			tr.writeErr.Store(true)
			tr.advance(stageWroteRequest)
		}, io.EOF, nil, tgapi.PhaseWrite},
		{"wrote request", func(tr *phaseTracker) { tr.advance(stageWroteRequest) }, io.EOF, nil, tgapi.PhaseRead},
		{"first byte", func(tr *phaseTracker) { tr.advance(stageGotResponse) }, io.EOF, nil, tgapi.PhaseRead},
		{"deadline err", func(*phaseTracker) {}, context.DeadlineExceeded, nil, tgapi.PhaseTimeout},
		{"deadline ctx", func(tr *phaseTracker) { tr.advance(stageWroteRequest) }, io.EOF, context.DeadlineExceeded, tgapi.PhaseTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newPhaseTracker(time.Now())
			tt.setup(tr)
			if got := tr.classify(tt.err, tt.ctx); got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
		})
	}
}

func TestClientTraceHooks(t *testing.T) {
	tr := newPhaseTracker(time.Now())
	ct := tr.clientTrace()
	ct.DNSDone(httptrace.DNSDoneInfo{Err: io.EOF})
	if !tr.dialErr.Load() {
		t.Fatal("dns err")
	}
	tr.dialErr.Store(false)
	ct.ConnectDone("tcp", "x", io.EOF)
	if !tr.dialErr.Load() {
		t.Fatal("connect err")
	}
	ct.TLSHandshakeDone(tls.ConnectionState{}, io.EOF)
	if !tr.tlsErr.Load() {
		t.Fatal("tls err")
	}
	ct.GotConn(httptrace.GotConnInfo{})
	ct.WroteHeaders()
	ct.WroteRequest(httptrace.WroteRequestInfo{Err: io.EOF})
	ct.GotFirstResponseByte()
	if stage(tr.stage.Load()) != stageGotResponse || !tr.writeErr.Load() || tr.upstream() <= 0 {
		t.Fatal("stage tracking")
	}
	if newPhaseTracker(time.Now()).upstream() < 0 {
		t.Fatal("upstream before first byte")
	}
}

func TestMTLS(t *testing.T) {
	e := newEnv(t, okHandler)
	t.Run("no client cert", func(t *testing.T) {
		c := e.newClient(t, e.srvCert, false)
		resp, err := c.Get("https://" + e.addr + "/_agent/status") //nolint:noctx
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("request without client cert succeeded")
		}
	})
	t.Run("agent cert instead of server cert", func(t *testing.T) {
		c := e.newClient(t, e.agCert, true)
		resp, err := c.Get("https://" + e.addr + "/_agent/status") //nolint:noctx
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("agent cert accepted as server")
		}
	})
	t.Run("foreign CA", func(t *testing.T) {
		_, other, _, _ := newPKI(t)
		c := e.newClient(t, other, true)
		resp, err := c.Get("https://" + e.addr + "/_agent/status") //nolint:noctx
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("foreign CA accepted")
		}
	})
	t.Run("server cert ok", func(t *testing.T) {
		if resp := e.do(t, http.MethodGet, "/_agent/status", nil, nil); resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
	})
}

func TestDrain(t *testing.T) {
	var calls atomic.Int32
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		okHandler.ServeHTTP(w, r)
	}))
	if r := e.do(t, http.MethodPost, "/_agent/drain", nil, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	resp := e.do(t, http.MethodPost, "/tg/bot1:a/sendMessage", nil, strings.NewReader("x"))
	assertAgentError(t, resp, 503, tgapi.PhasePreSend)
	if calls.Load() != 0 {
		t.Fatal("upstream called while draining")
	}
	st := readJSON(t, e.do(t, http.MethodGet, "/_agent/status", nil, nil))
	if st["draining"] != true {
		t.Fatalf("status %v", st)
	}
	if r := e.do(t, http.MethodDelete, "/_agent/drain", nil, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	if r := e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil); r.StatusCode != 200 || calls.Load() != 1 {
		t.Fatalf("after undrain: %d calls=%d", r.StatusCode, calls.Load())
	}
	if !e.agent.Draining() {
		e.agent.SetDraining(true)
	}
}

func TestStreaming5MB(t *testing.T) {
	const total = 5 << 20
	release := make(chan struct{})
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "5242880")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 4096))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write(bytes.Repeat([]byte("b"), total-4096))
	}))
	resp := e.do(t, http.MethodGet, "/tg/file/bot1:a/photos/x.jpg", nil, nil)
	first := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, first); err != nil || first[0] != 'a' {
		t.Fatalf("first byte before upstream finished: %v", err)
	}
	close(release)
	rest := readAll(t, resp.Body)
	if len(rest)+1 != total {
		t.Fatalf("got %d bytes", len(rest)+1)
	}
}

func TestStatusAndStats(t *testing.T) {
	e := newEnv(t, okHandler)
	for range 3 {
		_ = readAll(t, e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil).Body)
	}
	closed := closedAddr(t)
	e.cfg.OverrideTelegramAPIURL("https://" + closed) //nolint:errcheck
	e.startAgent(t)
	_ = e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil)
	st := readJSON(t, e.do(t, http.MethodGet, "/_agent/status", nil, nil))
	for _, k := range []string{"version", "commit", "uptime_s", "inflight", "rps_1m", "errors_by_phase",
		"upstream_rtt_ms", "draining", "cert_not_after"} {
		if _, ok := st[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if st["errors_by_phase"].(map[string]any)[tgapi.PhaseDial].(float64) != 1 {
		t.Errorf("errors_by_phase %v", st["errors_by_phase"])
	}
	if st["rps_1m"].(float64) <= 0 {
		t.Errorf("rps %v", st["rps_1m"])
	}
	if st["cert_not_after"].(string) == "" || st["cert_not_after"].(string)[:4] == "0001" {
		t.Errorf("cert_not_after %v", st["cert_not_after"])
	}
}

func TestStatsUnit(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := newStats(func() time.Time { return now })
	s.begin(false)
	s.begin(true)
	s.end(true)
	if s.inflight.Load() != 1 || s.rps1m() != 2.0/60 {
		t.Fatalf("inflight=%d rps=%v", s.inflight.Load(), s.rps1m())
	}
	now = now.Add(61 * time.Second)
	if s.rps1m() != 0 {
		t.Fatal("old buckets must expire")
	}
	s.begin(false) // перезапись бакета
	s.recordError("nope")
	s.recordError(tgapi.PhaseRead)
	if s.errorsByPhase()[tgapi.PhaseRead] != 1 {
		t.Fatal("errors")
	}
	s.observeRTT(100 * time.Millisecond)
	s.observeRTT(200 * time.Millisecond)
	if got := s.upstreamRTT(); got < 129 || got > 131 {
		t.Fatalf("ewma %v", got)
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, okHandler)
	if r := e.do(t, http.MethodGet, "/_agent/healthz", nil, nil); r.StatusCode != 200 {
		t.Fatalf("healthz %d", r.StatusCode)
	}
	e.upstream.Close()
	e.agent.health = newHealthProbe(e.agent.probeUpstream, time.Now)
	r := e.do(t, http.MethodGet, "/_agent/healthz", nil, nil)
	if r.StatusCode != 503 {
		t.Fatalf("healthz with dead upstream: %d", r.StatusCode)
	}
}

func TestHealthCache(t *testing.T) {
	now := time.Unix(0, 0)
	var n int
	h := newHealthProbe(func(context.Context) error {
		n++
		if n == 1 {
			return io.EOF
		}
		return nil
	}, func() time.Time { return now })
	if err := h.check(context.Background()); err == nil {
		t.Fatal("want err")
	}
	now = now.Add(9 * time.Second)
	if err := h.check(context.Background()); err == nil || n != 1 {
		t.Fatalf("cached: err=%v n=%d", err, n)
	}
	now = now.Add(2 * time.Second)
	if err := h.check(context.Background()); err != nil || n != 2 {
		t.Fatalf("refresh: err=%v n=%d", err, n)
	}
}

func TestProbeDefaultPort(t *testing.T) {
	a := &Agent{upstream: mustURL(t, "https://127.0.0.1"), upTLS: &tls.Config{MinVersion: tls.VersionTLS12}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.probeUpstream(ctx); err == nil {
		t.Fatal("expected failure on :443")
	}
}

func TestRequestTimeout(t *testing.T) {
	tests := map[string]time.Duration{
		"":        30 * time.Second,
		"abc":     30 * time.Second,
		"-5":      30 * time.Second,
		"0":       30 * time.Second,
		"1500":    1500 * time.Millisecond,
		"65000":   65 * time.Second,
		"9999999": 65 * time.Second,
	}
	for in, want := range tests {
		h := http.Header{}
		if in != "" {
			h.Set(tgapi.HeaderTimeoutMs, in)
		}
		if got := requestTimeout(h); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

func TestRoutesMisc(t *testing.T) {
	e := newEnv(t, okHandler)
	if r := e.do(t, http.MethodGet, "/nope", nil, nil); r.StatusCode != 404 {
		t.Fatal(r.StatusCode)
	}
	if r := e.do(t, http.MethodGet, "/tg/", nil, nil); r.StatusCode != 404 {
		t.Fatal(r.StatusCode)
	}
}

func TestNewErrors(t *testing.T) {
	_, _, _, dir := newPKI(t)
	good := func() *config.AgentConfig {
		c := config.DefaultAgent()
		c.TLS = config.TLSFiles{
			CertFile: filepath.Join(dir, "agent.crt"),
			KeyFile:  filepath.Join(dir, "agent.key"),
			CAFile:   filepath.Join(dir, "ca.crt"),
		}
		return c
	}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(nil, lg); err == nil {
		t.Error("nil cfg")
	}
	if a, err := New(good(), nil); err != nil || a == nil {
		t.Errorf("nil logger: %v", err)
	}
	c := good()
	c.TLS.CertFile = filepath.Join(dir, "missing")
	if _, err := New(c, lg); err == nil {
		t.Error("missing cert")
	}
	c = good()
	c.TLS.CAFile = filepath.Join(dir, "missing")
	if _, err := New(c, lg); err == nil {
		t.Error("missing ca")
	}
	c = good()
	bad := filepath.Join(dir, "bad.crt")
	_ = os.WriteFile(bad, []byte("junk"), 0o600)
	c.TLS.CAFile = bad
	if _, err := New(c, lg); err == nil {
		t.Error("bad ca")
	}
}

func TestRunGracefulShutdown(t *testing.T) {
	_, _, _, dir := newPKI(t)
	cfg := config.DefaultAgent()
	cfg.TLS = config.TLSFiles{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	cfg.Listen.API = "127.0.0.1:0"
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	// занятый порт → ошибка listen
	ln, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg.Listen.API = ln.Addr().String()
	a, _ = New(cfg, nil)
	if err := a.Run(context.Background()); err == nil {
		t.Fatal("expected listen error")
	}
}

func TestNoTokenInLogs(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buf}, nil))
	e := newEnv(t, okHandler)
	e.upstream.Close()
	a, err := New(e.cfg, lg)
	if err != nil {
		t.Fatal(err)
	}
	e.agent = a
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tg/bot123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678/getMe", nil)
	a.Handler().ServeHTTP(rec, req)
	mu.Lock()
	defer mu.Unlock()
	if rec.Code != 502 || !strings.Contains(buf.String(), "upstream request failed") {
		t.Fatalf("code=%d logs=%q", rec.Code, buf.String())
	}
	if strings.Contains(buf.String(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678") ||
		strings.Contains(rec.Body.String(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678") {
		t.Fatalf("token leaked: %s / %s", buf.String(), rec.Body.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
