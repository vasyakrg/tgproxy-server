package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

var bothALPN = []string{ALPNReverse, ALPNMTProto}

func mtRevOpts(dc netip.AddrPort, mut func(*config.AgentConfig)) revOpts {
	return revOpts{alpns: bothALPN, cfg: func(c *config.AgentConfig) {
		c.OverrideMTProtoDCs(map[int][]netip.AddrPort{2: {dc}})
		if mut != nil {
			mut(c)
		}
	}}
}

// collect принимает n соединений gateway и раскладывает их по ALPN.
func collect(t *testing.T, g *gateway, n int) (bot, mt []*gwConn) {
	t.Helper()
	for range n {
		c := g.next(t)
		if c.alpn == ALPNMTProto {
			mt = append(mt, c)
		} else {
			bot = append(bot, c)
		}
	}
	return bot, mt
}

type gwStream struct {
	pw   *io.PipeWriter
	resp *http.Response
}

func (c *gwConn) open(t *testing.T, path string) (*gwStream, int) {
	t.Helper()
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://agent"+path, pr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		cancel()
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { cancel(); _ = pw.Close(); _ = resp.Body.Close() })
	return &gwStream{pw: pw, resp: resp}, resp.StatusCode
}

func (s *gwStream) echo(t *testing.T, msg string) {
	t.Helper()
	if _, err := s.pw.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(s.resp.Body, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo = %q, %v; want %q", buf, err, msg)
	}
}

func (c *gwConn) put(t *testing.T, body string) int {
	t.Helper()
	r, _ := c.do(t, http.MethodPut, "/_agent/mtproto/pool", body)
	return r.StatusCode
}

func mtConns(r *revEnv) (int, int) { return r.agent.MTProtoReverseConns() }

func TestMTProtoClassHoldsMinConns(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeReverse, true, mtRevOpts(dc.addr, nil))
	bot, mt := collect(t, r.gw, 4)
	if len(bot) != 2 || len(mt) != 2 {
		t.Fatalf("bot=%d mtproto=%d, want 2/2", len(bot), len(mt))
	}
	waitFor(t, "mtproto conns", func() bool { c, tg := mtConns(r); return c == 2 && tg == 2 })
	s, code := mt[0].open(t, "/_agent/mtproto/dc/2")
	if code != http.StatusOK {
		t.Fatalf("dc stream: %d", code)
	}
	s.echo(t, "ping")
}

func TestMTProtoClassRestrictedRoutes(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeReverse, true, mtRevOpts(dc.addr, nil))
	_, mt := collect(t, r.gw, 4)
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/_agent/status"},
		{http.MethodGet, "/_agent/healthz"},
		{http.MethodPost, "/_agent/drain"},
		{http.MethodPut, "/_agent/config"},
		{http.MethodPost, "/tg/bot1/getMe"},
		{http.MethodGet, "/_agent/mtproto/pool"},
	} {
		resp, _ := mt[0].do(t, p.method, p.path, "")
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 404/405", p.method, p.path, resp.StatusCode)
		}
	}
	// PUT pool на Bot API-классе недоступен.
	bot, _ := collect2(r)
	if resp, _ := bot[0].do(t, http.MethodPut, "/_agent/mtproto/pool", `{"conns":5}`); resp.StatusCode == http.StatusNoContent {
		t.Fatal("pool endpoint must not be served on the bot class")
	}
}

// collect2 — снимок соединений gateway по классам.
func collect2(r *revEnv) ([]*gwConn, []*gwConn) {
	r.gw.mu.Lock()
	defer r.gw.mu.Unlock()
	var bot, mt []*gwConn
	for _, c := range r.gw.all {
		if c.alpn == ALPNMTProto {
			mt = append(mt, c)
		} else {
			bot = append(bot, c)
		}
	}
	return bot, mt
}

func TestMTProtoPoolGrowClampShrink(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeReverse, true, mtRevOpts(dc.addr, nil))
	_, mt := collect(t, r.gw, 4)

	if code := mt[0].put(t, `{"conns":5}`); code != http.StatusNoContent {
		t.Fatalf("PUT = %d", code)
	}
	waitFor(t, "grow to 5", func() bool { c, tg := mtConns(r); return c == 5 && tg == 5 })

	mt[0].put(t, `{"conns":100}`)
	waitFor(t, "clamp max 16", func() bool { c, tg := mtConns(r); return c == 16 && tg == 16 })

	mt[0].put(t, `{"conns":0}`)
	waitFor(t, "clamp min 2", func() bool { c, tg := mtConns(r); return c == 2 && tg == 2 })
}

func TestMTProtoPoolBadBody(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeReverse, true, mtRevOpts(dc.addr, nil))
	_, mt := collect(t, r.gw, 4)
	for _, b := range []string{``, `{}`, `{"conns":"x"}`, `{"conns":3,"x":1}`, `[`} {
		if code := mt[0].put(t, b); code != http.StatusBadRequest {
			t.Errorf("body %q: %d, want 400", b, code)
		}
	}
	if _, tg := mtConns(r); tg != 2 {
		t.Fatalf("target changed by bad body: %d", tg)
	}
}

// Сжатие отпускает соединения без стримов; соединение со стримом живёт.
func TestMTProtoShrinkKeepsBusyConn(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeReverse, true, mtRevOpts(dc.addr, func(c *config.AgentConfig) {
		c.MTProto.ReverseConnsMin = 1
	}))
	_, mt := collect(t, r.gw, 3) // 2 bot + 1 mtproto
	mt[0].put(t, `{"conns":4}`)
	waitFor(t, "grow", func() bool { c, _ := mtConns(r); return c == 4 })
	_, all := collect2(r)
	var busy *gwConn
	for _, c := range all {
		if c != mt[0] {
			busy = c
			break
		}
	}
	s, _ := busy.open(t, "/_agent/mtproto/dc/2")
	s.echo(t, "a")
	mt[0].put(t, `{"conns":1}`)
	waitFor(t, "shrink to 1", func() bool { c, _ := mtConns(r); return c == 1 })
	s.echo(t, "still alive")
	if c, _ := mtConns(r); c != 1 {
		t.Fatalf("conns = %d", c)
	}
}

// Сжатие занятого соединения ждёт завершения стрима и не рвёт его.
func TestMTProtoShrinkWaitsForStreams(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeReverse, true, mtRevOpts(dc.addr, func(c *config.AgentConfig) {
		c.MTProto.ReverseConnsMin = 1
		c.MTProto.ReverseConnsMax = 2
	}))
	_, mt := collect(t, r.gw, 3)
	waitFor(t, "min=1 pool", func() bool { c, _ := mtConns(r); return c == 1 })
	mt[0].put(t, `{"conns":2}`)
	waitFor(t, "grow", func() bool { c, _ := mtConns(r); return c == 2 })
	_, all := collect2(r)
	if len(all) != 2 {
		t.Fatalf("mt conns at gw = %d", len(all))
	}
	s1, _ := all[0].open(t, "/_agent/mtproto/dc/2")
	s2, _ := all[1].open(t, "/_agent/mtproto/dc/2")
	s1.echo(t, "1")
	s2.echo(t, "2")
	all[0].put(t, `{"conns":1}`)
	time.Sleep(200 * time.Millisecond) // GOAWAY разошёлся
	s1.echo(t, "after-goaway-1")
	s2.echo(t, "after-goaway-2")
	if c, _ := mtConns(r); c != 2 {
		t.Fatalf("busy conns closed prematurely: %d", c)
	}
	_ = s1.pw.Close()
	_ = s2.pw.Close()
	waitFor(t, "retired conn closes", func() bool { c, _ := mtConns(r); return c == 1 })
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Старый сервер (ALPN без tgproxy-mtproto/1): Bot API-класс работает, MTProto
// молча ждёт, без Warn/Error и без штурма сервера.
func TestMTProtoOldServerNoALPN(t *testing.T) {
	var logs lockedBuf
	r := newRevEnvWith(t, config.AgentModeReverse, true, revOpts{
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		agent:  []Option{WithConnectorOptions(WithUnsupportedRetry(time.Hour))},
	})
	c := r.gw.next(t)
	r.gw.next(t)
	waitFor(t, "mtproto attempts", func() bool { return r.gw.attempts.Load() >= 4 })
	time.Sleep(300 * time.Millisecond)
	if got := r.gw.attempts.Load(); got != 4 {
		t.Fatalf("attempts = %d, want 4 (2 bot + 2 mtproto, без повторов)", got)
	}
	if resp, _ := c.do(t, http.MethodGet, "/_agent/healthz", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("bot class: %d", resp.StatusCode)
	}
	if conns, _ := mtConns(r); conns != 0 {
		t.Fatalf("mtproto conns = %d", conns)
	}
	if _, _, n, _ := r.agent.mgr.snapshot(); n != 2 {
		t.Fatalf("bot conns = %d", n)
	}
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "class=mtproto") && (strings.Contains(line, "level=WARN") || strings.Contains(line, "level=ERROR") || strings.Contains(line, "level=INFO")) {
			t.Errorf("noisy log: %s", line)
		}
	}
}

func TestMTProtoOldServerRetriesAfterInterval(t *testing.T) {
	r := newRevEnvWith(t, config.AgentModeReverse, true, revOpts{
		agent: []Option{WithConnectorOptions(WithUnsupportedRetry(100 * time.Millisecond))},
	})
	r.gw.next(t)
	r.gw.next(t)
	waitFor(t, "periodic retries", func() bool { return r.gw.attempts.Load() >= 8 })
}

func TestMTProtoClassNotStarted(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	t.Run("mtproto disabled", func(t *testing.T) {
		o := mtRevOpts(dc.addr, func(c *config.AgentConfig) { c.MTProto.Enabled = false })
		r := newRevEnvWith(t, config.AgentModeReverse, true, o)
		r.gw.next(t)
		r.gw.next(t)
		time.Sleep(200 * time.Millisecond)
		if got := r.gw.attempts.Load(); got != 2 {
			t.Fatalf("attempts = %d, want 2", got)
		}
		if c, tg := mtConns(r); c != 0 || tg != 0 {
			t.Fatalf("mtproto pool %d/%d", c, tg)
		}
	})
	t.Run("dial mode", func(t *testing.T) {
		r := newRevEnvWith(t, config.AgentModeDial, false, mtRevOpts(dc.addr, nil))
		if c, tg := mtConns(r); c != 0 || tg != 0 {
			t.Fatalf("mtproto pool %d/%d", c, tg)
		}
		if r.gw.attempts.Load() != 0 {
			t.Fatal("dial mode must not connect")
		}
	})
}

func TestMTProtoBothModeStartsClass(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeBoth, true, mtRevOpts(dc.addr, nil))
	_, mt := collect(t, r.gw, 4)
	if len(mt) != 2 {
		t.Fatalf("mt = %d", len(mt))
	}
}

// drain не закрывает живые стримы и соединения; новые стримы получают 503.
func TestMTProtoDrainKeepsLiveStreams(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeReverse, true, mtRevOpts(dc.addr, nil))
	bot, mt := collect(t, r.gw, 4)
	s, _ := mt[0].open(t, "/_agent/mtproto/dc/2")
	s.echo(t, "before")
	if resp, _ := bot[0].do(t, http.MethodPost, "/_agent/drain", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("drain: %d", resp.StatusCode)
	}
	s.echo(t, "during drain")
	if _, code := mt[1].open(t, "/_agent/mtproto/dc/2"); code != http.StatusServiceUnavailable {
		t.Fatalf("new stream during drain = %d, want 503", code)
	}
	if c, _ := mtConns(r); c != 2 {
		t.Fatalf("drain closed mtproto conns: %d", c)
	}
}

func TestMTProtoReconnectAfterDrop(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	r := newRevEnvWith(t, config.AgentModeReverse, true, mtRevOpts(dc.addr, nil))
	_, mt := collect(t, r.gw, 4)
	_ = mt[0].conn.Close()
	c := r.gw.next(t)
	if c.alpn != ALPNMTProto {
		t.Fatalf("reconnect alpn = %q", c.alpn)
	}
}
