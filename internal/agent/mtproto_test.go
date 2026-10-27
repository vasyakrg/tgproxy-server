package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// fakeDC — локальный TCP-сервер, играющий дата-центр Telegram.
type fakeDC struct {
	ln   net.Listener
	addr netip.AddrPort
	wg   sync.WaitGroup
}

func newFakeDC(t *testing.T, handle func(net.Conn)) *fakeDC {
	t.Helper()
	ln, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDC{ln: ln, addr: netip.MustParseAddrPort(ln.Addr().String())}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.wg.Add(1)
			go func() {
				defer d.wg.Done()
				defer func() { _ = c.Close() }()
				handle(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); d.wg.Wait() })
	return d
}

func echoDC(c net.Conn) { _, _ = io.Copy(c, c) }

// holdDC держит соединение, ничего не отправляя, пока клиент не закроется.
func holdDC(c net.Conn) { _, _ = io.Copy(io.Discard, c) }

type mtOpt func(*config.AgentConfig)

// newMTEnv поднимает агента, у которого DC 2 указывает на dcAddr.
func newMTEnv(t *testing.T, dcAddr netip.AddrPort, opts ...mtOpt) *env {
	t.Helper()
	e, upPool := newEnvNoAgent(t, http.NotFoundHandler())
	e.cfg.OverrideMTProtoDCs(map[int][]netip.AddrPort{2: {dcAddr}})
	for _, o := range opts {
		o(e.cfg)
	}
	e.startAgent(t, WithUpstreamRootCAs(upPool))
	return e
}

type stream struct {
	resp *http.Response
	pw   *io.PipeWriter
}

func (s *stream) Write(p []byte) (int, error) { return s.pw.Write(p) }
func (s *stream) CloseWrite()                 { _ = s.pw.Close() }

// openStream открывает full-duplex POST и возвращает его после получения заголовков.
func openStream(t *testing.T, e *env, path string, hdr map[string]string) (*stream, int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+e.addr+path, pr)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { cancel(); _ = pw.Close(); _ = resp.Body.Close() })
	return &stream{resp: resp, pw: pw}, resp.StatusCode
}

func waitStreams(t *testing.T, a *Agent, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for a.MTProtoStreams() != want {
		if time.Now().After(deadline) {
			t.Fatalf("streams = %d, want %d", a.MTProtoStreams(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMTProtoHeadersBeforeFirstDCByte(t *testing.T) {
	dc := newFakeDC(t, holdDC) // DC молчит
	e := newMTEnv(t, dc.addr)
	s, code := openStream(t, e, "/_agent/mtproto/dc/2", map[string]string{headerDC: "2"})
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200 до первого байта DC", code)
	}
	if e.agent.MTProtoStreams() != 1 {
		t.Fatalf("streams = %d, want 1", e.agent.MTProtoStreams())
	}
	s.CloseWrite()
	waitStreams(t, e.agent, 0)
}

func TestMTProtoEcho5MiBBothDirections(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	e := newMTEnv(t, dc.addr)
	s, code := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	payload := make([]byte, 5<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	werr := make(chan error, 1)
	go func() {
		_, err := s.Write(payload)
		s.CloseWrite() // half-close: DC получит EOF и закроет эхо
		werr <- err
	}()
	got, err := io.ReadAll(s.resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-werr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("эхо не совпало: got %d bytes, want %d", len(got), len(payload))
	}
	waitStreams(t, e.agent, 0)
}

func TestMTProtoInteractiveNoBuffering(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	e := newMTEnv(t, dc.addr)
	s, _ := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	buf := make([]byte, 4)
	for range 3 { // маленькие сообщения туда-обратно без закрытия записи
		if _, err := s.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(s.resp.Body, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("got %q err %v", buf, err)
		}
	}
}

func TestMTProtoDCClosesStream(t *testing.T) {
	dc := newFakeDC(t, func(c net.Conn) { _, _ = c.Write([]byte("hi")) })
	e := newMTEnv(t, dc.addr)
	s, _ := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	got, err := io.ReadAll(s.resp.Body)
	if err != nil || string(got) != "hi" {
		t.Fatalf("got %q err %v", got, err)
	}
	waitStreams(t, e.agent, 0)
}

func TestMTProtoClientCancelReleasesStream(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	s, _ := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	waitStreams(t, e.agent, 1)
	_ = s.resp.Body.Close() // RST_STREAM
	waitStreams(t, e.agent, 0)
}

func TestMTProtoBadRequests(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	cases := []struct {
		name string
		path string
		hdr  map[string]string
		code int
	}{
		{"header mismatch", "/_agent/mtproto/dc/2", map[string]string{headerDC: "3"}, http.StatusBadRequest},
		{"negative header", "/_agent/mtproto/dc/2", map[string]string{headerDC: "-2"}, http.StatusBadRequest},
		{"negative dc", "/_agent/mtproto/dc/-2", nil, http.StatusBadRequest},
		{"zero dc", "/_agent/mtproto/dc/0", nil, http.StatusBadRequest},
		{"non-numeric dc", "/_agent/mtproto/dc/abc", nil, http.StatusBadRequest},
		{"unknown dc", "/_agent/mtproto/dc/9", nil, http.StatusForbidden},
		{"known in table but not overridden", "/_agent/mtproto/dc/1", nil, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := e.do(t, http.MethodPost, c.path, c.hdr, nil)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != c.code {
				t.Fatalf("code = %d, want %d", resp.StatusCode, c.code)
			}
			if resp.Header.Get(tgapi.HeaderSource) != tgapi.SourceAgent {
				t.Fatalf("no %s header", tgapi.HeaderSource)
			}
		})
	}
	if e.agent.MTProtoStreams() != 0 {
		t.Fatalf("streams leaked: %d", e.agent.MTProtoStreams())
	}
}

func TestMTProtoDialRefused(t *testing.T) {
	e := newMTEnv(t, netip.MustParseAddrPort(closedAddr(t)))
	resp := e.do(t, http.MethodPost, "/_agent/mtproto/dc/2", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", resp.StatusCode)
	}
	if p := resp.Header.Get(tgapi.HeaderErrorPhase); p != tgapi.PhaseDial {
		t.Fatalf("phase = %q, want dial", p)
	}
	if e.agent.MTProtoStreams() != 0 {
		t.Fatalf("streams = %d", e.agent.MTProtoStreams())
	}
}

func TestMTProtoDialTimeout(t *testing.T) {
	e := newMTEnv(t, netip.MustParseAddrPort("127.0.0.1:1"), func(c *config.AgentConfig) {
		c.MTProto.DialTimeout = 100 * time.Millisecond
	})
	e.agent.mtp.dialFn = func(ctx context.Context, _ []netip.AddrPort) (net.Conn, error) {
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Err: ctx.Err()}
	}
	start := time.Now()
	resp := e.do(t, http.MethodPost, "/_agent/mtproto/dc/2", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", resp.StatusCode)
	}
	if p := resp.Header.Get(tgapi.HeaderErrorPhase); p != tgapi.PhaseTimeout {
		t.Fatalf("phase = %q, want timeout", p)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("dial_timeout не сработал")
	}
}

func TestMTProtoDialControlRejectsLoopbackOutsideOverride(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	// Боевой режим: таблица не переопределена -> loopback отвергается dial-control'ом.
	e.agent.mtp.dialFn = newDCDialer(false).dial
	resp := e.do(t, http.MethodPost, "/_agent/mtproto/dc/2", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", resp.StatusCode)
	}
	if e.agent.MTProtoStreams() != 0 {
		t.Fatalf("streams = %d", e.agent.MTProtoStreams())
	}
}

func TestDCDialControl(t *testing.T) {
	cases := []struct {
		addr     string
		prod     bool // ожидание в боевом режиме
		testMode bool // ожидание при переопределённой таблице
	}{
		{"149.154.167.51:443", true, true},
		{"[2001:67c:4e8:f002::a]:443", true, true},
		{"[::ffff:149.154.167.51]:443", true, true},
		{"91.105.192.100:443", true, true},
		{"8.8.8.8:443", false, true}, // публичный, но не Telegram
		{"127.0.0.1:443", false, true},
		{"[::1]:443", false, true},
		{"10.0.0.1:443", false, true},
		{"192.168.1.1:443", false, true},
		{"169.254.169.254:443", false, false},
		{"224.0.0.1:443", false, false},
		{"0.0.0.0:443", false, false},
		{"[::]:443", false, false},
	}
	prod, test := dcDialControl(false), dcDialControl(true)
	for _, c := range cases {
		if err := prod("tcp", c.addr, nil); (err == nil) != c.prod {
			t.Errorf("prod %s: err=%v, want allowed=%v", c.addr, err, c.prod)
		} else if err != nil && !errors.Is(err, errDCDenied) {
			t.Errorf("prod %s: err %v не errDCDenied", c.addr, err)
		}
		if err := test("tcp", c.addr, nil); (err == nil) != c.testMode {
			t.Errorf("test %s: err=%v, want allowed=%v", c.addr, err, c.testMode)
		}
	}
	for _, bad := range []string{"noport", "host.example:443"} {
		if err := prod("tcp", bad, nil); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestMTProtoMaxStreams(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	e := newMTEnv(t, dc.addr, func(c *config.AgentConfig) { c.MTProto.MaxStreams = 2 })
	s1, _ := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	_, _ = openStream(t, e, "/_agent/mtproto/dc/2", nil)
	waitStreams(t, e.agent, 2)
	resp := e.do(t, http.MethodPost, "/_agent/mtproto/dc/2", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", resp.StatusCode)
	}
	if p := resp.Header.Get(tgapi.HeaderErrorPhase); p != tgapi.PhasePreSend {
		t.Fatalf("phase = %q, want pre-send", p)
	}
	_ = s1.resp.Body.Close()
	waitStreams(t, e.agent, 1)
	if _, code := openStream(t, e, "/_agent/mtproto/dc/2", nil); code != http.StatusOK {
		t.Fatalf("после освобождения слота code = %d", code)
	}
}

func TestMTProtoDrain(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	e := newMTEnv(t, dc.addr)
	live, _ := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	e.agent.SetDraining(true)
	resp := e.do(t, http.MethodPost, "/_agent/mtproto/dc/2", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(tgapi.HeaderErrorPhase) != tgapi.PhasePreSend {
		t.Fatalf("drain: code=%d phase=%q", resp.StatusCode, resp.Header.Get(tgapi.HeaderErrorPhase))
	}
	// Живой стрим продолжает работать.
	buf := make([]byte, 5)
	if _, err := live.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(live.resp.Body, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("live stream: %q %v", buf, err)
	}
	e.agent.SetDraining(false)
	if _, code := openStream(t, e, "/_agent/mtproto/dc/2", nil); code != http.StatusOK {
		t.Fatalf("после отмены drain code = %d", code)
	}
}

func TestMTProtoIdleTimeout(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr, func(c *config.AgentConfig) {
		c.MTProto.IdleTimeout = 200 * time.Millisecond
	})
	s, _ := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	start := time.Now()
	if _, err := io.ReadAll(s.resp.Body); err != nil {
		t.Logf("read after idle: %v", err) // закрытие допустимо и ошибкой, и EOF
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 5*time.Second {
		t.Fatalf("idle закрыл через %s", d)
	}
	waitStreams(t, e.agent, 0)
}

func TestMTProtoIdleResetByTraffic(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	e := newMTEnv(t, dc.addr, func(c *config.AgentConfig) {
		c.MTProto.IdleTimeout = 300 * time.Millisecond
	})
	s, _ := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	buf := make([]byte, 1)
	for range 6 { // 6×100ms > idle_timeout, но трафик продлевает жизнь
		time.Sleep(100 * time.Millisecond)
		if _, err := s.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(s.resp.Body, buf); err != nil {
			t.Fatalf("стрим закрыт при активном трафике: %v", err)
		}
	}
}

func TestMTProtoMaxDuration(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	e := newMTEnv(t, dc.addr, func(c *config.AgentConfig) {
		c.MTProto.IdleTimeout = time.Hour
		c.MTProto.MaxDuration = 400 * time.Millisecond
	})
	s, _ := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	start := time.Now()
	buf := make([]byte, 1)
	for { // активный трафик не спасает от max_duration
		if _, err := s.Write([]byte("x")); err != nil {
			break
		}
		if _, err := io.ReadFull(s.resp.Body, buf); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
		if time.Since(start) > 5*time.Second {
			t.Fatal("max_duration не сработал")
		}
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("закрыт слишком рано: %s", d)
	}
	waitStreams(t, e.agent, 0)
}

func TestMTProtoDisabled(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr, func(c *config.AgentConfig) { c.MTProto.Enabled = false })
	if e.agent.MTProtoEnabled() {
		t.Fatal("MTProtoEnabled = true")
	}
	resp := e.do(t, http.MethodPost, "/_agent/mtproto/dc/2", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", resp.StatusCode)
	}
}

func TestMTProtoRequiresServerCert(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	for name, c := range map[string]*http.Client{
		"no client cert": e.newClient(t, e.srvCert, false),
		"agent cert":     e.newClient(t, e.agCert, true), // валидный, но SAN не tgproxy-server
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
				"https://"+e.addr+"/_agent/mtproto/dc/2", http.NoBody)
			resp, err := c.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("ожидался отказ рукопожатия, code=%d", resp.StatusCode)
			}
		})
	}
	if e.agent.MTProtoStreams() != 0 {
		t.Fatalf("streams = %d", e.agent.MTProtoStreams())
	}
}

func TestMTProtoWrongMethod(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	resp := e.do(t, http.MethodGet, "/_agent/mtproto/dc/2", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound { // catch-all "/" агента
		t.Fatalf("code = %d, want 404", resp.StatusCode)
	}
}

func TestMTProtoAddrs(t *testing.T) {
	e := newEnv(t, http.NotFoundHandler())
	r := e.agent.mtp
	v4 := r.addrs(2)
	if len(v4) == 0 || !v4[0].Addr().Is4() {
		t.Fatalf("v4 = %v", v4)
	}
	r.cfg.IPv6 = true
	both := r.addrs(2)
	if len(both) != len(v4)+1 || !both[0].Addr().Is6() || !both[len(both)-1].Addr().Is4() {
		t.Fatalf("ipv6 first expected: %v", both)
	}
	if len(r.addrs(99)) != 0 {
		t.Fatal("unknown dc must have no addrs")
	}
}

func TestDCDialerNoAddrs(t *testing.T) {
	if _, err := newDCDialer(true).dial(context.Background(), nil); err == nil {
		t.Fatal("want error")
	}
}
