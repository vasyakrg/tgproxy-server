package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

// gateway — фейковый agent_gateway: TLS-сервер, после handshake делающий
// http2.Transport.NewClientConn поверх входящего соединения агента.
type gateway struct {
	ln         net.Listener
	attempts   atomic.Int32 // принятые TCP-соединения
	handshakes atomic.Int32 // успешные TLS handshake
	cc         chan *gwConn
	mu         sync.Mutex
	all        []*gwConn
}

type gwConn struct {
	conn net.Conn
	cc   *http2.ClientConn //nolint:staticcheck // deprecated-обёртка, но API x/net из задачи
}

func newGateway(t *testing.T, cert tls.Certificate, ca *x509.CertPool, alpn string) *gateway {
	t.Helper()
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{alpn},
	}
	raw, err := listenLocal()
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{ln: raw, cc: make(chan *gwConn, 64)}
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			g.attempts.Add(1)
			go func() {
				tc := tls.Server(c, cfg)
				if err := tc.HandshakeContext(context.Background()); err != nil {
					_ = c.Close()
					return
				}
				// TLS 1.3: клиент мог отвергнуть нас после нашего Finished —
				// проверяем жизнеспособность соединения первой записью h2.
				cc, err := (&http2.Transport{}).NewClientConn(tc) //nolint:staticcheck // см. выше
				if err != nil {
					_ = c.Close()
					return
				}
				g.handshakes.Add(1)
				gc := &gwConn{conn: tc, cc: cc}
				g.mu.Lock()
				g.all = append(g.all, gc)
				g.mu.Unlock()
				g.cc <- gc
			}()
		}
	}()
	t.Cleanup(func() {
		_ = raw.Close()
		g.mu.Lock()
		defer g.mu.Unlock()
		for _, c := range g.all {
			_ = c.conn.Close()
		}
	})
	return g
}

func (g *gateway) url() string { return "https://" + g.ln.Addr().String() }

func (g *gateway) next(t *testing.T) *gwConn {
	t.Helper()
	select {
	case c := <-g.cc:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("no reverse connection from agent")
		return nil
	}
}

func (c *gwConn) do(t *testing.T, method, path, body string) (reply, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "https://agent"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{StatusCode: resp.StatusCode}, b
}

// reply — статус ответа reverse-канала (тело уже прочитано и закрыто).
type reply struct{ StatusCode int }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

var fastBackoff = WithConnectorOptions(WithBackoff(10*time.Millisecond, 40*time.Millisecond), WithStableAfter(time.Millisecond))

// revEnv — агент, запускаемый в нужном режиме, с фейковым Telegram и gateway.
type revEnv struct {
	*env
	gw      *gateway
	cfgPath string
	done    chan struct{}
	err     error
	cancel  context.CancelFunc
	api     string
}

func tgOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"result":{"path":"`+r.URL.Path+`"}}`)
	})
}

func newRevEnv(t *testing.T, mode config.AgentMode, withURL bool) *revEnv {
	t.Helper()
	e, upPool := newEnvNoAgent(t, tgOK())
	srvPEM, err := pki.IssueServerClient(e.ca, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gwCert, err := srvPEM.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	r := &revEnv{env: e, gw: newGateway(t, gwCert, e.pool, ALPNReverse)}
	r.api = closedAddr(t)
	e.cfg.Listen.API = r.api
	e.cfg.Mode = mode
	if withURL {
		e.cfg.ServerURL = r.gw.url()
	}
	r.cfgPath = filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(r.cfgPath, []byte("# agent\nmode: "+string(mode)+" # keep\nlisten:\n  api: \""+r.api+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.cfg.SetPath(r.cfgPath)
	r.start(t, upPool)
	return r
}

func (r *revEnv) start(t *testing.T, upPool *x509.CertPool) {
	t.Helper()
	a, err := New(r.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), WithUpstreamRootCAs(upPool), fastBackoff)
	if err != nil {
		t.Fatal(err)
	}
	r.agent = a
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() { r.err = a.Run(ctx); close(r.done) }()
	t.Cleanup(r.stop)
	r.addr = r.api
	r.client = r.newClient(t, r.srvCert, true)
}

func (r *revEnv) stop() {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(15 * time.Second):
	}
}

func portOpen(addr string) bool {
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func status(t *testing.T, c *gwConn) map[string]any {
	t.Helper()
	resp, b := c.do(t, http.MethodGet, "/_agent/status", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReverseProxyAndTwoConns(t *testing.T) {
	r := newRevEnv(t, config.AgentModeReverse, true)
	c1, c2 := r.gw.next(t), r.gw.next(t)

	resp, body := c1.do(t, http.MethodGet, "/tg/bot123:abc/getMe", "")
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"ok":true`) || !strings.Contains(string(body), "/bot123:abc/getMe") {
		t.Fatalf("getMe: %d %s", resp.StatusCode, body)
	}
	if resp, _ := c2.do(t, http.MethodGet, "/tg/bot123:abc/getMe", ""); resp.StatusCode != 200 {
		t.Fatalf("second conn: %d", resp.StatusCode)
	}
	waitFor(t, "2 conns", func() bool { _, _, n, _ := r.agent.mgr.snapshot(); return n == 2 })
	st := status(t, c1)
	if st["reverse_conns"] != float64(2) || st["reverse_state"] != StateConnected || st["mode"] != "reverse" {
		t.Fatalf("status: %v", st)
	}
	if portOpen(r.api) {
		t.Fatal("agent in reverse mode must not listen on the incoming port")
	}
}

func TestReverseReconnectAfterDrop(t *testing.T) {
	r := newRevEnv(t, config.AgentModeReverse, true)
	c1, c2 := r.gw.next(t), r.gw.next(t)
	_ = c1.conn.Close()
	// второе соединение продолжает работать, первое переподключается
	if resp, _ := c2.do(t, http.MethodGet, "/tg/bot1:a/getMe", ""); resp.StatusCode != 200 {
		t.Fatalf("surviving conn: %d", resp.StatusCode)
	}
	c3 := r.gw.next(t)
	if resp, _ := c3.do(t, http.MethodGet, "/tg/bot1:a/getMe", ""); resp.StatusCode != 200 {
		t.Fatalf("reconnected conn: %d", resp.StatusCode)
	}
	waitFor(t, "2 conns again", func() bool { _, _, n, _ := r.agent.mgr.snapshot(); return n == 2 })
}

func TestReverseDrain(t *testing.T) {
	r := newRevEnv(t, config.AgentModeReverse, true)
	c := r.gw.next(t)
	if resp, _ := c.do(t, http.MethodPost, "/_agent/drain", ""); resp.StatusCode != 200 {
		t.Fatalf("drain: %d", resp.StatusCode)
	}
	if resp, _ := c.do(t, http.MethodGet, "/tg/bot1:a/getMe", ""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("draining: %d", resp.StatusCode)
	}
	if st := status(t, c); st["draining"] != true {
		t.Fatalf("status: %v", st)
	}
}

func TestReverseRejectsBadServers(t *testing.T) {
	cases := map[string]func(t *testing.T, e *env) (tls.Certificate, *x509.CertPool){
		"foreign CA": func(t *testing.T, _ *env) (tls.Certificate, *x509.CertPool) {
			ca, err := pki.NewCA("evil", 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			b, err := pki.IssueServerClient(ca, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			c, _ := b.TLSCertificate()
			return c, ca.Pool()
		},
		"no server SAN": func(_ *testing.T, e *env) (tls.Certificate, *x509.CertPool) {
			return e.agCert, e.pool // валидный серт проекта, но агентский
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			e, upPool := newEnvNoAgent(t, tgOK())
			cert, pool := mk(t, e)
			// клиентский CA gateway — наш (агентский серт принимается), серт сервера плохой
			gw := newGateway(t, cert, e.pool, ALPNReverse)
			_ = pool
			e.cfg.Listen.API = closedAddr(t)
			e.cfg.Mode = config.AgentModeReverse
			e.cfg.ServerURL = gw.url()
			a, err := New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), WithUpstreamRootCAs(upPool), fastBackoff)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- a.Run(ctx) }()
			// несколько попыток с backoff, ни одной установленной сессии
			waitFor(t, "retries", func() bool { return gw.attempts.Load() >= 4 })
			if gw.handshakes.Load() != 0 {
				t.Fatalf("session established with bad server: %d", gw.handshakes.Load())
			}
			if _, _, n, st := a.mgr.snapshot(); n != 0 || st != StateConnecting {
				t.Fatalf("conns=%d state=%s", n, st)
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReverseRejectsWrongALPN(t *testing.T) {
	e, upPool := newEnvNoAgent(t, tgOK())
	b, _ := pki.IssueServerClient(e.ca, time.Hour)
	cert, _ := b.TLSCertificate()
	gw := newGateway(t, cert, e.pool, "h2")
	e.cfg.Listen.API = closedAddr(t)
	e.cfg.Mode = config.AgentModeReverse
	e.cfg.ServerURL = gw.url()
	a, err := New(e.cfg, nil, WithUpstreamRootCAs(upPool), fastBackoff)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, "retries", func() bool { return gw.attempts.Load() >= 3 })
	if gw.handshakes.Load() != 0 {
		t.Fatal("session established without reverse ALPN")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReverseSwitchDialReverseDial(t *testing.T) {
	r := newRevEnv(t, config.AgentModeDial, false)
	waitFor(t, "dial listener", func() bool { return portOpen(r.api) })
	put := func(c *http.Client, url, body string) *http.Response {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, url, strings.NewReader(body))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	// dial -> reverse (запрос приходит по dial-листенеру)
	resp := put(r.client, "https://"+r.api+"/_agent/config", `{"mode":"reverse","server_url":"`+r.gw.url()+`"}`) //nolint:bodyclose // закрывается в t.Cleanup и в r.do
	if resp.StatusCode != 200 {
		t.Fatalf("PUT: %d %s", resp.StatusCode, readAll(t, resp.Body))
	}
	c := r.gw.next(t)
	r.gw.next(t)
	waitFor(t, "listener closed", func() bool { return !portOpen(r.api) })
	data, _ := os.ReadFile(r.cfgPath)
	if !strings.Contains(string(data), "mode: reverse") || !strings.Contains(string(data), "server_url: "+r.gw.url()) ||
		!strings.Contains(string(data), "# keep") || !strings.Contains(string(data), "# agent") {
		t.Fatalf("config file:\n%s", data)
	}
	if st := status(t, c); st["mode"] != "reverse" {
		t.Fatalf("status: %v", st)
	}

	// reverse -> dial; ответ на PUT обязан дойти по закрываемому reverse-каналу
	rr, body := c.do(t, http.MethodPut, "/_agent/config", `{"mode":"dial"}`)
	if rr.StatusCode != 200 {
		t.Fatalf("PUT dial: %d %s", rr.StatusCode, body)
	}
	waitFor(t, "listener reopened", func() bool { return portOpen(r.api) })
	waitFor(t, "no reverse conns", func() bool { _, _, n, _ := r.agent.mgr.snapshot(); return n == 0 })
	if got := r.do(t, http.MethodGet, "/_agent/status", nil, nil); got.StatusCode != 200 { //nolint:bodyclose // см. выше
		t.Fatalf("status over dial: %d", got.StatusCode)
	}
	st := readJSON(t, r.do(t, http.MethodGet, "/_agent/status", nil, nil)) //nolint:bodyclose // см. выше
	if st["mode"] != "dial" || st["reverse_conns"] != float64(0) {
		t.Fatalf("status: %v", st)
	}
	data, _ = os.ReadFile(r.cfgPath)
	if !strings.Contains(string(data), "mode: dial") || !strings.Contains(string(data), "server_url: "+r.gw.url()) {
		t.Fatalf("config file:\n%s", data)
	}
}

func TestConfigBothAndServerURLChange(t *testing.T) {
	r := newRevEnv(t, config.AgentModeBoth, true)
	waitFor(t, "dial listener", func() bool { return portOpen(r.api) })
	c := r.gw.next(t)
	r.gw.next(t)
	if resp := r.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil); resp.StatusCode != 200 { //nolint:bodyclose // закрывается в r.do
		t.Fatalf("dial path: %d", resp.StatusCode)
	}
	if resp, _ := c.do(t, http.MethodGet, "/tg/bot1:a/getMe", ""); resp.StatusCode != 200 {
		t.Fatalf("reverse path: %d", resp.StatusCode)
	}
	// смена server_url в reverse: новый gateway получает соединения, старый теряет
	e2 := r.env
	b, _ := pki.IssueServerClient(e2.ca, time.Hour)
	cert, _ := b.TLSCertificate()
	gw2 := newGateway(t, cert, e2.pool, ALPNReverse)
	resp, body := c.do(t, http.MethodPut, "/_agent/config", `{"mode":"reverse","server_url":"`+gw2.url()+`"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT: %d %s", resp.StatusCode, body)
	}
	gw2.next(t)
	gw2.next(t)
	waitFor(t, "listener closed", func() bool { return !portOpen(r.api) })
	// идемпотентный повтор не рвёт соединения
	n := gw2.attempts.Load()
	c2 := gw2.next2(t)
	_ = c2
	if resp, _ := c2.do(t, http.MethodPut, "/_agent/config", `{"mode":"reverse","server_url":"`+gw2.url()+`"}`); resp.StatusCode != 200 {
		t.Fatalf("repeat PUT: %d", resp.StatusCode)
	}
	time.Sleep(100 * time.Millisecond)
	if gw2.attempts.Load() != n {
		t.Fatal("idempotent PUT reconnected")
	}
}

// next2 возвращает любое живое соединение (из уже принятых).
func (g *gateway) next2(t *testing.T) *gwConn {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.all) == 0 {
		t.Fatal("no conns")
	}
	return g.all[len(g.all)-1]
}

func TestConfigValidationAndErrors(t *testing.T) {
	r := newRevEnv(t, config.AgentModeDial, false)
	waitFor(t, "dial listener", func() bool { return portOpen(r.api) })
	put := func(body string) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "https://"+r.api+"/_agent/config", strings.NewReader(body))
		resp, err := r.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for body, want := range map[string]int{
		`not json`:              400,
		`{"mode":"dial","x":1}`: 400,
		`{"mode":"weird"}`:      422,
		`{"mode":"reverse"}`:    422,
		`{"mode":"reverse","server_url":"http://x"}`:   422,
		`{"mode":"both","server_url":"https://u:p@h"}`: 422,
		`{"mode":"dial","server_url":"ftp://h"}`:       422,
	} {
		if code, b := put(body); code != want {
			t.Errorf("%s: %d (%s), want %d", body, code, b, want)
		}
	}
	// без пути файла сохранить нельзя -> 409, состояние не меняется
	r.cfg.SetPath("")
	if code, b := put(`{"mode":"dial"}`); code != 409 || !strings.Contains(b, "persist") {
		t.Fatalf("no path: %d %s", code, b)
	}
	// файл в несуществующем каталоге
	r.cfg.SetPath(filepath.Join(t.TempDir(), "nope", "agent.yaml"))
	if code, _ := put(`{"mode":"dial"}`); code != 409 {
		t.Fatalf("missing file: %d", code)
	}
	if mode, _, _, _ := r.agent.mgr.snapshot(); mode != config.AgentModeDial {
		t.Fatalf("mode changed on failure: %s", mode)
	}
}

func TestConfigApplyFailureRollsBack(t *testing.T) {
	r := newRevEnv(t, config.AgentModeReverse, true)
	c := r.gw.next(t)
	// занимаем порт dial-листенера -> переключение в dial невозможно
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", r.api)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	resp, body := c.do(t, http.MethodPut, "/_agent/config", `{"mode":"dial"}`)
	if resp.StatusCode != 409 || !strings.Contains(string(body), "cannot apply") {
		t.Fatalf("PUT: %d %s", resp.StatusCode, body)
	}
	data, _ := os.ReadFile(r.cfgPath)
	if !strings.Contains(string(data), "mode: reverse") {
		t.Fatalf("file not rolled back:\n%s", data)
	}
	if st := status(t, c); st["mode"] != "reverse" {
		t.Fatalf("status: %v", st)
	}
	// откат тоже может не удаться
	r.agent.saveConn = func(string, config.AgentMode, string) error { return os.ErrPermission }
	resp, body = c.do(t, http.MethodPut, "/_agent/config", `{"mode":"dial"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("PUT: %d %s", resp.StatusCode, body)
	}
}

func TestServeFatalAndReverseClosesPreset(t *testing.T) {
	e, upPool := newEnvNoAgent(t, tgOK())
	a, err := New(e.cfg, nil, WithUpstreamRootCAs(upPool))
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := listenLocal()
	_ = ln.Close()
	if err := a.Serve(context.Background(), ln); err == nil {
		t.Fatal("expected serve error on closed listener")
	}

	// reverse + готовый листенер: листенер закрывается, не используется
	e.cfg.Mode = config.AgentModeReverse
	e.cfg.ServerURL = "https://127.0.0.1:1"
	a, err = New(e.cfg, nil, WithUpstreamRootCAs(upPool), fastBackoff)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ = listenLocal()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, ln) }()
	waitFor(t, "preset closed", func() bool { return !portOpen(ln.Addr().String()) })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// reverse без валидного URL при старте -> ошибка
	e.cfg.ServerURL = "http://nope"
	a, _ = New(e.cfg, nil, WithUpstreamRootCAs(upPool))
	if err := a.Run(context.Background()); err == nil {
		t.Fatal("expected bad server_url error")
	}
}

func TestConnectorUnits(t *testing.T) {
	e, upPool := newEnvNoAgent(t, tgOK())
	a, err := New(e.cfg, nil, WithUpstreamRootCAs(upPool))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.NewConnector("http://x"); err == nil {
		t.Fatal("http must be rejected")
	}
	if _, err := a.NewConnector("https://h", WithBackoff(0, time.Second)); err == nil {
		t.Fatal("bad backoff must be rejected")
	}
	c, err := a.NewConnector("https://example.org", WithConns(3), WithBackoff(time.Second, 8*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c.addr != "example.org:443" || c.n != 3 || c.State() != StateConnecting || c.Conns() != 0 {
		t.Fatalf("connector: %+v", c)
	}
	if c.tlsCfg.ServerName != "example.org" {
		t.Fatal("SNI not set for DNS host")
	}
	ip, _ := a.NewConnector("https://127.0.0.1:8444")
	if ip.tlsCfg.ServerName != "" || ip.addr != "127.0.0.1:8444" {
		t.Fatalf("ip connector: %s %q", ip.addr, ip.tlsCfg.ServerName)
	}
	WithConns(0)(c)
	if c.n != 3 {
		t.Fatal("WithConns(0) must be ignored")
	}
	// backoff: экспонента с потолком, jitter в [d/2, d]
	for attempt, max := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second} {
		for range 50 {
			if d := c.backoff(attempt); d < max/2 || d > max {
				t.Fatalf("attempt %d: %v not in [%v,%v]", attempt, d, max/2, max)
			}
		}
	}
	c.backoffMin, c.backoffMax = 1, 1
	if d := c.backoff(3); d != 1 {
		t.Fatalf("tiny backoff: %v", d)
	}
}

func TestReverseGracefulStop(t *testing.T) {
	r := newRevEnv(t, config.AgentModeReverse, true)
	c := r.gw.next(t)
	r.gw.next(t)
	r.cancel()
	select {
	case <-r.done:
		if r.err != nil {
			t.Fatal(r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop")
	}
	if _, _, n, _ := r.agent.mgr.snapshot(); n != 0 {
		t.Fatalf("conns after stop: %d", n)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://agent/_agent/healthz", bytes.NewReader(nil))
	if resp, err := c.cc.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("request after stop must fail")
	}
}
