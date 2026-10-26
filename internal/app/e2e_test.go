package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

const (
	testToken = "123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testKey   = "tgp_devkey_local_only"
	mb        = 1 << 20
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type e2eOpts struct {
	rules  []config.AccessRule
	agents int  // число агентов (по умолчанию 1: id "local"); id остальных — "a2", "a3"…
	obs    bool // метрики + история + уведомления (telegram_id получателя — obsChatID)
}

const (
	notifyToken = "777000:NOTIFYNOTIFYNOTIFYNOTIFYNOTIFYNOTIFY1"
	obsChatID   = int64(424242)
	metricsBear = "metrics-bearer-for-tests"
)

type tgMessage struct {
	ChatID int64  `json:"chat_id"`
	Text   string `json:"text"`
}

type e2eAgent struct {
	id          string
	addr        string
	metricsAddr string // адрес /metrics агента (loopback, без bearer)
	cancel      context.CancelFunc
	done        chan struct{}
}

type e2e struct {
	t          *testing.T
	logs       *syncBuf
	logger     *slog.Logger
	level      *slog.LevelVar
	cfg        *config.ServerConfig
	pkiDir     string
	upPool     *x509.CertPool
	tg         *httptest.Server
	tgHandler  http.HandlerFunc
	tgHits     atomic.Int64
	srv        *Server
	dial       *transport.Dial
	proxyURL   string
	adminURL   string
	agents     []*e2eAgent
	srvDone    chan error
	cancelSrv  context.CancelFunc
	gotSHA     chan [32]byte
	reloadCfg  func() (*config.ServerConfig, error)
	metricsURL string
	ticks      chan time.Time
	msgs       chan tgMessage
}

func localRule(cidr string) config.AccessRule {
	return config.AccessRule{Name: "net", CIDRs: []netip.Prefix{netip.MustParsePrefix(cidr)}}
}

func keyRule() config.AccessRule {
	h := sha256.Sum256([]byte(testKey))
	return config.AccessRule{Name: "key", KeySHA256: fmt.Sprintf("%x", h[:]), KeyHash: h[:]}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// startAgent запускает агента id на addr ("" — свободный порт).
func (e *e2e) startAgent(id, addr string) *e2eAgent {
	e.t.Helper()
	acfg := config.DefaultAgent()
	acfg.TLS = config.TLSFiles{
		CertFile: filepath.Join(e.pkiDir, pki.AgentCertFile(id)),
		KeyFile:  filepath.Join(e.pkiDir, pki.AgentKeyFile(id)),
		CAFile:   filepath.Join(e.pkiDir, pki.FileCACert),
	}
	acfg.DataDir = e.t.TempDir()
	mln := listen(e.t) // резервируем адрес, чтобы тесты могли читать /metrics агента
	metricsAddr := mln.Addr().String()
	_ = mln.Close()
	acfg.Listen.Metrics = metricsAddr
	if err := acfg.OverrideTelegramAPIURL(e.tg.URL); err != nil {
		e.t.Fatal(err)
	}
	var ln net.Listener
	if addr == "" {
		ln = listen(e.t)
	} else {
		var err error
		for range 50 { // порт может освобождаться не мгновенно
			if ln, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			e.t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &e2eAgent{id: id, addr: ln.Addr().String(), metricsAddr: metricsAddr, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(a.done)
		_ = RunAgent(ctx, acfg, e.logger, AgentOptions{Agent: []agent.Option{agent.WithUpstreamRootCAs(e.upPool)}, Listener: ln})
	}()
	return a
}

func (a *e2eAgent) stop(t *testing.T) {
	t.Helper()
	a.cancel()
	select {
	case <-a.done:
	case <-time.After(15 * time.Second):
		t.Error("agent did not stop")
	}
}

func newE2E(t *testing.T, o e2eOpts) *e2e {
	t.Helper()
	e := &e2e{t: t, logs: &syncBuf{}, gotSHA: make(chan [32]byte, 4)}
	logger, level, err := NewLogger(config.LoggingConfig{Level: "debug", Format: "text"}, e.logs)
	if err != nil {
		t.Fatal(err)
	}
	e.logger, e.level = logger, level

	// фейковый Telegram
	e.tg = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.tgHits.Add(1)
		if e.msgs != nil && r.URL.Path == "/bot"+notifyToken+"/sendMessage" {
			var m tgMessage
			_ = json.NewDecoder(r.Body).Decode(&m)
			e.msgs <- m
			_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":7}}`)
			return
		}
		if e.tgHandler != nil {
			e.tgHandler(w, r)
			return
		}
		defaultTG(e, w, r)
	}))
	t.Cleanup(e.tg.Close)
	e.upPool = x509.NewCertPool()
	e.upPool.AddCert(e.tg.Certificate())

	// PKI и агенты
	n := max(o.agents, 1)
	ids := []string{"local"}
	for i := 2; i <= n; i++ {
		ids = append(ids, fmt.Sprintf("a%d", i))
	}
	e.pkiDir = t.TempDir()
	if err := pki.DevInit(e.pkiDir, ids); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		e.agents = append(e.agents, e.startAgent(id, ""))
	}
	t.Cleanup(func() {
		for _, a := range e.agents {
			a.cancel()
		}
		for _, a := range e.agents {
			select {
			case <-a.done:
			case <-time.After(15 * time.Second):
				t.Error("agent did not stop")
			}
		}
	})

	// сервер
	scfg := config.DefaultServer()
	scfg.Listen.Metrics = "127.0.0.1:0"
	scfg.Listen.Proxy = "127.0.0.1:0" // tls.mode=off допустим только на loopback без trusted_proxies
	for _, a := range e.agents {
		scfg.Agents = append(scfg.Agents, config.AgentEndpoint{ID: a.id, URL: "https://" + a.addr, Mode: config.AgentModeDial, Weight: 1})
	}
	scfg.AgentTLS = config.TLSFiles{
		CertFile: filepath.Join(e.pkiDir, pki.FileServerCert),
		KeyFile:  filepath.Join(e.pkiDir, pki.FileServerKey),
		CAFile:   filepath.Join(e.pkiDir, pki.FileCACert),
	}
	scfg.Store.SQLitePath = filepath.Join(t.TempDir(), "tgproxy.db")
	scfg.Buffer.TmpDir = t.TempDir()
	scfg.Router.NoAgentWait = time.Second
	scfg.AccessRules = o.rules
	if scfg.AccessRules == nil {
		scfg.AccessRules = []config.AccessRule{localRule("127.0.0.0/8"), keyRule()}
	}
	e.cfg = scfg
	sopts := ServerOptions{}
	chatID := int64(0)
	if o.obs {
		chatID = obsChatID
	}
	dir := t.TempDir()
	scfg.Auth.UsersFile = writeTestUsers(t, dir, chatID)
	scfg.Auth.AllowPasswordOnly = true
	scfg.PKI.KEKFile = filepath.Join(dir, "kek")
	if err := pki.GenerateKEK(scfg.PKI.KEKFile); err != nil {
		t.Fatal(err)
	}
	scfg.Server.PublicBaseURL = "http://127.0.0.1:8080"
	if o.obs {
		tokFile := filepath.Join(dir, "notify-token")
		if err := os.WriteFile(tokFile, []byte(notifyToken), 0o600); err != nil {
			t.Fatal(err)
		}
		scfg.Notify.BotTokenFile, scfg.Notify.BotToken = tokFile, config.Secret(notifyToken)
		scfg.Metrics.Bearer = config.Secret(metricsBear)
		e.ticks, e.msgs = make(chan time.Time), make(chan tgMessage, 32)
		mln := listen(t)
		e.metricsURL = "http://" + mln.Addr().String()
		sopts.MetricsListener, sopts.SamplerTicks, sopts.NotifyPoll = mln, e.ticks, 50*time.Millisecond
	}
	e.reloadCfg = func() (*config.ServerConfig, error) { return scfg, nil }

	pln, adln := listen(t), listen(t)
	e.proxyURL = "http://" + pln.Addr().String()
	e.adminURL = "http://" + adln.Addr().String()
	sopts.Level = level
	sopts.ReloadConfig = func() (*config.ServerConfig, error) { return e.reloadCfg() }
	sopts.AccessOptions = []access.Option{access.WithRefreshInterval(100 * time.Millisecond)}
	sopts.AgentOptions = []agents.Option{agents.WithPollInterval(150 * time.Millisecond),
		agents.WithPollTimeout(time.Second), agents.WithReloadInterval(100 * time.Millisecond)}
	srv, err := NewServer(context.Background(), scfg, logger, sopts)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv

	// отдельный Dial для прямых проверок адаптера
	cert, pool, err := loadAgentTLS(scfg)
	if err != nil {
		t.Fatal(err)
	}
	e.dial = transport.NewDial(cert, pool)
	t.Cleanup(func() { _ = e.dial.Close() })

	sctx, scancel := context.WithCancel(context.Background())
	e.cancelSrv = scancel
	e.srvDone = make(chan error, 1)
	go func() { e.srvDone <- srv.Serve(sctx, pln, adln) }()
	t.Cleanup(func() {
		scancel()
		select {
		case err := <-e.srvDone:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(40 * time.Second):
			t.Error("server did not stop")
		}
	})
	e.waitReady(n)
	return e
}

// waitReady ждёт, пока в реестре up станет не меньше n агентов.
func (e *e2e) waitReady(n int) {
	e.t.Helper()
	e.waitFor(10*time.Second, "agents up", func() bool {
		up := 0
		for _, st := range e.srv.reg.List() {
			if st.Up {
				up++
			}
		}
		return up >= n
	})
}

func (e *e2e) waitFor(d time.Duration, what string, ok func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func defaultTG(e *e2e, w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/bot"+testToken+"/getMe":
		_, _ = io.WriteString(w, `{"ok":true,"result":{"id":123456,"is_bot":true,"username":"fake_bot"}}`)
	case r.URL.Path == "/bot"+testToken+"/sendDocument":
		h := sha256.New()
		_, _ = io.Copy(h, r.Body)
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		e.gotSHA <- sum
		_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":1}}`)
	case strings.HasPrefix(r.URL.Path, "/file/bot"+testToken+"/"):
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fileBlob)
	case r.URL.Path == "/bot"+testToken+"/getUpdates":
		time.Sleep(1500 * time.Millisecond)
		_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
	default:
		http.NotFound(w, r)
	}
}

var fileBlob = func() []byte {
	b := make([]byte, 5*mb)
	_, _ = rand.Read(b)
	return b
}()

type result struct{ StatusCode int }

func (e *e2e) do(method, path string, hdr http.Header, body io.Reader) (result, []byte) {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, e.proxyURL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return result{StatusCode: resp.StatusCode}, b
}

func TestE2EGetMeByNetworkRule(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	resp, b := e.do("GET", "/bot"+testToken+"/getMe", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

func TestE2EGetMeByKey(t *testing.T) {
	// сеть не подходит, остаётся ключ
	e := newE2E(t, e2eOpts{rules: []config.AccessRule{localRule("10.0.0.0/8"), keyRule()}})
	resp, b := e.do("GET", "/k/"+testKey+"/bot"+testToken+"/getMe", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp, _ = e.do("GET", "/bot"+testToken+"/getMe", nil, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("no key: %d", resp.StatusCode)
	}
}

func TestE2EDenied(t *testing.T) {
	e := newE2E(t, e2eOpts{rules: []config.AccessRule{localRule("10.0.0.0/8")}})
	resp, _ := e.do("GET", "/bot"+testToken+"/getMe", nil, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestE2ESendDocument5MB(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	payload := make([]byte, 5*mb)
	_, _ = rand.Read(payload)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("chat_id", "42")
	fw, _ := mw.CreateFormFile("document", "a.bin")
	_, _ = fw.Write(payload)
	_ = mw.Close()
	want := sha256.Sum256(body.Bytes())
	resp, b := e.do("POST", "/bot"+testToken+"/sendDocument",
		http.Header{"Content-Type": {mw.FormDataContentType()}}, bytes.NewReader(body.Bytes()))
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	select {
	case got := <-e.gotSHA:
		if got != want {
			t.Fatal("body mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake telegram did not get the body")
	}
}

func TestE2EFileDownload5MB(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	resp, b := e.do("GET", "/file/bot"+testToken+"/documents/file_1.bin", nil, nil)
	if resp.StatusCode != 200 || !bytes.Equal(b, fileBlob) {
		t.Fatalf("%d, len %d", resp.StatusCode, len(b))
	}
}

func TestE2EGetUpdatesLongPoll(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	start := time.Now()
	resp, b := e.do("GET", "/bot"+testToken+"/getUpdates?timeout=2", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if d := time.Since(start); d < 1400*time.Millisecond {
		t.Fatalf("answered too early: %v", d)
	}
}

func TestE2EAgentDown502(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.agents[0].stop(t)
	// агент known-down в реестре (опрос/пассивный health) -> балансировщик пуст
	e.waitFor(10*time.Second, "agent down", func() bool { st, _ := e.srv.reg.Get("local"); return !st.Up })
	resp, b := e.do("GET", "/bot"+testToken+"/getMe", nil, nil)
	var env struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	if resp.StatusCode != 502 || env.Description != "tgproxy: no healthy agents" {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	// readyz без живых агентов — 503
	r2, _ := e.adminGet("/readyz")
	if r2.StatusCode != 503 {
		t.Fatalf("readyz: %d", r2.StatusCode)
	}
}

// Один из двух агентов остановлен: запросы идут через второй без ошибок
// (в том числе до того, как реестр заметил падение).
func TestE2ETwoAgentsOneStopped(t *testing.T) {
	e := newE2E(t, e2eOpts{agents: 2})
	for i := 0; i < 10; i++ {
		if resp, b := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); resp.StatusCode != 200 {
			t.Fatalf("warmup %d: %d %s", i, resp.StatusCode, b)
		}
	}
	e.agents[0].stop(t)
	for i := 0; i < 60; i++ {
		resp, b := e.do("GET", "/bot"+testToken+"/getMe", nil, nil)
		if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok":true`) {
			t.Fatalf("request %d: %d %s", i, resp.StatusCode, b)
		}
	}
	e.waitFor(10*time.Second, "local down", func() bool { st, _ := e.srv.reg.Get("local"); return !st.Up })
	if r, _ := e.adminGet("/readyz"); r.StatusCode != 200 {
		t.Fatalf("readyz with one agent up: %d", r.StatusCode)
	}

	// возвращаем агента: снова up без рестарта сервера
	e.agents[0] = e.startAgent("local", e.agents[0].addr)
	e.waitFor(10*time.Second, "local up again", func() bool { st, _ := e.srv.reg.Get("local"); return st.Up })
}

func tgRateLimited(chat string, retry int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/sendMessage") && r.URL.Query().Get("chat_id") == chat {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintf(w, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after %d","parameters":{"retry_after":%d}}`, retry, retry)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":1}}`)
	}
}

// 429 от Telegram открывает окно (bot, chat): повторы в тот же чат получают
// 429 от сервера без похода к агенту, другой чат проходит.
func TestE2E429Window(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.tgHandler = tgRateLimited("7", 5)
	send := func(chat string) (result, []byte) {
		return e.do("POST", "/bot"+testToken+"/sendMessage?chat_id="+chat+"&text=x", nil, nil)
	}
	if r, _ := send("7"); r.StatusCode != 429 {
		t.Fatalf("first: %d", r.StatusCode)
	}
	hits := e.tgHits.Load()
	r, b := send("7")
	if r.StatusCode != 429 || !strings.Contains(string(b), `"retry_after"`) {
		t.Fatalf("second: %d %s", r.StatusCode, b)
	}
	if e.tgHits.Load() != hits {
		t.Fatal("window must answer without calling the agent")
	}
	if r, _ := send("8"); r.StatusCode != 200 {
		t.Fatalf("other chat: %d", r.StatusCode)
	}
}

// Rate-limit правила: сверх rps — 429 от сервера, агент не вызывается.
func TestE2ERuleRateLimit(t *testing.T) {
	rule := localRule("127.0.0.0/8")
	rule.RPS = 1
	e := newE2E(t, e2eOpts{rules: []config.AccessRule{rule}})
	if r, b := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); r.StatusCode != 200 {
		t.Fatalf("first: %d %s", r.StatusCode, b)
	}
	hits := e.tgHits.Load()
	limited := 0
	for range 5 {
		resp, b := e.do("GET", "/bot"+testToken+"/getMe", nil, nil)
		if resp.StatusCode == 429 {
			limited++
			var env struct {
				Parameters struct {
					RetryAfter int `json:"retry_after"`
				} `json:"parameters"`
			}
			if err := json.Unmarshal(b, &env); err != nil || env.Parameters.RetryAfter < 1 {
				t.Fatalf("bad 429 body: %s", b)
			}
		}
	}
	if limited == 0 {
		t.Fatal("no 429 above rps")
	}
	if got := e.tgHits.Load() - hits; got != int64(5-limited) {
		t.Fatalf("agent called %d times, want %d (limited requests must not reach the agent)", got, 5-limited)
	}
}

// Правило, добавленное через CLI-функцию прямо в БД, начинает работать без рестарта.
func TestE2EAccessAddedViaCLIWithoutRestart(t *testing.T) {
	e := newE2E(t, e2eOpts{rules: []config.AccessRule{localRule("10.0.0.0/8")}})
	if r, _ := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); r.StatusCode != 403 {
		t.Fatalf("before: %d", r.StatusCode)
	}
	st, err := OpenSQLite(context.Background(), e.cfg) // как `tgproxy access add -c server.yaml`
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	res, err := AccessAdd(context.Background(), st.AccessRules(), AccessAddParams{Name: "ext", WithKey: true})
	if err != nil || res.Key == "" {
		t.Fatalf("add: %v", err)
	}
	e.waitFor(5*time.Second, "key rule active", func() bool {
		r, _ := e.do("GET", "/k/"+res.Key+"/bot"+testToken+"/getMe", nil, nil)
		return r.StatusCode == 200
	})
	// удаление тоже подхватывается
	if _, err := AccessDelete(context.Background(), st.AccessRules(), 0, "ext"); err != nil {
		t.Fatal(err)
	}
	e.waitFor(5*time.Second, "key rule revoked", func() bool {
		r, _ := e.do("GET", "/k/"+res.Key+"/bot"+testToken+"/getMe", nil, nil)
		return r.StatusCode == 403
	})
}

// Правила из конфига засеваются в БД только при пустой таблице.
func TestE2ESeedOnlyIntoEmptyTables(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rules, err := e.srv.st.AccessRules().List(context.Background())
	if err != nil || len(rules) != 2 {
		t.Fatalf("seeded rules: %d %v", len(rules), err)
	}
	ags, err := e.srv.st.Agents().List(context.Background())
	if err != nil || len(ags) != 1 || ags[0].ID != "local" {
		t.Fatalf("seeded agents: %+v %v", ags, err)
	}
}

func (e *e2e) adminGet(path string) (result, string) {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", e.adminURL+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return result{StatusCode: resp.StatusCode}, string(b)
}

func TestE2EAdminHealth(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	if r, _ := e.adminGet("/healthz"); r.StatusCode != 200 {
		t.Fatalf("healthz %d", r.StatusCode)
	}
	if r, _ := e.adminGet("/readyz"); r.StatusCode != 200 {
		t.Fatalf("readyz %d", r.StatusCode)
	}
}

type slowReader struct{ left int64 }

func (s *slowReader) Read(p []byte) (int, error) {
	if s.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > s.left {
		n = s.left
	}
	s.left -= n
	return int(n), nil
}

func TestE2EBodyTooLarge413(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	const size = 52 * mb
	hdr := http.Header{"Content-Type": {"application/octet-stream"}}

	// известный Content-Length
	req, _ := http.NewRequestWithContext(context.Background(), "POST", e.proxyURL+"/bot"+testToken+"/sendDocument",
		bytes.NewReader(make([]byte, size)))
	req.Header = hdr.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("known length: %d", resp.StatusCode)
	}

	// chunked: MaxBytesError приходит из тела через транспорт в роутер
	req2, _ := http.NewRequestWithContext(context.Background(), "POST", e.proxyURL+"/bot"+testToken+"/sendDocument",
		io.NopCloser(&slowReader{left: size}))
	req2.Header = hdr.Clone()
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != 413 {
		t.Fatalf("chunked: %d", resp2.StatusCode)
	}
}

func TestE2EReloadAppliesLogLevel(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	next := *e.cfg
	next.Logging.Level = "warn"
	e.reloadCfg = func() (*config.ServerConfig, error) { return &next, nil }
	if err := e.srv.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.level.Level() != slog.LevelWarn {
		t.Fatalf("level not applied: %v", e.level.Level())
	}
	if resp, _ := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("after reload: %d", resp.StatusCode)
	}

	next.Logging.Level = "nope"
	if err := e.srv.Reload(context.Background()); err == nil {
		t.Fatal("bad level must be rejected")
	}
	e.reloadCfg = func() (*config.ServerConfig, error) { return nil, fmt.Errorf("boom") }
	if err := e.srv.Reload(context.Background()); err == nil {
		t.Fatal("loader error must propagate")
	}
	if resp, _ := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("after rejected reload: %d", resp.StatusCode)
	}
}

func TestE2ENoTokenInLogs(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.do("GET", "/bot"+testToken+"/getMe", nil, nil)
	e.do("GET", "/k/"+testKey+"/bot"+testToken+"/getMe", nil, nil)
	e.agents[0].stop(t)
	e.do("GET", "/bot"+testToken+"/getMe", nil, nil) // ошибочный путь тоже пишет логи
	logs := e.logs.String()
	if logs == "" {
		t.Fatal("no logs captured")
	}
	if strings.Contains(logs, "AAAAAAAAAAAAAAAAAAAA") {
		t.Fatalf("token leaked in logs:\n%s", logs)
	}
	if strings.Contains(logs, testKey) {
		t.Fatalf("client key leaked in logs:\n%s", logs)
	}
}

func TestIngressTLSACMEViaEgressNeedsClient(t *testing.T) {
	c := config.DefaultServer()
	c.Listen.Metrics = "127.0.0.1:0"
	c.TLS = config.IngressTLS{
		Mode: config.TLSModeACME, Domains: []string{"x.test"}, CacheDir: filepath.Join(t.TempDir(), "acme"),
		ACME: config.ACMEConfig{ViaAgentEgress: true},
	}
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := s.newIngress(c); err == nil || !strings.Contains(err.Error(), "via_agent_egress") {
		t.Fatalf("got %v", err)
	}
}

func TestNewLoggerRedactsAndLevels(t *testing.T) {
	var buf syncBuf
	l, lv, err := NewLogger(config.LoggingConfig{Level: "info", Format: "json"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	l.Debug("hidden")
	l.Info("tok " + testToken)
	lv.Set(-4)
	l.Debug("shown")
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, "shown") || strings.Contains(out, "AAAAAAAA") {
		t.Fatal(out)
	}
	if _, _, err := NewLogger(config.LoggingConfig{Level: "x", Format: "json"}, &buf); err == nil {
		t.Fatal("bad level")
	}
	if _, _, err := NewLogger(config.LoggingConfig{Level: "info", Format: "xml"}, &buf); err == nil {
		t.Fatal("bad format")
	}
}

// testPassword — пароль пользователей тестового users-файла.
const testPassword = "test-password"

// writeTestUsers пишет users-файл (admin с паролем testPassword, получатель alert-ов chatID).
func writeTestUsers(t *testing.T, dir string, chatID int64) string {
	t.Helper()
	hash, err := auth.Hash(testPassword, auth.DefaultHashParams())
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("users:\n  admin:\n    displayname: Test Admin\n    password: '%s'\n    telegram_id: %d\n"+
		"  nobody:\n    password: '%s'\n    telegram_id: 0\n", hash, chatID, hash)
	path := filepath.Join(dir, "users.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
