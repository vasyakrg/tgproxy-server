package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/enroll"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

func TestALPNReverseConstantsMatch(t *testing.T) {
	if agent.ALPNReverse != transport.ALPNReverse {
		t.Fatalf("agent.ALPNReverse=%q transport.ALPNReverse=%q", agent.ALPNReverse, transport.ALPNReverse)
	}
}

// pkiEnv — сервер в PKI-режиме (CA в БД под KEK, agent_gateway) и фейковый Telegram.
type pkiEnv struct {
	t        *testing.T
	logs     *syncBuf
	srv      *Server
	tg       *httptest.Server
	tgHits   atomic.Int64
	upPool   *x509.CertPool
	proxyURL string
	adminURL string
	gwAddr   string
	metrics  string
	dir      string
	cancel   context.CancelFunc
	done     chan error
	agents   []*e2eAgent
	// tgHandler подменяет ответ фейкового Telegram (nil — стандартный getMe).
	tgHandler atomic.Pointer[http.HandlerFunc]
	ticks     chan time.Time // непустой, если тест сам управляет сэмплером истории
}

// pkiOpts — необязательные параметры newPKIEnvWith.
type pkiOpts struct {
	rules []config.AccessRule
	ticks bool // ручной сэмплер: e.ticks <- time.Now() сбрасывает историю/журнал ошибок в БД
	// pkgVersion != "" — «версия сервера» с подписанным релизом в кэше загрузок: нужна для команды
	// установки агента (enroll.Service требует проверенный пакет текущей версии).
	pkgVersion string
	// mtproto включает MTProto на shared-листенере (TLS-вход с SAN mtDomain).
	mtproto bool
	// scfg правит конфиг сервера до старта (после базовых значений).
	scfg func(*config.ServerConfig)
}

const pkiMetricsBearer = "pki-metrics-bearer"

func newPKIEnv(t *testing.T) *pkiEnv { return newPKIEnvWith(t, pkiOpts{}) }

func newPKIEnvWith(t *testing.T, o pkiOpts) *pkiEnv {
	t.Helper()
	e := &pkiEnv{t: t, logs: &syncBuf{}, dir: t.TempDir()}
	if o.ticks {
		e.ticks = make(chan time.Time)
	}
	logger, level, err := NewLogger(config.LoggingConfig{Level: "debug", Format: "text"}, e.logs)
	if err != nil {
		t.Fatal(err)
	}
	e.tg = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.tgHits.Add(1)
		if h := e.tgHandler.Load(); h != nil {
			(*h)(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/getMe") {
			_, _ = io.WriteString(w, `{"ok":true,"result":{"id":123456,"is_bot":true,"username":"fake_bot"}}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(e.tg.Close)
	e.upPool = x509.NewCertPool()
	e.upPool.AddCert(e.tg.Certificate())

	scfg := config.DefaultServer()
	scfg.Listen.Proxy = "127.0.0.1:0"
	scfg.Listen.Metrics = "127.0.0.1:0"
	scfg.Store.SQLitePath = filepath.Join(e.dir, "tgproxy.db")
	scfg.Buffer.TmpDir = t.TempDir()
	scfg.Router.NoAgentWait = time.Second
	scfg.AccessRules = []config.AccessRule{localRule("127.0.0.0/8")}
	if o.rules != nil {
		scfg.AccessRules = o.rules
	}
	scfg.Auth.UsersFile = writeTestUsers(t, e.dir, 0)
	scfg.Auth.AllowPasswordOnly = true
	scfg.PKI.KEKFile = filepath.Join(e.dir, "kek")
	scfg.Server.PublicBaseURL = "http://127.0.0.1:8080"
	scfg.Metrics.Bearer = config.Secret(pkiMetricsBearer)
	scfg.Update.StagingDir = filepath.Join(e.dir, "updates") // кэш загрузок для раскатки агентов
	tokFile := filepath.Join(e.dir, "notify-token")
	if err := os.WriteFile(tokFile, []byte(notifyToken), 0o600); err != nil {
		t.Fatal(err)
	}
	scfg.Notify.BotTokenFile, scfg.Notify.BotToken = tokFile, config.Secret(notifyToken)
	if err := pki.GenerateKEK(scfg.PKI.KEKFile); err != nil {
		t.Fatal(err)
	}
	if o.mtproto {
		cf, kf := writeIngressPair(t, t.TempDir(), 1)
		scfg.TLS = config.IngressTLS{Mode: config.TLSModeFiles, CertFile: cf, KeyFile: kf}
		scfg.MTProto.Enabled = true
		scfg.MTProto.FrontingDomain = mtDomain
		scfg.MTProto.MaxConnsPerIP = 1000
	}
	if o.scfg != nil {
		o.scfg(scfg)
	}

	// `tgproxy pki init`: без явной инициализации сервер не стартует.
	if _, err := NewServer(context.Background(), scfg, logger); err == nil || !strings.Contains(err.Error(), "CA is not initialized") {
		t.Fatalf("server without CA: %v", err)
	}
	initCA(t, scfg)
	if o.pkgVersion != "" {
		old := buildinfo.Version
		buildinfo.Version = o.pkgVersion
		t.Cleanup(func() { buildinfo.Version = old })
		signer := newE2ESigner(t)
		pub, perr := signer.pub.MarshalText()
		if perr != nil {
			t.Fatal(perr)
		}
		scfg.Update.PubKeys = []string{string(pub)}
		e.publishRelease(o.pkgVersion, signer)
	}

	gwLn, mln, pln, adln := listen(t), listen(t), listen(t), listen(t)
	e.gwAddr = gwLn.Addr().String()
	scheme := "http://"
	if o.mtproto {
		scheme = "https://"
	}
	e.metrics = scheme + mln.Addr().String()
	e.proxyURL = scheme + pln.Addr().String()
	e.adminURL = scheme + adln.Addr().String()
	srv, err := NewServer(context.Background(), scfg, logger, ServerOptions{
		Level: level, GatewayListener: gwLn, MetricsListener: mln, SamplerTicks: e.ticks,
		GatewayURL:       "https://" + e.gwAddr,
		DenylistInterval: 50 * time.Millisecond,
		AccessOptions:    []access.Option{access.WithRefreshInterval(100 * time.Millisecond)},
		AgentOptions: []agents.Option{agents.WithPollInterval(150 * time.Millisecond),
			agents.WithPollTimeout(time.Second), agents.WithReloadInterval(100 * time.Millisecond)},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan error, 1)
	go func() { e.done <- srv.Serve(ctx, pln, adln) }()
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
		cancel()
		select {
		case err := <-e.done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(40 * time.Second):
			t.Error("server did not stop")
		}
	})
	return e
}

func initCA(t *testing.T, cfg *config.ServerConfig) {
	t.Helper()
	ctx := context.Background()
	st, err := OpenSQLite(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	kek, err := pki.LoadKEK(cfg.PKI.KEKFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadOrInit(ctx, st.Certs(), kek, pki.Options{}); err != nil {
		t.Fatal(err)
	}
}

func (e *pkiEnv) waitFor(d time.Duration, what string, ok func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timeout waiting for %s\nlogs:\n%s", what, e.logs.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (e *pkiEnv) up(id string) bool {
	st, ok := e.srv.reg.Get(id)
	return ok && st.Up
}

func (e *pkiEnv) addAgent(id string, mode store.AgentMode, url string) {
	e.t.Helper()
	if _, err := e.srv.st.Agents().Create(context.Background(), store.Agent{ID: id, Name: id, Mode: mode, URL: url, Weight: 1}); err != nil {
		e.t.Fatal(err)
	}
	if err := e.srv.reg.Refresh(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

// issue выпускает агенту сертификат от CA сервера и пишет crt/key/ca в каталог.
func (e *pkiEnv) issue(id string) config.TLSFiles {
	e.t.Helper()
	csr, key, err := pki.NewAgentCSR(id)
	if err != nil {
		e.t.Fatal(err)
	}
	crt, _, err := e.srv.Authority().SignAgentCSR(context.Background(), csr, id, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	dir := filepath.Join(e.dir, "agent-"+id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		e.t.Fatal(err)
	}
	f := config.TLSFiles{CertFile: filepath.Join(dir, "agent.crt"), KeyFile: filepath.Join(dir, "agent.key"), CAFile: filepath.Join(dir, "ca.crt")}
	for path, data := range map[string][]byte{f.CertFile: crt, f.KeyFile: key, f.CAFile: e.srv.Authority().CertPEM()} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			e.t.Fatal(err)
		}
	}
	return f
}

func (e *pkiEnv) agentConfig(files config.TLSFiles, mode config.AgentMode) *config.AgentConfig {
	e.t.Helper()
	acfg := config.DefaultAgent()
	acfg.TLS, acfg.Mode, acfg.DataDir = files, mode, e.t.TempDir()
	acfg.ServerURL = "https://" + e.gwAddr
	acfg.Listen.Metrics = "127.0.0.1:0"
	if err := acfg.OverrideTelegramAPIURL(e.tg.URL); err != nil {
		e.t.Fatal(err)
	}
	return acfg
}

// startReverse запускает агента без листенера: он сам дозванивается до gateway.
func (e *pkiEnv) startReverse(id string, acfg *config.AgentConfig) *e2eAgent {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a := &e2eAgent{id: id, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(a.done)
		_ = RunAgent(ctx, acfg, e.srv.logger, AgentOptions{Agent: []agent.Option{
			agent.WithUpstreamRootCAs(e.upPool),
			agent.WithConnectorOptions(agent.WithBackoff(50*time.Millisecond, 200*time.Millisecond)),
		}})
	}()
	e.agents = append(e.agents, a)
	return a
}

func (e *pkiEnv) getMe() (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, e.proxyURL+"/bot"+testToken+"/getMe", http.NoBody)
	if err != nil {
		return 0, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func (e *pkiEnv) metricsBody() string {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, e.metrics+"/metrics", http.NoBody)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+pkiMetricsBearer)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // тестовый самоподписанный сертификат входа
	}}
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func certSerialFromFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		t.Fatal("no PEM in " + path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pki.SerialString(c)
}

func TestPKIReverseAgentServesProxyRequests(t *testing.T) {
	e := newPKIEnv(t)
	files := e.issue("nat1")
	e.addAgent("nat1", store.ModeReverse, "")
	e.startReverse("nat1", e.agentConfig(files, config.AgentModeReverse))

	e.waitFor(10*time.Second, "reverse agent up", func() bool { return e.up("nat1") })
	// Агент поднимается по первому соединению; второе может ещё устанавливаться.
	e.waitFor(10*time.Second, "2 reverse conns", func() bool { return e.srv.pki.pool.Conns("nat1") == 2 })
	before := e.tgHits.Load()
	for range 5 {
		if code, err := e.getMe(); err != nil || code != http.StatusOK {
			t.Fatalf("getMe via reverse agent: %d %v\nlogs:\n%s", code, err, e.logs.String())
		}
	}
	if got := e.tgHits.Load() - before; got != 5 {
		t.Fatalf("telegram hits through the agent: %d, want 5", got)
	}
	body := e.metricsBody()
	for _, want := range []string{`tgp_agent_up{agent="nat1",mode="reverse"} 1`, `tgp_agent_reverse_conns{agent="nat1"} 2`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, grepLines(body, "tgp_agent_"))
		}
	}
}

func TestPKIEnrollmentEndToEnd(t *testing.T) {
	e := newPKIEnvWith(t, pkiOpts{pkgVersion: "1.2.3"})
	svc := e.srv.Enrollment()
	if svc == nil {
		t.Fatal("enrollment is not wired")
	}
	is, err := svc.IssueFor(context.Background(), enroll.IssueRequest{Name: "nat-box"})
	if err != nil {
		t.Fatal(err)
	}
	token, cmdline := is.Token, is.Cmdline
	if !strings.Contains(cmdline, e.srv.Authority().CAFingerprint()) || !strings.Contains(cmdline, "https://"+e.gwAddr) ||
		!strings.Contains(cmdline, "/enroll/package/tgproxy_1.2.3_amd64.deb") {
		t.Fatalf("cmdline: %s", cmdline)
	}
	e.checkPackageDownload(token)

	// конфиг агента как после установки пакета: пути к tls заданы, файлов ещё нет
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yaml")
	body := "mode: dial\ntls:\n  cert_file: " + filepath.Join(dir, "agent.crt") + "\n  key_file: " + filepath.Join(dir, "agent.key") +
		"\n  ca_file: " + filepath.Join(dir, "ca.crt") + "\ndata_dir: " + dir + "\nlisten:\n  metrics: \"127.0.0.1:19443\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		Server: "https://" + e.gwAddr, Token: token, CAFingerprint: e.srv.Authority().CAFingerprint(), ConfigPath: cfgPath,
	})
	if err != nil {
		t.Fatalf("enroll: %v\nlogs:\n%s", err, e.logs.String())
	}
	if res.AgentID != "nat-box" {
		t.Fatalf("agent id %q", res.AgentID)
	}
	// токен одноразовый
	if _, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		Server: "https://" + e.gwAddr, Token: token, CAFingerprint: e.srv.Authority().CAFingerprint(), ConfigPath: cfgPath,
	}); err == nil {
		t.Fatal("token reuse must be rejected")
	}

	acfg, err := config.LoadAgent(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if acfg.Mode != config.AgentModeReverse {
		t.Fatalf("mode after enroll: %s", acfg.Mode)
	}
	acfg.Listen.Metrics = "127.0.0.1:0"
	if err := acfg.OverrideTelegramAPIURL(e.tg.URL); err != nil {
		t.Fatal(err)
	}
	e.startReverse("nat-box", acfg)

	e.waitFor(10*time.Second, "enrolled agent in balancer", func() bool { return e.up("nat-box") })
	if code, err := e.getMe(); err != nil || code != http.StatusOK {
		t.Fatalf("getMe through enrolled agent: %d %v", code, err)
	}
	if st, _ := e.srv.reg.Get("nat-box"); st.Agent.Mode != store.ModeReverse {
		t.Fatalf("registry mode: %s", st.Agent.Mode)
	}

	body2 := e.metricsBody()
	if want := `tgp_enroll_attempts_total{result="ok"} 1`; !strings.Contains(body2, want) {
		t.Errorf("missing %q in:\n%s", want, grepLines(body2, "enroll"))
	}
	if want := `tgp_enroll_attempts_total{result="denied"} 1`; !strings.Contains(body2, want) {
		t.Errorf("missing %q in:\n%s", want, grepLines(body2, "enroll"))
	}
	items, err := e.srv.st.Outbox().Recent(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var alerted bool
	for _, it := range items {
		alerted = alerted || (it.Type == "agent_enrolled" && it.AgentID == "nat-box")
	}
	if !alerted {
		t.Errorf("alert agent_enrolled not queued: %+v", items)
	}
}

func TestPKIRevokedAgentRejected(t *testing.T) {
	e := newPKIEnv(t)

	// reverse: отозванный сертификат закрывается на gateway до первого запроса
	revFiles := e.issue("rev-bad")
	e.addAgent("rev-bad", store.ModeReverse, "")
	if _, err := e.srv.Denylist().RevokeAgent(context.Background(), "rev-bad", "test"); err != nil {
		t.Fatal(err)
	}
	e.startReverse("rev-bad", e.agentConfig(revFiles, config.AgentModeReverse))
	e.waitFor(10*time.Second, "gateway rejection", func() bool {
		return strings.Contains(e.logs.String(), "gateway: peer rejected") && strings.Contains(e.logs.String(), "revoked")
	})
	time.Sleep(300 * time.Millisecond)
	if n := e.srv.pki.pool.Conns("rev-bad"); n != 0 {
		t.Fatalf("revoked agent attached %d reverse conns", n)
	}
	if e.up("rev-bad") {
		t.Fatal("revoked reverse agent is up")
	}

	// dial: тот же отозванный сертификат у агента с листенером отвергается транспортом сервера
	dialFiles := e.issue("dial-bad")
	ln := listen(t)
	e.addAgent("dial-bad", store.ModeDial, "https://"+ln.Addr().String())
	if _, err := e.srv.Denylist().RevokeAgent(context.Background(), "dial-bad", "test"); err != nil {
		t.Fatal(err)
	}
	acfg := e.agentConfig(dialFiles, config.AgentModeDial)
	ctx, cancel := context.WithCancel(context.Background())
	a := &e2eAgent{id: "dial-bad", cancel: cancel, done: make(chan struct{})}
	e.agents = append(e.agents, a)
	go func() {
		defer close(a.done)
		_ = RunAgent(ctx, acfg, e.srv.logger, AgentOptions{Agent: []agent.Option{agent.WithUpstreamRootCAs(e.upPool)}, Listener: ln})
	}()
	ref, _ := e.srv.reg.Ref("dial-bad")
	var lastErr error
	e.waitFor(10*time.Second, "dial transport rejection", func() bool {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_, lastErr = e.srv.tr.Status(sctx, ref)
		return lastErr != nil && strings.Contains(lastErr.Error(), "revoked")
	})
	time.Sleep(400 * time.Millisecond)
	if e.up("dial-bad") {
		t.Fatalf("revoked dial agent is up (last error: %v)", lastErr)
	}
}

func TestPKIRotateNowKeepsLiveAgent(t *testing.T) {
	e := newPKIEnv(t)
	files := e.issue("nat-rot")
	e.addAgent("nat-rot", store.ModeReverse, "")
	e.startReverse("nat-rot", e.agentConfig(files, config.AgentModeReverse))
	e.waitFor(10*time.Second, "reverse agent up", func() bool { return e.up("nat-rot") && e.srv.pki.pool.Conns("nat-rot") == 2 })
	oldSerial := certSerialFromFile(t, files.CertFile)

	var failures, total atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				total.Add(1)
				if code, err := e.getMe(); err != nil || code != http.StatusOK {
					failures.Add(1)
				}
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	err := e.srv.Rotator().RotateNow(context.Background(), "nat-rot")
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("RotateNow: %v\nlogs:\n%s", err, e.logs.String())
	}
	if total.Load() == 0 || failures.Load() != 0 {
		t.Fatalf("requests during rotation: %d total, %d failed", total.Load(), failures.Load())
	}
	if n := e.srv.pki.pool.Conns("nat-rot"); n != 2 {
		t.Fatalf("reverse conns after rotation: %d", n)
	}
	newSerial := certSerialFromFile(t, files.CertFile)
	if newSerial == oldSerial {
		t.Fatal("agent certificate was not replaced")
	}
	recs, err := e.srv.st.Certs().ListByAgent(context.Background(), "nat-rot")
	if err != nil || len(recs) != 2 {
		t.Fatalf("issued certs: %d %v", len(recs), err)
	}
	// старый серийник отзывается только после грейса, новый не отозван
	if d, _ := e.srv.st.Certs().IsDenied(context.Background(), newSerial); d {
		t.Fatal("new certificate is denied")
	}
	// после ротации новое reverse-соединение агента проходит gateway с новым сертификатом
	if code, err := e.getMe(); err != nil || code != http.StatusOK {
		t.Fatalf("getMe after rotation: %d %v", code, err)
	}
}

// Экран «Агенты»: REST под сессией показывает режимы, вес меняется через API, both сохраняется как есть.
func TestPKIAgentsAPIModesAndWeight(t *testing.T) {
	e := newPKIEnv(t)
	e.addAgent("nat1", store.ModeReverse, "")
	e.addAgent("b1", store.ModeBoth, "https://127.0.0.1:1")
	e.addAgent("d1", store.ModeDial, "https://127.0.0.1:2")
	if cfg := e.srv.Registry(); cfg == nil {
		t.Fatal("no registry")
	}
	adminURL := e.adminURL
	c := newAdminClient(t, adminURL)
	c.login()
	resp, body := c.do("GET", "/api/v1/agents", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	for _, want := range []string{`"id":"nat1"`, `"mode":"reverse"`, `"mode":"both"`, `"mode":"dial"`, `"link":"both"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
	resp, body = c.do("POST", "/api/v1/agents/d1/weight", map[string]string{"Content-Type": "application/json"}, strings.NewReader(`{"weight":7}`))
	if resp.StatusCode != 200 || !strings.Contains(body, `"weight":7`) {
		t.Fatalf("weight: %d %s", resp.StatusCode, body)
	}
	if st, _ := e.srv.reg.Get("d1"); st.Agent.Weight != 7 {
		t.Fatalf("registry weight %d", st.Agent.Weight)
	}
	// SSH-мастер и enrollment подключены в PKI-режиме
	if resp, _ = c.do("GET", "/api/v1/enrollments", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("enrollments: %d", resp.StatusCode)
	}
}

// packageGet — GET /enroll/package/<deb> на gateway с заданным Authorization (CA сервера как корень доверия).
func (e *pkiEnv) packageGet(auth string) (int, []byte) {
	e.t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(e.srv.Authority().CertPEM()) {
		e.t.Fatal("bad CA pem")
	}
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
	}}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+e.gwAddr+"/enroll/package/tgproxy_1.2.3_amd64.deb", http.NoBody)
	if err != nil {
		e.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := cl.Do(req)
	if err != nil {
		e.t.Fatalf("download: %v\nlogs:\n%s", err, e.logs.String())
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// checkPackageDownload скачивает пакет с gateway так же, как curl --cacert из команды установки:
// доверие только CA сервера, проверка имени хоста (IP gateway в SAN), TLS 1.3, токен в Authorization.
// Токен при этом не расходуется.
func (e *pkiEnv) checkPackageDownload(token string) {
	e.t.Helper()
	get := e.packageGet
	if code, b := get("Bearer " + token); code != http.StatusOK || string(b) != "DEB-1.2.3" {
		e.t.Fatalf("download: %d %q", code, b)
	}
	if code, _ := get("Bearer " + strings.Repeat("A", 43)); code != http.StatusUnauthorized {
		e.t.Fatalf("bad token: %d", code)
	}
	if code, _ := get(""); code != http.StatusUnauthorized {
		e.t.Fatalf("no token: %d", code)
	}
	if strings.Contains(e.logs.String(), token) {
		e.t.Fatal("token leaked into server logs")
	}
}

// Отзыв токена через API админки: после него и /enroll, и /enroll/package/ отвечают 401,
// токен в списке не показывается; уже скачанный пакет к этому не относится.
func TestPKIEnrollmentRevokeViaAPI(t *testing.T) {
	e := newPKIEnvWith(t, pkiOpts{pkgVersion: "1.2.3"})
	is, err := e.srv.Enrollment().IssueFor(context.Background(), enroll.IssueRequest{Name: "leaked"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := e.packageGet("Bearer " + is.Token); code != http.StatusOK {
		t.Fatalf("package before revoke: %d", code)
	}
	c := newAdminClient(t, e.adminURL)
	if resp, _ := c.do("DELETE", "/api/v1/enrollments/"+is.ID+"?confirm=yes", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoke without session: %d", resp.StatusCode)
	}
	c.login()
	resp, body := c.do("GET", "/api/v1/enrollments", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, is.ID) || strings.Contains(body, is.Token) {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	if resp, _ = c.do("DELETE", "/api/v1/enrollments/"+is.ID+"?confirm=yes", map[string]string{"Sec-Fetch-Site": "cross-site"}, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site revoke: %d", resp.StatusCode)
	}
	if resp, _ = c.do("DELETE", "/api/v1/enrollments/"+is.ID+"?confirm=yes", nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if code, _ := e.packageGet("Bearer " + is.Token); code != http.StatusUnauthorized {
		t.Fatalf("package after revoke: %d", code)
	}
	_, err = agent.Enroll(context.Background(), agent.EnrollOptions{
		Server: "https://" + e.gwAddr, Token: is.Token, CAFingerprint: e.srv.Authority().CAFingerprint(),
		ConfigPath: filepath.Join(t.TempDir(), "agent.yaml"),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid, expired or already used") {
		t.Fatalf("enroll with revoked token: %v", err)
	}
	if resp, body = c.do("GET", "/api/v1/enrollments", nil, nil); strings.Contains(body, is.ID) {
		t.Fatalf("revoked token still listed: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(e.logs.String(), is.Token) {
		t.Fatal("token leaked into server logs")
	}
}

// Перевыпуск токена для существующего агента: старый сертификат отзывается, живое соединение
// со старым ключом рвётся, агент (id, вес) сохраняется и работает с новым ключом.
func TestPKIReenrollExistingAgentEndToEnd(t *testing.T) {
	e := newPKIEnv(t)
	files := e.issue("keep-me")
	e.addAgent("keep-me", store.ModeReverse, "")
	oldSerial := certSerialFromFile(t, files.CertFile)
	e.startReverse("keep-me", e.agentConfig(files, config.AgentModeReverse))
	e.waitFor(10*time.Second, "agent up", func() bool { return e.up("keep-me") })
	if e.srv.pki.pool.Conns("keep-me") == 0 {
		t.Fatal("нет живого соединения до перевыпуска")
	}

	is, err := e.srv.Enrollment().IssueFor(context.Background(), enroll.IssueRequest{AgentID: "keep-me", InstalledOnly: true, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yaml")
	body := "mode: dial\ntls:\n  cert_file: " + filepath.Join(dir, "agent.crt") + "\n  key_file: " + filepath.Join(dir, "agent.key") +
		"\n  ca_file: " + filepath.Join(dir, "ca.crt") + "\ndata_dir: " + dir + "\nlisten:\n  metrics: \"127.0.0.1:19444\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		Server: "https://" + e.gwAddr, Token: is.Token, CAFingerprint: e.srv.Authority().CAFingerprint(), ConfigPath: cfgPath,
	})
	if err != nil {
		t.Fatalf("reenroll: %v\nlogs:\n%s", err, e.logs.String())
	}
	if res.AgentID != "keep-me" {
		t.Fatalf("agent id %q", res.AgentID)
	}
	if !e.srv.Denylist().IsDenied(oldSerial) {
		t.Fatal("старый сертификат не отозван")
	}
	if all, _ := e.srv.st.Agents().List(context.Background()); len(all) != 1 || all[0].Weight != 1 {
		t.Fatalf("агенты: %+v", all)
	}
	// старый процесс агента переподключиться не может: его сертификат отозван
	e.waitFor(10*time.Second, "old connection dropped", func() bool { return e.srv.pki.pool.Conns("keep-me") == 0 })
	time.Sleep(300 * time.Millisecond)
	if n := e.srv.pki.pool.Conns("keep-me"); n != 0 {
		t.Fatalf("старый ключ переподключился: %d", n)
	}

	acfg, err := config.LoadAgent(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	acfg.Listen.Metrics = "127.0.0.1:0"
	if err := acfg.OverrideTelegramAPIURL(e.tg.URL); err != nil {
		t.Fatal(err)
	}
	e.startReverse("keep-me", acfg)
	e.waitFor(10*time.Second, "agent up with new key", func() bool { return e.srv.pki.pool.Conns("keep-me") > 0 && e.up("keep-me") })
	if code, err := e.getMe(); err != nil || code != http.StatusOK {
		t.Fatalf("getMe через перевыпущенного агента: %d %v", code, err)
	}
}
