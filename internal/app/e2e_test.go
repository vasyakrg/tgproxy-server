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
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
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
	rules []config.AccessRule
}

type e2e struct {
	t         *testing.T
	logs      *syncBuf
	cfg       *config.ServerConfig
	tg        *httptest.Server
	tgHandler http.HandlerFunc
	srv       *Server
	dial      *transport.Dial
	proxyURL  string
	adminURL  string
	agentAddr string
	stopAgent context.CancelFunc
	agentDone chan struct{}
	srvDone   chan error
	cancelSrv context.CancelFunc
	gotSHA    chan [32]byte
	reloadCfg func() (*config.ServerConfig, error)
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

func newE2E(t *testing.T, o e2eOpts) *e2e {
	t.Helper()
	e := &e2e{t: t, logs: &syncBuf{}, gotSHA: make(chan [32]byte, 4)}
	logger, level, err := NewLogger(config.LoggingConfig{Level: "debug", Format: "text"}, e.logs)
	if err != nil {
		t.Fatal(err)
	}

	// фейковый Telegram
	e.tg = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.tgHandler != nil {
			e.tgHandler(w, r)
			return
		}
		defaultTG(e, w, r)
	}))
	t.Cleanup(e.tg.Close)

	// PKI
	dir := t.TempDir()
	if err := pki.DevInit(dir, []string{"local"}); err != nil {
		t.Fatal(err)
	}

	// агент
	acfg := config.DefaultAgent()
	acfg.TLS = config.TLSFiles{
		CertFile: filepath.Join(dir, pki.FileAgentCert),
		KeyFile:  filepath.Join(dir, pki.FileAgentKey),
		CAFile:   filepath.Join(dir, pki.FileCACert),
	}
	if err := acfg.OverrideTelegramAPIURL(e.tg.URL); err != nil {
		t.Fatal(err)
	}
	upPool := x509.NewCertPool()
	upPool.AddCert(e.tg.Certificate())
	aln := listen(t)
	e.agentAddr = aln.Addr().String()
	actx, acancel := context.WithCancel(context.Background())
	e.stopAgent = acancel
	e.agentDone = make(chan struct{})
	go func() {
		defer close(e.agentDone)
		_ = RunAgent(actx, acfg, logger, AgentOptions{Agent: []agent.Option{agent.WithUpstreamRootCAs(upPool)}, Listener: aln})
	}()
	t.Cleanup(func() {
		acancel()
		select {
		case <-e.agentDone:
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop")
		}
	})

	// сервер
	scfg := config.DefaultServer()
	scfg.Agents = []config.AgentEndpoint{{ID: "local", URL: "https://" + e.agentAddr, Mode: config.AgentModeDial, Weight: 1}}
	scfg.AgentTLS = config.TLSFiles{
		CertFile: filepath.Join(dir, pki.FileServerCert),
		KeyFile:  filepath.Join(dir, pki.FileServerKey),
		CAFile:   filepath.Join(dir, pki.FileCACert),
	}
	scfg.AccessRules = o.rules
	if scfg.AccessRules == nil {
		scfg.AccessRules = []config.AccessRule{localRule("127.0.0.0/8"), keyRule()}
	}
	e.cfg = scfg
	e.reloadCfg = func() (*config.ServerConfig, error) { return scfg, nil }

	pln, adln := listen(t), listen(t)
	e.proxyURL = "http://" + pln.Addr().String()
	e.adminURL = "http://" + adln.Addr().String()
	srv, err := NewServer(scfg, logger, ServerOptions{
		Level:        level,
		ReloadConfig: func() (*config.ServerConfig, error) { return e.reloadCfg() },
	})
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
	return e
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
	e.stopAgent()
	select {
	case <-e.agentDone:
	case <-time.After(15 * time.Second):
		t.Fatal("agent did not stop")
	}
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
	// readyz при остановленном агенте — 503
	r2, _ := e.adminGet("/readyz")
	if r2.StatusCode != 503 {
		t.Fatalf("readyz: %d", r2.StatusCode)
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

func TestE2EReloadChangesAccess(t *testing.T) {
	e := newE2E(t, e2eOpts{rules: []config.AccessRule{localRule("10.0.0.0/8")}})
	if resp, _ := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("before: %d", resp.StatusCode)
	}
	next := *e.cfg
	next.AccessRules = []config.AccessRule{localRule("127.0.0.0/8")}
	next.Logging.Level = "warn"
	e.reloadCfg = func() (*config.ServerConfig, error) { return &next, nil }
	if err := e.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("after: %d", resp.StatusCode)
	}

	// невалидный конфиг: остаётся прежний
	bad := *e.cfg
	bad.AccessRules = []config.AccessRule{{Name: "open"}} // без сетей и ключа
	e.reloadCfg = func() (*config.ServerConfig, error) { return &bad, nil }
	if err := e.srv.Reload(); err == nil {
		t.Fatal("reload of bad config must fail")
	}
	if resp, _ := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("after bad reload: %d", resp.StatusCode)
	}
	e.reloadCfg = func() (*config.ServerConfig, error) { return nil, fmt.Errorf("boom") }
	if err := e.srv.Reload(); err == nil {
		t.Fatal("loader error must propagate")
	}
}

func TestE2ENoTokenInLogs(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.do("GET", "/bot"+testToken+"/getMe", nil, nil)
	e.do("GET", "/k/"+testKey+"/bot"+testToken+"/getMe", nil, nil)
	e.stopAgent()
	<-e.agentDone
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

func TestIngressTLSACMENotImplemented(t *testing.T) {
	c := config.DefaultServer()
	c.TLS.Mode = config.TLSModeACME
	if _, err := ingressTLS(c); err == nil || !strings.Contains(err.Error(), "M4-T9") {
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
