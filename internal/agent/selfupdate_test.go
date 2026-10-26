package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/release"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

type signer struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{pub, priv}
}

// sign имитирует `minisign -S` (prehashed ED).
func (s signer) sign(msg []byte) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	_, _ = io.Copy(io.Discard, r)
	return r.SignWithComments(s.priv, "timestamp:1 file:checksums.txt", "untrusted")
}

// fakeGateway — mTLS-сервер с релизом в памяти (как /_agent_gw/packages/ без проверки идентичности).
type fakeGateway struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte // "<v>/<name>"
	calls int
	peers int // запросов с клиентским сертификатом
}

func (e *env) newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{files: map[string][]byte{}}
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.calls++
		if len(r.TLS.PeerCertificates) > 0 {
			g.peers++
		}
		b, ok := g.files[strings.TrimPrefix(r.URL.Path, "/_agent_gw/packages/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	g.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{e.srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    e.pool,
		MinVersion:   tls.VersionTLS13,
	}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

// publish кладёт релиз version, подписанный s; mutate позволяет испортить файлы.
func (g *fakeGateway) publish(version string, s signer, mutate func(deb, sums []byte) ([]byte, []byte)) {
	deb := []byte("DEB-" + version)
	sum := sha256.Sum256(deb)
	debName := release.DebName(version, runtime.GOARCH)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + debName + "\n")
	sig := s.sign(sums)
	if mutate != nil {
		deb, sums = mutate(deb, sums)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.files[version+"/"+debName] = deb
	g.files[version+"/"+release.ChecksumsName] = sums
	g.files[version+"/"+release.SigName] = sig
}

func (g *fakeGateway) stats() (calls, peers int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls, g.peers
}

func startUpdateAgent(t *testing.T, cfg UpdateConfig) (*env, *fakeGateway) {
	t.Helper()
	e, upPool := newEnvNoAgent(t, http.NotFoundHandler())
	e.cfg.DataDir = t.TempDir()
	e.startAgent(t, WithUpstreamRootCAs(upPool), WithUpdateConfig(cfg), WithVersionFunc(func() string { return "1.0.0" }))
	return e, e.newFakeGateway(t)
}

func postUpdate(t *testing.T, e *env, body string) (int, map[string]any) {
	t.Helper()
	resp := e.do(t, http.MethodPost, "/_agent/update", nil, strings.NewReader(body)) //nolint:bodyclose // закрывается в e.do (t.Cleanup)
	m := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func updateBody(version, gw string) string {
	b, _ := json.Marshal(map[string]string{"version": version, "gateway_url": gw})
	return string(b)
}

func trusted(s signer, floor string) UpdateConfig {
	return UpdateConfig{Verifier: &verify.Verifier{Keys: []verify.PublicKey{s.pub}, MinVersion: floor}}
}

func stagedDir(e *env) string { return filepath.Join(e.cfg.DataDir, "updates", "staged") }

func TestUpdateStagesVerifiedRelease(t *testing.T) {
	s := newSigner(t)
	e, gw := startUpdateAgent(t, trusted(s, "1.0.0"))
	gw.publish("1.1.0", s, nil)

	code, body := postUpdate(t, e, updateBody("1.1.0", gw.srv.URL))
	if code != http.StatusAccepted || body["state"] != UpdateStaged {
		t.Fatalf("POST = %d %v, want 202 staged", code, body)
	}
	if _, peers := gw.stats(); peers == 0 {
		t.Error("агент не предъявил клиентский сертификат gateway")
	}
	req, err := os.ReadFile(filepath.Join(stagedDir(e), "request"))
	if err != nil || string(req) != `{"version":"1.1.0","component":"agent"}` {
		t.Fatalf("request = %q, %v", req, err)
	}
	for _, n := range []string{release.DebName("1.1.0", runtime.GOARCH), release.ChecksumsName, release.SigName} {
		fi, err := os.Stat(filepath.Join(stagedDir(e), n))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("staged %s: %v %v", n, fi, err)
		}
		if _, err := os.Stat(filepath.Join(e.cfg.DataDir, "updates", "downloads", "1.1.0", n)); err != nil {
			t.Errorf("downloads/1.1.0/%s: %v", n, err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(e.cfg.DataDir, "updates", ".*")); len(m) != 0 {
		t.Errorf("остались временные каталоги: %v", m)
	}

	st := readJSON(t, e.do(t, http.MethodGet, "/_agent/update", nil, nil)) //nolint:bodyclose // закрывается в e.do (t.Cleanup)
	if st["state"] != UpdateStaged || st["version"] != "1.1.0" {
		t.Fatalf("status = %v", st)
	}
	// Повтор той же команды идемпотентен, другая версия — 409.
	if code, _ := postUpdate(t, e, updateBody("1.1.0", gw.srv.URL)); code != http.StatusAccepted {
		t.Errorf("повтор = %d, want 202", code)
	}
	gw.publish("1.2.0", s, nil)
	if code, _ := postUpdate(t, e, updateBody("1.2.0", gw.srv.URL)); code != http.StatusConflict {
		t.Errorf("вторая версия при занятой очереди = %d, want 409", code)
	}
}

func TestUpdateRejectsForeignSignature(t *testing.T) {
	trustedKey, attacker := newSigner(t), newSigner(t)
	e, gw := startUpdateAgent(t, trusted(trustedKey, "1.0.0"))
	gw.publish("1.1.0", attacker, nil) // валидный minisign, но чужой ключ

	code, body := postUpdate(t, e, updateBody("1.1.0", gw.srv.URL))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("POST = %d %v, want 422", code, body)
	}
	assertNothingStaged(t, e)
	st := readJSON(t, e.do(t, http.MethodGet, "/_agent/update", nil, nil)) //nolint:bodyclose // закрывается в e.do (t.Cleanup)
	if st["state"] != UpdateFailed || st["error"] == "" {
		t.Fatalf("status = %v", st)
	}
}

// Без UpdateConfig агент использует вшитые ключи релиза (у тестового ключа нет приватной
// части): любая подпись «от сервера» отвергается.
func TestUpdateDefaultVerifierUsesEmbeddedKeys(t *testing.T) {
	e, gw := startUpdateAgent(t, UpdateConfig{})
	gw.publish("1.1.0", newSigner(t), nil)
	if code, _ := postUpdate(t, e, updateBody("1.1.0", gw.srv.URL)); code != http.StatusUnprocessableEntity {
		t.Fatalf("POST = %d, want 422", code)
	}
	assertNothingStaged(t, e)
}

func TestUpdateRejectsDowngradeEvenWhenSigned(t *testing.T) {
	s := newSigner(t)
	e, gw := startUpdateAgent(t, trusted(s, "1.0.0"))
	gw.publish("0.9.0", s, nil) // корректно подписана, но ниже установленной

	code, body := postUpdate(t, e, updateBody("0.9.0", gw.srv.URL))
	if code != http.StatusUnprocessableEntity || !strings.Contains(body["error"].(string), "min_version") {
		t.Fatalf("POST = %d %v, want 422 min_version", code, body)
	}
	if calls, _ := gw.stats(); calls != 0 {
		t.Errorf("пакет скачивался (%d запросов) несмотря на понижение версии", calls)
	}
	assertNothingStaged(t, e)
}

func TestUpdateRejectsTamperedDeb(t *testing.T) {
	s := newSigner(t)
	e, gw := startUpdateAgent(t, trusted(s, "1.0.0"))
	gw.publish("1.1.0", s, func(_, sums []byte) ([]byte, []byte) { return []byte("EVIL"), sums })
	if code, _ := postUpdate(t, e, updateBody("1.1.0", gw.srv.URL)); code != http.StatusUnprocessableEntity {
		t.Fatalf("POST = %d, want 422", code)
	}
	assertNothingStaged(t, e)
}

func TestUpdateBadInput(t *testing.T) {
	s := newSigner(t)
	e, gw := startUpdateAgent(t, trusted(s, "1.0.0"))
	for name, body := range map[string]string{
		"не json":         "{",
		"лишнее поле":     `{"version":"1.1.0","gateway_url":"` + gw.srv.URL + `","deb":"x"}`,
		"версия":          updateBody("../../etc", gw.srv.URL),
		"http gateway":    updateBody("1.1.0", "http://127.0.0.1:1"),
		"gateway с путём": updateBody("1.1.0", gw.srv.URL+"/x"),
		"пустой gateway":  updateBody("1.1.0", ""),
	} {
		if code, _ := postUpdate(t, e, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	// Та же версия, что уже установлена.
	if code, _ := postUpdate(t, e, updateBody("1.0.0", gw.srv.URL)); code != http.StatusConflict {
		t.Errorf("текущая версия: %d, want 409", code)
	}
	// Gateway недоступен / нет файла → 502, ничего не staged.
	if code, _ := postUpdate(t, e, updateBody("1.1.0", gw.srv.URL)); code != http.StatusBadGateway {
		t.Errorf("нет релиза на gateway: %d, want 502", code)
	}
	assertNothingStaged(t, e)
}

func TestUpdateStatusReportsApplyResult(t *testing.T) {
	s := newSigner(t)
	e, _ := startUpdateAgent(t, trusted(s, "1.0.0"))
	st := readJSON(t, e.do(t, http.MethodGet, "/_agent/update", nil, nil)) //nolint:bodyclose // закрывается в e.do (t.Cleanup)
	if st["state"] != UpdateIdle {
		t.Fatalf("idle: %v", st)
	}
	dir := filepath.Join(e.cfg.DataDir, "updates")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	write := func(js string) {
		if err := os.WriteFile(filepath.Join(dir, "result.json"), []byte(js), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":"1.1.0","ok":true,"rolled_back":false,"error":"","at":"2026-01-01T00:00:00Z"}`)
	st = readJSON(t, e.do(t, http.MethodGet, "/_agent/update", nil, nil)) //nolint:bodyclose // закрывается в e.do (t.Cleanup)
	if st["state"] != UpdateApplied || st["version"] != "1.1.0" {
		t.Fatalf("applied: %v", st)
	}
	write(`{"version":"1.2.0","ok":false,"rolled_back":true,"error":"health","at":"2026-01-01T00:00:00Z"}`)
	st = readJSON(t, e.do(t, http.MethodGet, "/_agent/update", nil, nil)) //nolint:bodyclose // закрывается в e.do (t.Cleanup)
	if st["state"] != UpdateFailed || st["error"] != "health" {
		t.Fatalf("failed: %v", st)
	}
	res, _ := st["result"].(map[string]any)
	if res["rolled_back"] != true {
		t.Fatalf("result: %v", st)
	}
}

func assertNothingStaged(t *testing.T, e *env) {
	t.Helper()
	if _, err := os.Stat(stagedDir(e)); !os.IsNotExist(err) {
		t.Errorf("updates/staged создан для отвергнутого релиза: %v", err)
	}
	if m, _ := filepath.Glob(filepath.Join(e.cfg.DataDir, "updates", "downloads", "*")); len(m) != 0 {
		t.Errorf("отвергнутый релиз попал в кэш загрузок: %v", m)
	}
}
