package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/release"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type e2eSigner struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func newE2ESigner(t *testing.T) e2eSigner {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return e2eSigner{pub, priv}
}

// publishRelease кладёт подписанный релиз в кэш загрузок сервера (updates/downloads/<v>).
func (e *pkiEnv) publishRelease(version string, s e2eSigner) {
	e.t.Helper()
	dir := release.VersionDir(filepath.Join(e.dir, "updates", "downloads"), version)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		e.t.Fatal(err)
	}
	deb := []byte("DEB-" + version)
	sum := sha256.Sum256(deb)
	debName := release.DebName(version, runtime.GOARCH)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + debName + "\n")
	r := minisign.NewReader(bytes.NewReader(sums))
	_, _ = io.Copy(io.Discard, r)
	sig := r.SignWithComments(s.priv, "timestamp:1 file:checksums.txt", "untrusted")
	for name, b := range map[string][]byte{debName: deb, release.ChecksumsName: sums, release.SigName: sig} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil { //nolint:gosec // кэш загрузок читается gateway
			e.t.Fatal(err)
		}
	}
}

// updAgent — агент с фейковым root-apply: подхватывает updates/staged/request, «ставит» версию и пишет result.json.
type updAgent struct {
	id      string
	dataDir string
	ver     atomic.Value
	mu      sync.Mutex
	reqs    []string // содержимое увиденных request
}

func (a *updAgent) version() string { return a.ver.Load().(string) }

func (a *updAgent) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.reqs...)
}

// fakeApply — замена `tgproxy update apply`: request → result.json(ok) + смена версии + удаление request.
func (a *updAgent) fakeApply(ctx context.Context) {
	req := filepath.Join(a.dataDir, "updates", "staged", "request")
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
		b, err := os.ReadFile(req)
		if err != nil {
			continue
		}
		var r struct{ Version, Component string }
		if json.Unmarshal(b, &r) != nil || r.Component != "agent" {
			continue
		}
		a.mu.Lock()
		a.reqs = append(a.reqs, string(b))
		a.mu.Unlock()
		res := `{"version":"` + r.Version + `","ok":true,"rolled_back":false,"error":"","at":"2026-01-01T00:00:00Z"}`
		_ = os.WriteFile(filepath.Join(a.dataDir, "updates", "result.json"), []byte(res), 0o600)
		a.ver.Store(r.Version)
		_ = os.Remove(req)
	}
}

// startUpdatable запускает агента (dial — со своим листенером, reverse — дозвон до gateway) с вшитым в тест ключом релизов.
func (e *pkiEnv) startUpdatable(id string, mode config.AgentMode, trusted e2eSigner, version string) *updAgent {
	e.t.Helper()
	files := e.issue(id)
	acfg := e.agentConfig(files, mode)
	ua := &updAgent{id: id, dataDir: acfg.DataDir}
	ua.ver.Store(version)
	opts := []agent.Option{
		agent.WithUpstreamRootCAs(e.upPool),
		agent.WithVersionFunc(ua.version),
		agent.WithUpdateConfig(agent.UpdateConfig{Verifier: &verify.Verifier{Keys: []verify.PublicKey{trusted.pub}, MinVersion: version}}),
		agent.WithConnectorOptions(agent.WithBackoff(50*time.Millisecond, 200*time.Millisecond)),
	}
	ao := AgentOptions{Agent: opts}
	if mode == config.AgentModeDial {
		ln := listen(e.t)
		ao.Listener = ln
		e.addAgent(id, store.ModeDial, "https://"+ln.Addr().String())
	} else {
		e.addAgent(id, store.ModeReverse, "")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &e2eAgent{id: id, cancel: cancel, done: make(chan struct{})}
	e.agents = append(e.agents, a)
	go ua.fakeApply(ctx)
	go func() {
		defer close(a.done)
		_ = RunAgent(ctx, acfg, e.srv.logger, ao)
	}()
	return ua
}

type rolloutView struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	State    string `json:"state"`
	Active   bool   `json:"active"`
	Error    string `json:"error"`
	Progress struct {
		Done, Skipped, Failed, Pending int
	} `json:"progress"`
	Steps []struct {
		AgentID     string `json:"agent_id"`
		Phase       string `json:"phase"`
		State       string `json:"state"`
		FromVersion string `json:"from_version"`
		Error       string `json:"error"`
	} `json:"steps"`
}

func (e *pkiEnv) rolloutAPI(c *adminClient, method, path, body string) (int, rolloutView) {
	e.t.Helper()
	var rd io.Reader
	hdr := map[string]string{}
	if body != "" {
		rd, hdr["Content-Type"] = strings.NewReader(body), "application/json"
	}
	resp, out := c.do(method, path, hdr, rd)
	var v rolloutView
	_ = json.Unmarshal([]byte(out), &v)
	return resp.StatusCode, v
}

func (e *pkiEnv) waitRolloutEnd(c *adminClient) rolloutView {
	e.t.Helper()
	var v rolloutView
	e.waitFor(90*time.Second, "rollout finished", func() bool {
		code, cur := e.rolloutAPI(c, "GET", "/api/v1/rollouts/current", "")
		v = cur
		return code == http.StatusOK && !cur.Active
	})
	return v
}

func TestRolloutE2EDialAndReverseAgents(t *testing.T) {
	e := newPKIEnv(t)
	release1 := newE2ESigner(t)
	e.publishRelease("1.1.0", release1)
	dial := e.startUpdatable("dial1", config.AgentModeDial, release1, "1.0.0")
	rev := e.startUpdatable("rev1", config.AgentModeReverse, release1, "1.0.0")
	e.waitFor(15*time.Second, "agents up", func() bool { return e.up("dial1") && e.up("rev1") })
	e.waitFor(10*time.Second, "agent versions polled", func() bool {
		for _, id := range []string{"dial1", "rev1"} {
			if st, _ := e.srv.reg.Get(id); st.LastStatus == nil || st.LastStatus.Version != "1.0.0" {
				return false
			}
		}
		return true
	})
	c := newAdminClient(t, e.adminURL)
	c.login()

	if code, _ := e.rolloutAPI(c, "GET", "/api/v1/rollouts/current", ""); code != http.StatusNotFound {
		t.Fatalf("current до первой раскатки: %d", code)
	}
	code, v := e.rolloutAPI(c, "POST", "/api/v1/rollouts", `{"version":"1.1.0","batch_size":1}`)
	if code != http.StatusAccepted || !v.Active || len(v.Steps) != 2 {
		t.Fatalf("start: %d %+v\nlogs:\n%s", code, v, e.logs.String())
	}
	if code, _ := e.rolloutAPI(c, "POST", "/api/v1/rollouts", `{"version":"1.1.0"}`); code != http.StatusConflict {
		t.Errorf("вторая раскатка параллельно: %d, want 409", code)
	}
	v = e.waitRolloutEnd(c)
	if v.State != "done" || v.Progress.Done != 2 || v.Progress.Failed != 0 {
		t.Fatalf("итог: %+v\nlogs:\n%s", v, e.logs.String())
	}
	phases := map[string]string{}
	for _, s := range v.Steps {
		phases[s.AgentID] = s.Phase
		if s.State != "done" || s.FromVersion != "1.0.0" {
			t.Errorf("шаг %+v", s)
		}
	}
	if phases["dial1"] != "canary" || phases["rev1"] != "batch" {
		t.Errorf("фазы: %v", phases)
	}
	for _, ua := range []*updAgent{dial, rev} {
		got := ua.seen()
		if len(got) != 1 || got[0] != `{"version":"1.1.0","component":"agent"}` || ua.version() != "1.1.0" {
			t.Errorf("%s: requests=%v version=%s", ua.id, got, ua.version())
		}
		for _, n := range []string{release.DebName("1.1.0", runtime.GOARCH), release.ChecksumsName, release.SigName} {
			if _, err := os.Stat(filepath.Join(ua.dataDir, "updates", "downloads", "1.1.0", n)); err != nil {
				t.Errorf("%s: %v", ua.id, err)
			}
		}
		if st, ok := e.srv.reg.Get(ua.id); !ok || st.Draining {
			t.Errorf("%s остался в drain", ua.id)
		}
	}
	if code, err := e.getMe(); err != nil || code != http.StatusOK {
		t.Errorf("getMe после раскатки: %d %v", code, err)
	}

	// Повторный запуск идемпотентен: агенты на версии пропускаются, команд нет.
	code, v = e.rolloutAPI(c, "POST", "/api/v1/rollouts", `{"version":"1.1.0"}`)
	if code != http.StatusAccepted || v.State != "done" || v.Progress.Skipped != 2 || v.Progress.Done != 0 {
		t.Fatalf("повтор: %d %+v", code, v)
	}
	if len(dial.seen())+len(rev.seen()) != 2 {
		t.Errorf("повторная раскатка создала request")
	}
}

func TestRolloutE2EForeignSignatureStopsAtCanary(t *testing.T) {
	e := newPKIEnv(t)
	trusted, attacker := newE2ESigner(t), newE2ESigner(t)
	e.publishRelease("1.1.0", attacker) // сервер раздаёт релиз с чужой подписью
	a1 := e.startUpdatable("dial1", config.AgentModeDial, trusted, "1.0.0")
	a2 := e.startUpdatable("dial2", config.AgentModeDial, trusted, "1.0.0")
	e.waitFor(15*time.Second, "agents up", func() bool { return e.up("dial1") && e.up("dial2") })
	c := newAdminClient(t, e.adminURL)
	c.login()

	code, v := e.rolloutAPI(c, "POST", "/api/v1/rollouts", `{"version":"1.1.0","batch_size":2}`)
	if code != http.StatusAccepted {
		t.Fatalf("start: %d", code)
	}
	v = e.waitRolloutEnd(c)
	if v.State != "failed" || !strings.Contains(v.Error, "422") {
		t.Fatalf("итог: %+v", v)
	}
	states := map[string]string{}
	for _, s := range v.Steps {
		states[s.AgentID] = s.State
	}
	if states["dial1"] != "failed" || states["dial2"] != "pending" {
		t.Fatalf("шаги: %v", states)
	}
	for _, ua := range []*updAgent{a1, a2} {
		if len(ua.seen()) != 0 || ua.version() != "1.0.0" {
			t.Errorf("%s: staged=%v version=%s", ua.id, ua.seen(), ua.version())
		}
		if _, err := os.Stat(filepath.Join(ua.dataDir, "updates", "staged")); !os.IsNotExist(err) {
			t.Errorf("%s: staged создан для чужой подписи", ua.id)
		}
		if st, _ := e.srv.reg.Get(ua.id); st.Draining {
			t.Errorf("%s остался в drain", ua.id)
		}
	}
	e.waitFor(5*time.Second, "rollout_failed alert queued", func() bool {
		items, _ := e.srv.st.Outbox().Recent(context.Background(), 20)
		for _, it := range items {
			if it.Type == "rollout_failed" && it.AgentID == "dial1" {
				return true
			}
		}
		return false
	})

	// Остановка при отсутствии активной раскатки — 409; ручного отката нет (эндпоинта не существует).
	if code, _ := e.rolloutAPI(c, "POST", "/api/v1/rollouts/current/stop", ""); code != http.StatusConflict {
		t.Errorf("stop без раскатки: %d", code)
	}
	if code, _ := e.rolloutAPI(c, "POST", "/api/v1/agents/dial1/rollback", "{}"); code != http.StatusNotFound {
		t.Errorf("rollback: %d", code)
	}
}

func TestRolloutE2EPackagesNeedAgentCertificate(t *testing.T) {
	e := newPKIEnv(t)
	s := newE2ESigner(t)
	e.publishRelease("1.1.0", s)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: insecureTLS()}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+e.gwAddr+"/_agent_gw/packages/1.1.0/"+release.ChecksumsName, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("без клиентского сертификата: %d, want 401", resp.StatusCode)
	}
}

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} //nolint:gosec // тест: проверяем отказ без клиентского сертификата
}
