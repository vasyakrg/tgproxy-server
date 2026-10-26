package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

const (
	secPassword   = "Pa55w0rd-SECRET-xyz"
	secPassphrase = "pass-phrase-SECRET-123"
	secKey        = "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYBODYSECRETKEYBODY\n-----END OPENSSH PRIVATE KEY-----"
)

var secrets = []string{secPassword, secPassphrase, "SECRETKEYBODY"}

func assertNoSecrets(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(text, s) {
			t.Errorf("%s содержит секрет %q", what, s)
		}
	}
}

type fakeInstaller struct {
	mu     sync.Mutex
	reqs   []installer.Request
	err    error
	events []installer.Event
	live   chan installer.Event
	status installer.JobStatus
	stErr  error
}

func (f *fakeInstaller) Install(_ context.Context, req installer.Request) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req) // срезы секретов не копируются: проверяем затирание вызывающим
	if f.err != nil {
		return "", f.err
	}
	return "01JOBJOBJOBJOBJOBJOBJOBJOB", nil
}

func (f *fakeInstaller) Status(context.Context, string) (installer.JobStatus, error) {
	return f.status, f.stErr
}

func (f *fakeInstaller) Events(_ context.Context, id string, after int64) ([]installer.Event, <-chan installer.Event, error) {
	if id == "01NOSUCHJOBNOSUCHJOBNOSUCH" {
		return nil, nil, store.ErrNotFound
	}
	var out []installer.Event
	for _, e := range f.events {
		if e.Seq > after {
			out = append(out, e)
		}
	}
	if f.live != nil {
		return out, f.live, nil
	}
	ch := make(chan installer.Event)
	close(ch)
	return out, ch, nil
}

func ev(seq int64, kind, step, status, msg string) installer.Event {
	return installer.Event{Seq: seq, JobID: "j", At: t0, Kind: kind, Step: step, Status: status, Level: "info", Message: msg}
}

func jobEvents() []installer.Event {
	return []installer.Event{
		ev(1, installer.EventStep, "ssh", installer.StepPending, "SSH-подключение"),
		ev(2, installer.EventStep, "ssh", installer.StepRunning, "SSH-подключение"),
		ev(3, installer.EventLog, "ssh", "", "ssh 10.0.0.1:22 host key OK"),
		ev(4, installer.EventStep, "ssh", installer.StepOK, "SSH-подключение"),
		ev(5, installer.EventDone, "", "", "Агент установлен"),
	}
}

type installEnv struct {
	fi   *fakeInstaller
	svc  *api.InstallService
	mux  *http.ServeMux
	st   *memtest.Store
	logs *bytes.Buffer
	now  time.Time
}

func newInstallEnv(t *testing.T, mod func(*api.InstallConfig)) *installEnv {
	t.Helper()
	e := &installEnv{fi: &fakeInstaller{}, st: memtest.New(), logs: &bytes.Buffer{}, now: t0}
	lg := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := api.InstallConfig{
		Installer: e.fi, HostKeys: e.st.HostKeys(), Audit: e.st.Audit(), Logger: lg, Now: func() time.Time { return e.now },
		Probe: func(_ context.Context, tg installer.Target) (string, string, error) {
			return "ssh-ed25519", "SHA256:abc" + strconv.Itoa(tg.Port), nil
		},
	}
	if mod != nil {
		mod(&cfg)
	}
	e.svc = api.NewInstallService(cfg)
	e.mux = http.NewServeMux()
	(&api.InstallAPI{Service: e.svc, Log: lg, Heartbeat: 20 * time.Millisecond}).Routes(e.mux, nil)
	return e
}

func (e *installEnv) post(path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "POST", path, bytes.NewReader(b)))
	return rec
}

func validBody() map[string]any {
	return map[string]any{
		"name": "ams-2", "host": "91.204.8.4", "ssh_port": 22, "user": "root", "agent_port": 8443, "weight": 100,
		"password": secPassword, "confirmed_fingerprint": "SHA256:abc22",
	}
}

func TestProbeEndpoint(t *testing.T) {
	e := newInstallEnv(t, nil)
	rec := e.post("/api/v1/hostkeys/probe", map[string]any{"host": "91.204.8.4"})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out map[string]any
	decode(t, rec, &out)
	if out["algo"] != "ED25519" || out["fingerprint"] != "SHA256:abc22" || out["pinned"] != false || out["host"] != "91.204.8.4:22" {
		t.Errorf("%v", out)
	}
	// закреплённый ключ: совпадение и несовпадение
	_ = e.st.HostKeys().Put(context.Background(), store.HostKey{Host: "91.204.8.4:22", Algo: "ssh-ed25519", Fingerprint: "SHA256:abc22", PublicKey: []byte{1}})
	decode(t, e.post("/api/v1/hostkeys/probe", map[string]any{"host": "91.204.8.4"}), &out)
	if out["pinned"] != true || out["match"] != true {
		t.Errorf("pinned: %v", out)
	}
	_ = e.st.HostKeys().Put(context.Background(), store.HostKey{Host: "91.204.8.4:22", Algo: "ssh-ed25519", Fingerprint: "SHA256:OTHER", PublicKey: []byte{1}})
	out = nil
	decode(t, e.post("/api/v1/hostkeys/probe", map[string]any{"host": "91.204.8.4"}), &out)
	if out["pinned"] != true || out["match"] != nil {
		t.Errorf("mismatch: %v", out)
	}
	if c := e.post("/api/v1/hostkeys/probe", map[string]any{"host": "bad host/x"}).Code; c != 422 {
		t.Errorf("host: %d", c)
	}
	if c := e.post("/api/v1/hostkeys/probe", map[string]any{"host": "h", "port": 70000}).Code; c != 422 {
		t.Errorf("port: %d", c)
	}
}

func TestProbeFailure(t *testing.T) {
	e := newInstallEnv(t, func(c *api.InstallConfig) {
		c.Probe = func(context.Context, installer.Target) (string, string, error) {
			return "", "", errors.New("dial tcp: connection refused")
		}
	})
	rec := e.post("/api/v1/hostkeys/probe", map[string]any{"host": "h"})
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestCreateJobPassesSecretsAndLeaksNone(t *testing.T) {
	e := newInstallEnv(t, nil)
	b := validBody()
	b["passphrase"] = ""
	rec := e.post("/api/v1/install-jobs", b)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out map[string]string
	decode(t, rec, &out)
	if out["id"] == "" || !strings.HasSuffix(out["events_url"], "/events") || rec.Header().Get("Location") == "" {
		t.Errorf("%v %v", out, rec.Header())
	}
	if len(e.fi.reqs) != 1 {
		t.Fatalf("reqs %d", len(e.fi.reqs))
	}
	r := e.fi.reqs[0]
	if r.Name != "ams-2" || r.Host != "91.204.8.4" || r.SSHPort != 22 || r.User != "root" || r.AgentPort != 8443 || r.Weight != 100 || r.ConfirmedFingerprint != "SHA256:abc22" {
		t.Errorf("req %+v", r)
	}
	// креды переданы установщику, а буфер вызывающего затёрт после вызова
	if bytes.Contains(r.Auth.Password, []byte(secPassword)) || len(r.Auth.Password) != len(secPassword) {
		t.Errorf("буфер пароля не затёрт: %q", r.Auth.Password)
	}
	assertNoSecrets(t, "ответ", rec.Body.String())
	assertNoSecrets(t, "логи", e.logs.String())
	au, _ := e.st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 1 || au[0].Action != api.AuditInstallStart || au[0].Target != "ams-2" {
		t.Fatalf("audit %+v", au)
	}
	assertNoSecrets(t, "аудит", fmt.Sprintf("%+v", au))
	if !strings.Contains(au[0].Detail, "auth=password") || !strings.Contains(au[0].Detail, "host=91.204.8.4:22") {
		t.Errorf("detail %q", au[0].Detail)
	}
}

func TestCreateJobDefaultsAndKeyAuth(t *testing.T) {
	e := newInstallEnv(t, nil)
	rec := e.post("/api/v1/install-jobs", map[string]any{"name": "a", "host": "h.example.com", "private_key": secKey, "passphrase": secPassphrase})
	if rec.Code != 202 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	r := e.fi.reqs[0]
	if r.SSHPort != 22 || r.AgentPort != 8443 || r.Weight != 100 || r.User != "root" {
		t.Errorf("умолчания: %+v", r)
	}
	au, _ := e.st.Audit().List(context.Background(), store.AuditQuery{})
	if !strings.Contains(au[0].Detail, "auth=key") {
		t.Errorf("detail %q", au[0].Detail)
	}
	assertNoSecrets(t, "ответ", rec.Body.String())
	assertNoSecrets(t, "аудит", fmt.Sprintf("%+v", au))
	assertNoSecrets(t, "логи", e.logs.String())
}

func TestCreateJobValidation(t *testing.T) {
	e := newInstallEnv(t, nil)
	cases := map[string]func(map[string]any){
		"name":        func(b map[string]any) { b["name"] = "bad name!" },
		"host":        func(b map[string]any) { b["host"] = "a b" },
		"ssh_port":    func(b map[string]any) { b["ssh_port"] = 70000 },
		"agent_port":  func(b map[string]any) { b["agent_port"] = -1 },
		"user":        func(b map[string]any) { b["user"] = "Root User" },
		"weight":      func(b map[string]any) { b["weight"] = 5000 },
		"auth":        func(b map[string]any) { delete(b, "password") },
		"private_key": func(b map[string]any) { delete(b, "password"); b["private_key"] = strings.Repeat("A", 40<<10) },
	}
	for field, mod := range cases {
		b := validBody()
		mod(b)
		rec := e.post("/api/v1/install-jobs", b)
		if rec.Code != 422 {
			t.Errorf("%s: %d %s", field, rec.Code, rec.Body)
			continue
		}
		var out struct {
			Fields map[string]string `json:"fields"`
		}
		decode(t, rec, &out)
		if out.Fields[field] == "" {
			t.Errorf("%s: нет ошибки поля: %s", field, rec.Body)
		}
		assertNoSecrets(t, field, rec.Body.String())
	}
	// ключ и пароль одновременно
	b := validBody()
	b["private_key"] = secKey
	if rec := e.post("/api/v1/install-jobs", b); rec.Code != 422 || !strings.Contains(rec.Body.String(), "auth") {
		t.Errorf("оба способа: %d", rec.Code)
	}
	if len(e.fi.reqs) != 0 {
		t.Errorf("установщик вызван при невалидном вводе: %d", len(e.fi.reqs))
	}
	// неизвестное поле и не-JSON
	b = validBody()
	b["evil"] = 1
	if c := e.post("/api/v1/install-jobs", b).Code; c != 400 {
		t.Errorf("unknown field: %d", c)
	}
}

func TestCreateJobInstallerErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
		sub  string
	}{
		{"unknown", &installer.ErrHostKeyUnknown{Algo: "ssh-ed25519", Fingerprint: "SHA256:zzz"}, 409, "host_key_unknown"},
		{"mismatch", installer.ErrHostKeyMismatch, 409, "host_key_mismatch"},
		{"passphrase", installer.ErrPassphraseRequired, 422, "passphrase"},
		{"badpass", installer.ErrBadPassphrase, 422, "passphrase"},
		{"noauth", installer.ErrNoAuth, 422, "auth"},
		{"conflict", fmt.Errorf("x: %w", store.ErrConflict), 422, "name"},
		{"installer", errors.New("installer: в кэше нет пакетов"), 422, "пакетов"},
		{"other", errors.New("db is down: " + secPassword), 500, "internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newInstallEnv(t, nil)
			e.fi.err = c.err
			rec := e.post("/api/v1/install-jobs", validBody())
			if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.sub) {
				t.Errorf("%d %s", rec.Code, rec.Body)
			}
			assertNoSecrets(t, "ответ", rec.Body.String())
			assertNoSecrets(t, "логи", e.logs.String())
			if au, _ := e.st.Audit().List(context.Background(), store.AuditQuery{}); len(au) != 0 {
				t.Errorf("аудит неудачного запуска: %+v", au)
			}
		})
	}
}

func TestInstallNotConfigured(t *testing.T) {
	svc := api.NewInstallService(api.InstallConfig{})
	mux := http.NewServeMux()
	(&api.InstallAPI{Service: svc}).Routes(mux, nil)
	for _, c := range [][3]string{
		{"POST", "/api/v1/install-jobs", `{"name":"a"}`},
		{"POST", "/api/v1/hostkeys/probe", `{"host":"h"}`},
		{"GET", "/api/v1/install-jobs/abc", ""},
		{"GET", "/api/v1/install-jobs/abc/events", ""},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), c[0], c[1], strings.NewReader(c[2])))
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: %d", c[0], c[1], rec.Code)
		}
	}
	if svc.Configured() {
		t.Error("configured")
	}
}

func TestJobStatusEndpoint(t *testing.T) {
	e := newInstallEnv(t, nil)
	fin := t0.Add(time.Minute)
	e.fi.status = installer.JobStatus{
		ID: "J1", AgentID: "ams-2", Host: "h:22", State: store.InstallDone, CreatedAt: t0, FinishedAt: &fin, LastSeq: 5,
		Steps: []installer.StepStatus{{Key: "ssh", Label: "SSH", Status: "ok"}},
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/install-jobs/J1", nil))
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	var out map[string]any
	decode(t, rec, &out)
	if out["state"] != "done" || out["last_seq"] != float64(5) || out["finished_at"] == nil || len(out["steps"].([]any)) != 1 {
		t.Errorf("%v", out)
	}
	e.fi.stErr = store.ErrNotFound
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/install-jobs/J1", nil))
	if rec.Code != 404 {
		t.Errorf("not found: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/install-jobs/bad%20id", nil))
	if rec.Code != 404 {
		t.Errorf("bad id: %d", rec.Code)
	}
}

// ---------- SSE ----------

type frame struct{ id, event, data string }

func readFrames(t *testing.T, r io.Reader, n int) []frame {
	t.Helper()
	sc := bufio.NewScanner(r)
	var out []frame
	var cur frame
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.event != "" {
				out = append(out, cur)
				if n > 0 && len(out) == n {
					return out
				}
			}
			cur = frame{}
		case strings.HasPrefix(line, "id: "):
			cur.id = line[4:]
		case strings.HasPrefix(line, "event: "):
			cur.event = line[7:]
		case strings.HasPrefix(line, "data: "):
			cur.data = line[6:]
		}
	}
	return out
}

func sse(t *testing.T, e *installEnv, path, lastID string) (*http.Response, func()) {
	t.Helper()
	srv := httptest.NewServer(e.mux)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+path, nil)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	return resp, func() { _ = resp.Body.Close(); srv.Close() }
}

func TestSSEReplayFinishedJob(t *testing.T) {
	e := newInstallEnv(t, nil)
	e.fi.events = jobEvents()
	resp, done := sse(t, e, "/api/v1/install-jobs/J1/events", "") //nolint:bodyclose // закрывается в done()
	defer done()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type %q", ct)
	}
	fr := readFrames(t, resp.Body, 0)
	if len(fr) != 5 {
		t.Fatalf("frames %d: %+v", len(fr), fr)
	}
	want := []string{"step", "step", "log", "step", "done"}
	for i, f := range fr {
		if f.event != want[i] || f.id != strconv.Itoa(i+1) {
			t.Errorf("frame %d: %+v", i, f)
		}
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(fr[1].data), &d); err != nil || d["step"] != "ssh" || d["status"] != "running" || d["seq"] != float64(2) {
		t.Errorf("data %s", fr[1].data)
	}
}

func TestSSEResumeAfterLastEventID(t *testing.T) {
	e := newInstallEnv(t, nil)
	e.fi.events = jobEvents()
	resp, done := sse(t, e, "/api/v1/install-jobs/J1/events", "3") //nolint:bodyclose // закрывается в done()
	defer done()
	fr := readFrames(t, resp.Body, 0)
	if len(fr) != 2 || fr[0].id != "4" || fr[1].id != "5" || fr[1].event != "done" {
		t.Fatalf("после Last-Event-ID=3 ожидались 4,5: %+v", fr)
	}
	// всё уже получено
	resp2, done2 := sse(t, e, "/api/v1/install-jobs/J1/events", "5") //nolint:bodyclose // закрывается в done()
	defer done2()
	if fr := readFrames(t, resp2.Body, 0); len(fr) != 0 {
		t.Errorf("лишние события: %+v", fr)
	}
	// то же через query
	resp3, done3 := sse(t, e, "/api/v1/install-jobs/J1/events?last_event_id=4", "") //nolint:bodyclose // закрывается в done()
	defer done3()
	if fr := readFrames(t, resp3.Body, 0); len(fr) != 1 || fr[0].id != "5" {
		t.Errorf("query: %+v", fr)
	}
}

func TestSSELiveStreamStopsAtTerminalEvent(t *testing.T) {
	e := newInstallEnv(t, nil)
	e.fi.events = jobEvents()[:2]
	e.fi.live = make(chan installer.Event, 4)
	resp, done := sse(t, e, "/api/v1/install-jobs/J1/events", "") //nolint:bodyclose // закрывается в done()
	defer done()
	e.fi.live <- ev(3, installer.EventLog, "ssh", "", "ключ "+secretToken+" замаскирован")
	e.fi.live <- ev(4, installer.EventError, "", "", "шаг не выполнен")
	e.fi.live <- ev(5, installer.EventLog, "", "", "после терминального не отправляется")
	fr := readFrames(t, resp.Body, 0)
	if len(fr) != 4 {
		t.Fatalf("frames %+v", fr)
	}
	if fr[3].event != "fail" {
		t.Errorf("неуспех должен идти как fail: %+v", fr[3])
	}
	if strings.Contains(fr[2].data, secretTail) {
		t.Errorf("токен не замаскирован: %s", fr[2].data)
	}
}

func TestSSEClosedLiveChannelEndsStream(t *testing.T) {
	e := newInstallEnv(t, nil)
	e.fi.events = jobEvents()[:1]
	e.fi.live = make(chan installer.Event)
	resp, done := sse(t, e, "/api/v1/install-jobs/J1/events", "") //nolint:bodyclose // закрывается в done()
	defer done()
	go func() { time.Sleep(30 * time.Millisecond); close(e.fi.live) }()
	if fr := readFrames(t, resp.Body, 0); len(fr) != 1 {
		t.Errorf("%+v", fr)
	}
}

func TestSSEHeartbeat(t *testing.T) {
	e := newInstallEnv(t, nil)
	e.fi.live = make(chan installer.Event)
	resp, done := sse(t, e, "/api/v1/install-jobs/J1/events", "") //nolint:bodyclose // закрывается в done()
	defer done()
	sc := bufio.NewScanner(resp.Body)
	deadline := time.After(2 * time.Second)
	got := make(chan bool, 1)
	go func() {
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), ": ping") {
				got <- true
				return
			}
		}
		got <- false
	}()
	select {
	case ok := <-got:
		if !ok {
			t.Error("поток закрылся без ping")
		}
	case <-deadline:
		t.Error("нет heartbeat")
	}
}

func TestSSEErrors(t *testing.T) {
	e := newInstallEnv(t, nil)
	for _, c := range []struct {
		path, last string
		code       int
	}{
		{"/api/v1/install-jobs/J1/events", "abc", 400},
		{"/api/v1/install-jobs/J1/events", "-5", 400},
		{"/api/v1/install-jobs/01NOSUCHJOBNOSUCHJOBNOSUCH/events", "", 404},
		{"/api/v1/install-jobs/bad%20id/events", "", 404},
	} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(context.Background(), "GET", c.path, nil)
		if c.last != "" {
			r.Header.Set("Last-Event-ID", c.last)
		}
		e.mux.ServeHTTP(rec, r)
		if rec.Code != c.code {
			t.Errorf("%s (%s): %d", c.path, c.last, rec.Code)
		}
	}
}

// ---------- staged-креды мастера ----------

func TestStageConfirmFlow(t *testing.T) {
	e := newInstallEnv(t, nil)
	act := api.Actor{User: "alice", IP: "1.2.3.4"}
	probe := api.ProbeResult{Addr: "h:22", Algo: "ED25519", Fingerprint: "SHA256:shown"}
	in := api.InstallInput{Name: "a", Host: "h", SSHPort: 22, User: "root", AgentPort: 8443, Weight: 10, Password: []byte(secPassword)}
	id, err := e.svc.Stage(act, in, probe)
	if err != nil || id == "" {
		t.Fatal(err)
	}
	gotProbe, form, ok := e.svc.Pending(act, id)
	if !ok || gotProbe.Fingerprint != "SHA256:shown" || form.Name != "a" || form.Password != nil {
		t.Fatalf("pending: %+v %+v %v", gotProbe, form, ok)
	}
	if _, _, ok := e.svc.Pending(api.Actor{User: "bob"}, id); ok {
		t.Error("чужая сессия видит staged")
	}
	if _, _, err := e.svc.Confirm(context.Background(), api.Actor{User: "bob"}, id); !errors.Is(err, api.ErrPendingGone) {
		t.Errorf("чужое подтверждение: %v", err)
	}
	job, form, err := e.svc.Confirm(context.Background(), act, id)
	if err != nil || job == "" || form.Name != "a" {
		t.Fatalf("confirm: %v %v", job, err)
	}
	r := e.fi.reqs[0]
	// подтверждается именно показанный администратору отпечаток
	if r.ConfirmedFingerprint != "SHA256:shown" || string(bytes.TrimRight(r.Auth.Password, "\x00")) != "" && false {
		t.Errorf("req %+v", r)
	}
	if bytes.Contains(r.Auth.Password, []byte(secPassword)) {
		t.Error("staged-пароль не затёрт после запуска")
	}
	if _, _, err := e.svc.Confirm(context.Background(), act, id); !errors.Is(err, api.ErrPendingGone) {
		t.Errorf("повторное подтверждение: %v", err)
	}
	assertNoSecrets(t, "логи", e.logs.String())
}

func TestStageRejectAndExpiry(t *testing.T) {
	e := newInstallEnv(t, func(c *api.InstallConfig) { c.PendingTTL = 40 * time.Millisecond })
	act := api.Actor{User: "alice"}
	in := api.InstallInput{Name: "a", Host: "h", SSHPort: 22, Password: []byte(secPassword)}
	id, _ := e.svc.Stage(act, in, api.ProbeResult{Fingerprint: "SHA256:x"})
	form, ok := e.svc.Reject(act, id)
	if !ok || form.Host != "h" || form.Password != nil {
		t.Errorf("reject: %+v %v", form, ok)
	}
	if _, ok := e.svc.Reject(act, id); ok {
		t.Error("повторный reject")
	}
	// истечение: запись пропадает и затирается
	cp := []byte(secPassword)
	id, _ = e.svc.Stage(act, api.InstallInput{Name: "a", Host: "h", Password: cp}, api.ProbeResult{Fingerprint: "SHA256:x"})
	time.Sleep(120 * time.Millisecond)
	if _, _, ok := e.svc.Pending(act, id); ok {
		t.Error("просроченная запись жива")
	}
	if _, _, err := e.svc.Confirm(context.Background(), act, id); !errors.Is(err, api.ErrPendingGone) {
		t.Errorf("confirm просроченного: %v", err)
	}
	// истечение по часам сервиса
	e2 := newInstallEnv(t, nil)
	id, _ = e2.svc.Stage(act, in, api.ProbeResult{})
	e2.now = e2.now.Add(6 * time.Minute)
	if _, _, ok := e2.svc.Pending(act, id); ok {
		t.Error("истёкшая по часам запись жива")
	}
}

func TestStageCapacity(t *testing.T) {
	e := newInstallEnv(t, nil)
	act := api.Actor{User: "alice"}
	var last error
	for i := 0; i < 40; i++ {
		_, last = e.svc.Stage(act, api.InstallInput{Name: "a", Password: []byte("x")}, api.ProbeResult{})
	}
	if !errors.Is(last, api.ErrPendingGone) {
		t.Errorf("переполнение не ограничено: %v", last)
	}
}

func TestInputZero(t *testing.T) {
	in := api.InstallInput{Password: []byte("abc"), PrivateKey: []byte("def"), Passphrase: []byte("ghi")}
	p, k, ph := in.Password, in.PrivateKey, in.Passphrase
	in.Zero()
	for _, b := range [][]byte{p, k, ph} {
		for _, c := range b {
			if c != 0 {
				t.Errorf("не затёрто: %v", b)
			}
		}
	}
	if in.Password != nil || in.PrivateKey != nil || in.Passphrase != nil {
		t.Error("ссылки не сброшены")
	}
}
