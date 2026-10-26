package screens_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/enroll"
	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

var agNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

const (
	wSecretPw   = "Pa55w0rd-SECRET-xyz"
	wSecretPass = "pass-phrase-SECRET-123"
	wSecretKey  = "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYBODYSECRETKEYBODY\n-----END OPENSSH PRIVATE KEY-----"
	wToken      = "ENROLL-TOKEN-abcdef-123456"
)

var wSecrets = []string{wSecretPw, wSecretPass, "SECRETKEYBODY"}

func noSecrets(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range wSecrets {
		if strings.Contains(text, s) {
			t.Errorf("%s содержит секрет %q", what, s)
		}
	}
}

// ---------- фейки ----------

type agFleet struct {
	mu     sync.Mutex
	states []agents.State
	conns  map[string]int
	calls  []string
	err    error
	rm     agents.RemoveResult
}

func (f *agFleet) List() []agents.State { return f.states }

func (f *agFleet) Get(id string) (agents.State, bool) {
	for _, s := range f.states {
		if s.Agent.ID == id {
			return s, true
		}
	}
	return agents.State{}, false
}

func (f *agFleet) rec(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
	return f.err
}

func (f *agFleet) SetDraining(_ context.Context, id string, on bool) error {
	return f.rec(fmt.Sprintf("drain:%s:%t", id, on))
}
func (f *agFleet) RotateNow(_ context.Context, id string) error { return f.rec("rotate:" + id) }
func (f *agFleet) Remove(_ context.Context, id string) (agents.RemoveResult, error) {
	return f.rm, f.rec("remove:" + id)
}
func (f *agFleet) Conns(id string) int { return f.conns[id] }
func (f *agFleet) SetWeight(_ context.Context, id string, w int) error {
	return f.rec(fmt.Sprintf("weight:%s:%d", id, w))
}

func (f *agFleet) SetMode(_ context.Context, id string, m config.AgentMode, server, agentURL string) error {
	return f.rec(fmt.Sprintf("mode:%s:%s:%s:%s", id, m, server, agentURL))
}

func agState(id string, mode store.AgentMode, up bool, version string, certDays int) agents.State {
	u := ""
	if mode == store.ModeDial {
		u = "https://185.12.4.10:8443"
	}
	return agents.State{
		Agent: store.Agent{ID: id, Name: id, URL: u, Mode: mode, Weight: 100}, Up: up, LastSeen: agNow.Add(-2 * time.Second),
		LastStatus: &transport.AgentStatus{Version: version, RPS1m: 96.4, Inflight: 8, UpstreamRTTMs: 182, CertNotAfter: agNow.Add(time.Duration(certDays) * 24 * time.Hour)},
	}
}

type agInstaller struct {
	mu     sync.Mutex
	reqs   []installer.Request
	err    error
	status installer.JobStatus
	stErr  error
}

func (f *agInstaller) Install(_ context.Context, r installer.Request) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Сервис затирает свои буферы после вызова; настоящий Installer клонирует их на входе.
	r.Auth = r.Auth.Clone()
	f.reqs = append(f.reqs, r)
	if f.err != nil {
		return "", f.err
	}
	return "01JOBJOBJOBJOBJOBJOBJOBJOB", nil
}

func (f *agInstaller) Status(context.Context, string) (installer.JobStatus, error) {
	return f.status, f.stErr
}

func (f *agInstaller) Events(context.Context, string, int64) ([]installer.Event, <-chan installer.Event, error) {
	ch := make(chan installer.Event)
	close(ch)
	return nil, ch, nil
}

type agIssuer struct {
	repo store.EnrollmentRepo
	n    int
	err  error
}

func (f *agIssuer) IssueFor(ctx context.Context, r enroll.IssueRequest) (enroll.Issued, error) {
	if f.err != nil {
		return enroll.Issued{}, f.err
	}
	f.n++
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", wToken, f.n)))
	id := fmt.Sprintf("%016x", f.n)
	exp := agNow.Add(r.TTL)
	err := f.repo.Create(ctx, store.Enrollment{ID: id, TokenHash: h[:], Name: r.Name, Weight: r.Weight, CreatedBy: r.CreatedBy, CreatedAt: agNow, ExpiresAt: exp})
	return enroll.Issued{ID: id, Token: wToken, Cmdline: "sudo TGP_ENROLL_TOKEN=" + wToken + " tgproxy agent enroll --server https://srv:8444 --ca-fingerprint SHA256:ca",
		CmdlineInstalled: "printf %s 'x' | sudo tgproxy agent enroll --token-stdin", ExpiresAt: exp}, err
}

type agFx struct {
	*fx
	fleet  *agFleet
	inst   *agInstaller
	issuer *agIssuer
	logs   *bytes.Buffer
	sid    *http.Cookie
	rh     *screens.RolloutHandle
	probes int
	probe  func(installer.Target) (string, string, error)
	emerg  *agEmergency
}

type agOpts struct{ noService, noInstall, noEnroll, emergency bool }

func newAgFx(t *testing.T, o agOpts) *agFx {
	t.Helper()
	f := newFx(t, false)
	a := &agFx{fx: f, logs: &bytes.Buffer{}, inst: &agInstaller{}}
	a.fleet = &agFleet{
		states: []agents.State{
			agState("fra-1", store.ModeDial, true, "v1.4.1", 71),
			agState("hel-1", store.ModeDial, true, "v1.3.9", 12),
			agState("waw-1", store.ModeReverse, true, "v1.4.1", 88),
			agState("ist-1", store.ModeDial, false, "v1.4.1", 55),
		},
		conns: map[string]int{"waw-1": 2},
	}
	a.fleet.states[1].ConsecutiveFails = 1
	a.fleet.states[0].Draining = false
	lg := slog.New(slog.NewTextHandler(a.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a.probe = func(_ installer.Target) (string, string, error) {
		return "ssh-ed25519", "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", nil
	}
	deps := screens.AgentsDeps{Rollout: func() *screens.RolloutHandle { return a.rh }, Auth: f.a, ServerVersion: "v1.4.1", Logger: lg, Now: func() time.Time { return agNow }}
	if !o.noService {
		deps.Service = api.NewAgentsService(api.AgentsConfig{
			Agents: a.fleet, Drainer: a.fleet, Rotator: a.fleet, Remover: a.fleet, Mode: a.fleet, Weight: a.fleet, Reverse: a.fleet,
			Audit: f.st.Audit(), GatewayURL: "https://srv:8444", Logger: lg, Now: func() time.Time { return agNow },
		})
	}
	if !o.noInstall {
		deps.Install = api.NewInstallService(api.InstallConfig{
			Installer: a.inst, HostKeys: f.st.HostKeys(), Audit: f.st.Audit(), Logger: lg, Now: func() time.Time { return agNow },
			Probe: func(_ context.Context, tg installer.Target) (string, string, error) { a.probes++; return a.probe(tg) },
		})
	}
	if !o.noEnroll {
		a.issuer = &agIssuer{repo: f.st.Enrollments()}
		deps.Enroll = api.NewEnrollService(api.EnrollConfig{Issuer: a.issuer, Enrollments: f.st.Enrollments(), Audit: f.st.Audit(), Logger: lg, Now: func() time.Time { return agNow }})
	}
	if o.emergency {
		a.emerg = &agEmergency{}
		a.fleet.states[0].Agent.SSHHost, a.fleet.states[0].Agent.SSHPort = "185.12.4.10", 22 // у hel-1 цели нет
		deps.Emergency = &api.EmergencyService{Updater: a.emerg, Audit: f.st.Audit(), Log: lg, Now: func() time.Time { return agNow }}
	}
	screens.MountAgents(f.rt, deps)
	a.sid = f.sessionCookie("alice")
	return a
}

func (a *agFx) call(method, path string, form url.Values, htmx bool) (int, string, http.Header) {
	a.t.Helper()
	hd := map[string]string{}
	if htmx {
		hd["HX-Request"] = "true"
	}
	w := a.do(req{method: method, path: path, form: form, hdr: hd, cookies: []*http.Cookie{a.sid}})
	return w.Code, w.Body.String(), w.Header()
}

func (a *agFx) audit() []store.AuditEntry {
	list, _ := a.st.Audit().List(context.Background(), store.AuditQuery{})
	return list
}

func contains(t *testing.T, what, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("%s: нет %q\n%s", what, w, body)
		}
	}
}

// ---------- экран «Агенты» ----------

func TestAgentsRequireSessionAndCSRF(t *testing.T) {
	a := newAgFx(t, agOpts{})
	for _, p := range []string{"/agents", "/agents/new", "/agents/fra-1/more", "/agents/new/jobs/J1"} {
		if w := a.do(req{method: "GET", path: p}); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("GET %s без сессии: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/agents/fra-1/drain", "/agents/fra-1/rotate", "/agents/fra-1/delete", "/agents/fra-1/mode", "/agents/new/ssh", "/agents/new/nat", "/agents/enroll/ab/revoke"} {
		w := a.do(req{method: "POST", path: p, form: url.Values{"confirm": {"yes"}}, hdr: hx})
		if w.Code != 401 || w.Header().Get("HX-Redirect") != "/login" {
			t.Errorf("POST %s без сессии: %d", p, w.Code)
		}
		w = a.do(req{
			method: "POST", path: p, form: url.Values{"confirm": {"yes"}}, cookies: []*http.Cookie{a.sid},
			hdr: map[string]string{"HX-Request": "true", "Sec-Fetch-Site": "cross-site"},
		})
		if w.Code != 403 {
			t.Errorf("POST %s кросс-доменный: %d", p, w.Code)
		}
	}
	if len(a.fleet.calls) != 0 || len(a.inst.reqs) != 0 || a.issuer.n != 0 {
		t.Errorf("действия выполнены без прав: %v %d %d", a.fleet.calls, len(a.inst.reqs), a.issuer.n)
	}
}

func TestAgentsPage(t *testing.T) {
	a := newAgFx(t, agOpts{})
	code, body, hdr := a.call("GET", "/agents", nil, false)
	if code != 200 {
		t.Fatalf("code %d", code)
	}
	assertStrictCSP(t, body)
	if !strings.Contains(hdr.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("нет CSP")
	}
	contains(
		t, "страница", body,
		"<title>Агенты — tgproxy</title>", "4 агента · 3 в работе · версия сервера v1.4.1", "+ Добавить агента", `href="/agents/new"`,
		`id="agents-body"`, `hx-trigger="every 5s"`, `hx-include="#agents-filter"`, `id="agents-filter"`,
		">fra-1<", "185.12.4.10:8443", "→ агент", "агент →", "· 2 соед.", "В работе", "Деградация", "Недоступен",
		"96", "182 мс", "v1.3.9", "ver-stale", "71 д", "88 д", "12 д", "tone-warn", "только что",
		`aria-label="Вывести из балансировки (drain): fra-1"`, `aria-label="Перевыпустить сертификат: fra-1"`,
		`aria-label="Сменить режим связи: fra-1"`, `aria-label="Ещё действия: fra-1"`, `id="agent-modal"`, `data-modal-open="agent-modal"`,
	)
	if strings.Contains(body, `class="mono">v1.4.1</td>`) && strings.Contains(body, "ver-stale\">v1.4.1") {
		t.Error("актуальная версия подсвечена как отстающая")
	}
	if n := strings.Count(body, "<button"); n < 12 || strings.Contains(body, ">Drain</button>") {
		t.Error("действия должны быть иконками с aria-label")
	}
}

func TestAgentsFragmentAndFilters(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, body, hdr := a.call("GET", "/agents", nil, true)
	if strings.Contains(body, "<html") || !strings.Contains(body, `id="agents-body"`) || hdr.Get("Vary") == "" {
		t.Errorf("htmx-запрос должен получать фрагмент: %.200s", body)
	}
	_, body, _ = a.call("GET", "/agents?status=down", nil, true)
	if !strings.Contains(body, "ist-1") || strings.Contains(body, ">fra-1<") {
		t.Errorf("фильтр по статусу: %s", body)
	}
	_, body, _ = a.call("GET", "/agents?q=185.12", nil, true)
	if !strings.Contains(body, "fra-1") || strings.Contains(body, ">waw-1<") {
		t.Errorf("поиск по адресу: %s", body)
	}
	_, body, _ = a.call("GET", "/agents?q=нет-такого", nil, true)
	if !strings.Contains(body, "Ничего не найдено") {
		t.Errorf("пусто при фильтре: %s", body)
	}
	_, body, _ = a.call("GET", "/agents?status=%27%3E%3Cscript%3E", nil, true)
	if strings.Contains(body, "<script") || !strings.Contains(body, ">fra-1<") {
		t.Errorf("недопустимый статус игнорируется: %s", body)
	}
	a.fleet.states = nil
	_, body, _ = a.call("GET", "/agents", nil, true)
	if !strings.Contains(body, "Агентов пока нет") {
		t.Errorf("пустой реестр: %s", body)
	}
}

func TestAgentsStatesInPage(t *testing.T) {
	a := newAgFx(t, agOpts{})
	a.fleet.states[0].Draining = true
	a.fleet.states[2].LastStatus.CertNotAfter = agNow.Add(-time.Hour)
	a.fleet.states[3].LastSeen = time.Time{}
	a.fleet.states[3].LastStatus = nil
	a.fleet.conns["fra-1"] = 1
	_, body, _ := a.call("GET", "/agents", nil, true)
	contains(t, "состояния", body, "Drain", "undrain", "истёк", "tone-err", "оба", "· 1 соед.")
}

func TestAgentsNotConfigured(t *testing.T) {
	a := newAgFx(t, agOpts{noService: true})
	code, body, _ := a.call("GET", "/agents", nil, false)
	if code != 200 || !strings.Contains(body, "Управление агентами не настроено") {
		t.Errorf("%d %s", code, body)
	}
	for _, p := range []string{"/agents/fra-1/more", "/agents/fra-1/rotate", "/agents/fra-1/mode", "/agents/fra-1/delete"} {
		if c, _, _ := a.call("GET", p, nil, true); c != http.StatusNotImplemented {
			t.Errorf("GET %s: %d", p, c)
		}
	}
	if c, _, _ := a.call("POST", "/agents/fra-1/drain", nil, true); c != http.StatusNotImplemented {
		t.Errorf("drain: %d", c)
	}
}

func TestAgentDrainUndrain(t *testing.T) {
	a := newAgFx(t, agOpts{})
	if c, _, _ := a.call("POST", "/agents/fra-1/drain", nil, false); c != 400 {
		t.Errorf("не htmx: %d", c)
	}
	code, body, hdr := a.call("POST", "/agents/fra-1/drain", url.Values{"status": {"down"}}, true)
	if code != 200 || !strings.Contains(hdr.Get("HX-Trigger"), "drain") || !strings.Contains(body, `id="agents-body"`) {
		t.Fatalf("%d %v %s", code, hdr, body)
	}
	// фильтры сохраняются при обновлении таблицы
	if !strings.Contains(body, "ist-1") || strings.Contains(body, ">fra-1<") {
		t.Errorf("фильтр потерян: %s", body)
	}
	if c, _, h := a.call("POST", "/agents/fra-1/undrain", nil, true); c != 200 || !strings.Contains(h.Get("HX-Trigger"), "ok") {
		t.Errorf("undrain: %d", c)
	}
	if got := strings.Join(a.fleet.calls, ","); got != "drain:fra-1:true,drain:fra-1:false" {
		t.Errorf("calls %s", got)
	}
	if len(a.audit()) != 2 {
		t.Errorf("audit %+v", a.audit())
	}
	if c, _, h := a.call("POST", "/agents/nope/drain", nil, true); c != 200 || !strings.Contains(h.Get("HX-Trigger"), "err") {
		t.Errorf("неизвестный агент: %d %v", c, h)
	}
	if c, _, _ := a.call("POST", "/agents/-bad/drain", nil, true); c != 404 {
		t.Errorf("bad id: %d", c)
	}
	a.fleet.err = errors.New("db")
	if _, _, h := a.call("POST", "/agents/fra-1/drain", nil, true); !strings.Contains(h.Get("HX-Trigger"), "err") {
		t.Errorf("ошибка не показана тостом: %v", h)
	}
}

func TestAgentRotateFlow(t *testing.T) {
	a := newAgFx(t, agOpts{})
	code, body, _ := a.call("GET", "/agents/fra-1/rotate", nil, true)
	contains(t, "confirm", body, "Перевыпустить сертификат?", `name="confirm" value="yes"`, `hx-post="/agents/fra-1/rotate"`)
	if code != 200 {
		t.Fatalf("%d", code)
	}
	if c, _, _ := a.call("GET", "/agents/fra-1/rotate", nil, false); c != http.StatusSeeOther && c != 400 {
		t.Errorf("не htmx GET: %d", c)
	}
	if c, _, _ := a.call("POST", "/agents/fra-1/rotate", nil, true); c != 400 {
		t.Fatalf("без confirm: %d", c)
	}
	if len(a.fleet.calls) != 0 {
		t.Fatalf("ротация без подтверждения: %v", a.fleet.calls)
	}
	code, body, hdr := a.call("POST", "/agents/fra-1/rotate", url.Values{"confirm": {"yes"}}, true)
	if code != 200 || !strings.Contains(body, `hx-swap-oob="true"`) || !strings.Contains(hdr.Get("HX-Trigger"), "ok") {
		t.Errorf("%d %s", code, body)
	}
	a.fleet.err = agents.ErrRotationInProgress
	code, body, _ = a.call("POST", "/agents/fra-1/rotate", url.Values{"confirm": {"yes"}}, true)
	if code != 422 || !strings.Contains(body, "уже выполняется") {
		t.Errorf("in progress: %d %s", code, body)
	}
	if c, _, _ := a.call("GET", "/agents/nope/rotate", nil, true); c != 404 {
		t.Errorf("unknown: %d", c)
	}
}

func TestAgentModeFlow(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, body, _ := a.call("GET", "/agents/fra-1/mode", nil, true)
	contains(t, "форма", body, `name="mode" value="dial" checked`, "https://185.12.4.10:8443", `hx-post="/agents/fra-1/mode"`)
	_, body, _ = a.call("GET", "/agents/waw-1/mode", nil, true)
	contains(t, "reverse", body, `name="mode" value="reverse" checked`)

	// валидация: dial → reverse без соединений
	code, body, _ := a.call("POST", "/agents/fra-1/mode", url.Values{"mode": {"reverse"}}, true)
	if code != 422 || !strings.Contains(body, "Сначала включите") {
		t.Errorf("%d %s", code, body)
	}
	code, body, _ = a.call("POST", "/agents/waw-1/mode", url.Values{"mode": {"dial"}}, true)
	if code != 422 || !strings.Contains(body, "укажите адрес агента") {
		t.Errorf("%d %s", code, body)
	}
	if len(a.fleet.calls) != 0 {
		t.Fatalf("вызовы при ошибке: %v", a.fleet.calls)
	}
	code, body, hdr := a.call("POST", "/agents/fra-1/mode", url.Values{"mode": {"both"}}, true)
	if code != 200 || !strings.Contains(body, "hx-swap-oob") || !strings.Contains(hdr.Get("HX-Trigger"), "ok") {
		t.Errorf("%d %s", code, body)
	}
	if got := a.fleet.calls[0]; got != "mode:fra-1:both:https://srv:8444:https://185.12.4.10:8443" {
		t.Errorf("call %s", got)
	}
	a.fleet.err = api.ErrAgentRejected
	code, body, _ = a.call("POST", "/agents/fra-1/mode", url.Values{"mode": {"both"}}, true)
	if code != 422 || !strings.Contains(body, "Режим не изменён") {
		t.Errorf("rejected: %d %s", code, body)
	}
	a.fleet.err = errors.New("db")
	if code, _, _ = a.call("POST", "/agents/fra-1/mode", url.Values{"mode": {"both"}}, true); code != 422 {
		t.Errorf("internal: %d", code)
	}
	if n := len(a.audit()); n != 1 {
		t.Errorf("аудит: %d", n)
	}
}

func TestAgentMoreAndDeleteFlow(t *testing.T) {
	a := newAgFx(t, agOpts{})
	a.fleet.rm = agents.RemoveResult{Revoked: 3, DrainTimedOut: true, DrainUnchecked: true}
	_, body, _ := a.call("GET", "/agents/fra-1/more", nil, true)
	contains(t, "more", body, "fra-1", "185.12.4.10:8443", "Удалить агента…", `hx-get="/agents/fra-1/delete"`)
	_, body, _ = a.call("GET", "/agents/fra-1/delete", nil, true)
	contains(t, "confirm", body, "Удалить агента?", "denylist", `name="confirm" value="yes"`, "btn-danger")
	if c, _, _ := a.call("POST", "/agents/fra-1/delete", nil, true); c != 400 {
		t.Fatalf("без confirm: %d", c)
	}
	if len(a.fleet.calls) != 0 {
		t.Fatalf("удаление без подтверждения: %v", a.fleet.calls)
	}
	code, body, hdr := a.call("POST", "/agents/fra-1/delete", url.Values{"confirm": {"yes"}}, true)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	contains(t, "итог", body, "Агент «fra-1» удалён", "<strong>3</strong>", "denylist", "Не все запросы завершились", "недоступен", `hx-swap-oob="true"`)
	if !strings.Contains(hdr.Get("HX-Trigger"), "ok") {
		t.Errorf("нет тоста")
	}
	if au := a.audit(); len(au) != 1 || au[0].Action != api.AuditAgentRemove {
		t.Errorf("audit %+v", au)
	}
	a.fleet.err = errors.New("db")
	if code, _, _ = a.call("POST", "/agents/hel-1/delete", url.Values{"confirm": {"yes"}}, true); code != 422 {
		t.Errorf("ошибка удаления: %d", code)
	}
	if c, _, _ := a.call("GET", "/agents/nope/more", nil, true); c != 404 {
		t.Errorf("unknown: %d", c)
	}
}

func TestAgentsHelpersOnWeirdNames(t *testing.T) {
	a := newAgFx(t, agOpts{})
	a.fleet.states[0].Agent.Name = ""
	a.fleet.states[0].LastStatus.CertNotAfter = agNow.Add(2 * time.Hour)
	_, body, _ := a.call("GET", "/agents", nil, true)
	contains(t, "<1d", body, "&lt; 1 д")
}

func TestAgentWeightFlow(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, page, _ := a.call("GET", "/agents", nil, false)
	if !strings.Contains(page, `hx-get="/agents/fra-1/weight"`) {
		t.Errorf("нет иконки веса в строке")
	}
	code, body, _ := a.call("GET", "/agents/fra-1/weight", nil, true)
	if code != 200 || !strings.Contains(body, `name="weight"`) || !strings.Contains(body, `value="100"`) {
		t.Fatalf("форма: %d %s", code, body)
	}
	for _, bad := range []string{"0", "101", "abc", ""} {
		code, body, _ = a.call("POST", "/agents/fra-1/weight", url.Values{"weight": {bad}}, true)
		if code != 422 || !strings.Contains(body, "field-error") {
			t.Errorf("%q: %d %s", bad, code, body)
		}
	}
	if len(a.fleet.calls) != 0 {
		t.Fatalf("вызовы при ошибке: %v", a.fleet.calls)
	}
	code, body, hdr := a.call("POST", "/agents/fra-1/weight", url.Values{"weight": {"37"}}, true)
	if code != 200 || !strings.Contains(hdr.Get("HX-Trigger"), "ok") || !strings.Contains(body, "hx-swap-oob") {
		t.Errorf("%d %s", code, body)
	}
	if len(a.fleet.calls) != 1 || a.fleet.calls[0] != "weight:fra-1:37" {
		t.Errorf("calls %v", a.fleet.calls)
	}
	if n := len(a.audit()); n != 1 {
		t.Errorf("аудит: %d", n)
	}
	if code, _, _ = a.call("GET", "/agents/fra-1/weight", nil, false); code == 200 {
		t.Errorf("без htmx должно быть отказано")
	}
}
