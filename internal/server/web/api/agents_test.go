package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// fleet — фейк реестра агентов и всех управляющих интерфейсов.
type fleet struct {
	states   []agents.State
	conns    map[string]int
	calls    []string
	err      error
	removeRs agents.RemoveResult
	gotMode  struct {
		mode     config.AgentMode
		server   string
		agentURL string
	}
}

func (f *fleet) List() []agents.State { return f.states }

func (f *fleet) Get(id string) (agents.State, bool) {
	for _, s := range f.states {
		if s.Agent.ID == id {
			return s, true
		}
	}
	return agents.State{}, false
}

func (f *fleet) SetDraining(_ context.Context, id string, on bool) error {
	f.calls = append(f.calls, "drain:"+id+":"+map[bool]string{true: "on", false: "off"}[on])
	return f.err
}

func (f *fleet) RotateNow(_ context.Context, id string) error {
	f.calls = append(f.calls, "rotate:"+id)
	return f.err
}

func (f *fleet) Remove(_ context.Context, id string) (agents.RemoveResult, error) {
	f.calls = append(f.calls, "remove:"+id)
	return f.removeRs, f.err
}

func (f *fleet) Conns(id string) int { return f.conns[id] }

func (f *fleet) SetWeight(_ context.Context, id string, w int) error {
	f.calls = append(f.calls, fmt.Sprintf("weight:%s:%d", id, w))
	return f.err
}

func (f *fleet) SetMode(_ context.Context, id string, mode config.AgentMode, server, agentURL string) error {
	f.calls = append(f.calls, "mode:"+id+":"+string(mode))
	f.gotMode.mode, f.gotMode.server, f.gotMode.agentURL = mode, server, agentURL
	return f.err
}

func state(id string, mode store.AgentMode, up bool) agents.State {
	return agents.State{
		Agent: store.Agent{ID: id, Name: id, URL: map[bool]string{true: "https://10.0.0.1:8443", false: ""}[mode == store.ModeDial], Mode: mode, Weight: 100},
		Up:    up, LastSeen: t0,
		LastStatus: &transport.AgentStatus{Version: "v1.4.1", RPS1m: 12.5, Inflight: 3, UpstreamRTTMs: 41, CertNotAfter: t0.Add(72 * 24 * time.Hour)},
	}
}

type agentsEnv struct {
	mux   *http.ServeMux
	fleet *fleet
	svc   *api.AgentsService
	st    *memtest.Store
}

func newAgentsEnv(t *testing.T, mod func(*api.AgentsConfig, *fleet)) *agentsEnv {
	t.Helper()
	f := &fleet{
		states: []agents.State{state("fra-1", store.ModeDial, true), state("waw-1", store.ModeReverse, true), state("ist-1", store.ModeDial, false)},
		conns:  map[string]int{"waw-1": 2},
	}
	st := memtest.New()
	cfg := api.AgentsConfig{
		Agents: f, Drainer: f, Rotator: f, Remover: f, Mode: f, Weight: f, Reverse: f, Audit: st.Audit(),
		GatewayURL: "https://srv:8444", Now: func() time.Time { return t0 },
	}
	if mod != nil {
		mod(&cfg, f)
	}
	svc := api.NewAgentsService(cfg)
	mux := http.NewServeMux()
	(&api.AgentsAPI{Service: svc}).Routes(mux, nil)
	return &agentsEnv{mux: mux, fleet: f, svc: svc, st: st}
}

func (e *agentsEnv) call(method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	e.mux.ServeHTTP(rec, r)
	return rec
}

func (e *agentsEnv) audit(t *testing.T) []store.AuditEntry {
	t.Helper()
	list, err := e.st.Audit().List(context.Background(), store.AuditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestAgentsListShape(t *testing.T) {
	e := newAgentsEnv(t, nil)
	rec := e.call("GET", "/api/v1/agents", "")
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	var out struct {
		Items []api.AgentJSON `json:"items"`
	}
	decode(t, rec, &out)
	if len(out.Items) != 3 {
		t.Fatalf("items %d", len(out.Items))
	}
	by := map[string]api.AgentJSON{}
	for _, a := range out.Items {
		by[a.ID] = a
	}
	if a := by["fra-1"]; a.Link != "dial" || a.Status != "up" || a.Version != "v1.4.1" || a.RPS1m == nil || *a.RPS1m != 12.5 || a.CertNotAfter == nil {
		t.Errorf("fra-1: %+v", a)
	}
	if a := by["waw-1"]; a.Link != "reverse" || a.ReverseConns == nil || *a.ReverseConns != 2 {
		t.Errorf("waw-1: %+v", a)
	}
	if a := by["ist-1"]; a.Status != "down" || a.Up {
		t.Errorf("ist-1: %+v", a)
	}
}

func TestAgentLinkBothAndStatuses(t *testing.T) {
	e := newAgentsEnv(t, func(_ *api.AgentsConfig, f *fleet) {
		f.conns["fra-1"] = 1
		f.states[0].Draining = true
		f.states[1].ConsecutiveFails = 1
	})
	var out struct {
		Items []api.AgentJSON `json:"items"`
	}
	decode(t, e.call("GET", "/api/v1/agents", ""), &out)
	if out.Items[0].Link != "both" || out.Items[0].Status != "draining" {
		t.Errorf("fra-1: %+v", out.Items[0])
	}
	if out.Items[1].Status != "degraded" {
		t.Errorf("waw-1: %+v", out.Items[1])
	}
}

func TestDrainUndrainAudited(t *testing.T) {
	e := newAgentsEnv(t, nil)
	if rec := e.call("POST", "/api/v1/agents/fra-1/drain", ""); rec.Code != 200 {
		t.Fatalf("drain %d %s", rec.Code, rec.Body)
	}
	if rec := e.call("POST", "/api/v1/agents/fra-1/undrain", ""); rec.Code != 200 {
		t.Fatalf("undrain %d", rec.Code)
	}
	if got := strings.Join(e.fleet.calls, ","); got != "drain:fra-1:on,drain:fra-1:off" {
		t.Errorf("calls %s", got)
	}
	au := e.audit(t)
	if len(au) != 2 {
		t.Fatalf("audit %+v", au)
	}
	acts := map[string]bool{au[0].Action: true, au[1].Action: true}
	if !acts[api.AuditAgentDrain] || !acts[api.AuditAgentUndrain] {
		t.Errorf("audit actions %+v", au)
	}
}

func TestAgentNotFoundAndBadID(t *testing.T) {
	e := newAgentsEnv(t, nil)
	if c := e.call("POST", "/api/v1/agents/nope/drain", "").Code; c != 404 {
		t.Errorf("unknown: %d", c)
	}
	if c := e.call("POST", "/api/v1/agents/-bad/drain", "").Code; c != 404 {
		t.Errorf("bad id: %d", c)
	}
	if c := e.call("DELETE", "/api/v1/agents/..%2Fx?confirm=yes", "").Code; c != 404 {
		t.Errorf("traversal: %d", c)
	}
	if len(e.fleet.calls) != 0 {
		t.Errorf("calls %v", e.fleet.calls)
	}
}

func TestRotateRequiresConfirm(t *testing.T) {
	e := newAgentsEnv(t, nil)
	if c := e.call("POST", "/api/v1/agents/fra-1/rotate", "").Code; c != 400 {
		t.Fatalf("без confirm: %d", c)
	}
	if len(e.fleet.calls) != 0 {
		t.Fatalf("ротация без подтверждения: %v", e.fleet.calls)
	}
	if c := e.call("POST", "/api/v1/agents/fra-1/rotate?confirm=yes", "").Code; c != 200 {
		t.Fatalf("confirm: %d", c)
	}
	if e.audit(t)[0].Action != api.AuditAgentRotate {
		t.Errorf("audit %+v", e.audit(t))
	}
	e.fleet.err = agents.ErrRotationInProgress
	if c := e.call("POST", "/api/v1/agents/fra-1/rotate?confirm=yes", "").Code; c != 409 {
		t.Errorf("in progress: %d", c)
	}
}

func TestModeValidationAndSuccess(t *testing.T) {
	e := newAgentsEnv(t, nil)
	post := func(id, body string) *httptest.ResponseRecorder {
		return e.call("POST", "/api/v1/agents/"+id+"/mode", body)
	}
	// неизвестный режим
	if rec := post("fra-1", `{"mode":"x"}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), `"mode"`) {
		t.Errorf("bad mode: %d %s", rec.Code, rec.Body)
	}
	// reverse-агенту нужен адрес для dial
	if rec := post("waw-1", `{"mode":"dial"}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "agent_url") {
		t.Errorf("dial без адреса: %d %s", rec.Code, rec.Body)
	}
	if rec := post("waw-1", `{"mode":"dial","agent_url":"http://x"}`); rec.Code != 422 {
		t.Errorf("не https: %d", rec.Code)
	}
	// dial → reverse без соединений: отрежет агента
	if rec := post("fra-1", `{"mode":"reverse"}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "оба") {
		t.Errorf("reverse без соединений: %d %s", rec.Code, rec.Body)
	}
	if len(e.fleet.calls) != 0 {
		t.Fatalf("вызовы при невалидном вводе: %v", e.fleet.calls)
	}
	// dial → both
	if rec := post("fra-1", `{"mode":"both"}`); rec.Code != 200 {
		t.Fatalf("both: %d %s", rec.Code, rec.Body)
	}
	if e.fleet.gotMode.server != "https://srv:8444" || e.fleet.gotMode.agentURL != "https://10.0.0.1:8443" {
		t.Errorf("got %+v", e.fleet.gotMode)
	}
	// reverse-агент → dial с адресом
	if rec := post("waw-1", `{"mode":"dial","agent_url":"https://5.6.7.8:8443"}`); rec.Code != 200 {
		t.Fatalf("dial: %d %s", rec.Code, rec.Body)
	}
	if e.fleet.gotMode.server != "" || e.fleet.gotMode.agentURL != "https://5.6.7.8:8443" {
		t.Errorf("got %+v", e.fleet.gotMode)
	}
	// агент отказал
	e.fleet.err = api.ErrAgentRejected
	if c := post("fra-1", `{"mode":"both"}`).Code; c != 502 {
		t.Errorf("rejected: %d", c)
	}
	if rec := post("fra-1", `{"mode":"both","extra":1}`); rec.Code != 400 {
		t.Errorf("unknown field: %d", rec.Code)
	}
	if n := len(e.audit(t)); n != 2 {
		t.Errorf("аудит только успешных смен: %d", n)
	}
}

func TestModeNoGateway(t *testing.T) {
	e := newAgentsEnv(t, func(c *api.AgentsConfig, _ *fleet) { c.GatewayURL = "" })
	if rec := e.call("POST", "/api/v1/agents/fra-1/mode", `{"mode":"both"}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "agent_gateway") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestRemoveRequiresConfirmAndReportsResult(t *testing.T) {
	e := newAgentsEnv(t, func(_ *api.AgentsConfig, f *fleet) {
		f.removeRs = agents.RemoveResult{Revoked: 2, DrainTimedOut: true}
	})
	if c := e.call("DELETE", "/api/v1/agents/fra-1", "").Code; c != 400 {
		t.Fatalf("без confirm: %d", c)
	}
	if len(e.fleet.calls) != 0 {
		t.Fatalf("удаление без подтверждения: %v", e.fleet.calls)
	}
	rec := e.call("DELETE", "/api/v1/agents/fra-1?confirm=yes", "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	m := keys(t, rec)
	if string(m["revoked"]) != "2" || string(m["drain_timed_out"]) != "true" {
		t.Errorf("%s", rec.Body)
	}
	if au := e.audit(t); len(au) != 1 || au[0].Action != api.AuditAgentRemove || !strings.Contains(au[0].Detail, "revoked=2") {
		t.Errorf("audit %+v", au)
	}
	e.fleet.err = errors.New("boom secret-ish")
	rec = e.call("DELETE", "/api/v1/agents/ist-1?confirm=yes", "")
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("внутренняя ошибка не должна утекать: %d %s", rec.Code, rec.Body)
	}
}

func TestAgentsNotConfigured(t *testing.T) {
	svc := api.NewAgentsService(api.AgentsConfig{Agents: &fleet{}})
	mux := http.NewServeMux()
	(&api.AgentsAPI{Service: svc}).Routes(mux, nil)
	for _, c := range []struct{ m, p, body string }{
		{"POST", "/api/v1/agents/a/drain", ""},
		{"POST", "/api/v1/agents/a/rotate?confirm=yes", ""},
		{"POST", "/api/v1/agents/a/mode", `{"mode":"dial"}`},
		{"DELETE", "/api/v1/agents/a?confirm=yes", ""},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), c.m, c.p, strings.NewReader(c.body)))
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: %d", c.m, c.p, rec.Code)
		}
	}
	if c := svc.Capabilities(); c.Drain || c.Rotate || c.Mode || c.Remove {
		t.Errorf("caps %+v", c)
	}
	var nilSvc *api.AgentsService
	if nilSvc.Configured() || svc.Configured() == false {
		t.Errorf("configured")
	}
	if _, err := api.NewAgentsService(api.AgentsConfig{}).Get("x"); !errors.Is(err, api.ErrNotConfigured) {
		t.Errorf("get: %v", err)
	}
	if api.NewAgentsService(api.AgentsConfig{}).List() != nil {
		t.Errorf("list")
	}
}

func TestAgentsWrapAndCSRF(t *testing.T) {
	e := newAgentsEnv(t, nil)
	deny := api.Wrap(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	})
	mux := http.NewServeMux()
	(&api.AgentsAPI{Service: e.svc}).Routes(mux, deny)
	for _, c := range [][2]string{
		{"GET", "/api/v1/agents"},
		{"POST", "/api/v1/agents/fra-1/drain"},
		{"POST", "/api/v1/agents/fra-1/rotate"},
		{"POST", "/api/v1/agents/fra-1/mode"},
		{"DELETE", "/api/v1/agents/fra-1"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), c[0], c[1], nil))
		if rec.Code != 401 {
			t.Errorf("%s %s без сессии: %d", c[0], c[1], rec.Code)
		}
	}
	// кросс-доменная мутация отбивается CrossOriginProtection до хендлера
	prot := http.NewServeMux()
	(&api.AgentsAPI{Service: e.svc}).Routes(prot, auth.Protect)
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/agents/fra-1/drain", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	prot.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site: %d", rec.Code)
	}
	if len(e.fleet.calls) != 0 {
		t.Errorf("мутация выполнена: %v", e.fleet.calls)
	}
}

// ---------- TransportModeSetter ----------

type fakeTransport struct {
	gotPath, gotMethod, gotBody string
	status                      int
	err                         error
}

func (f *fakeTransport) RoundTrip(_ context.Context, _ transport.AgentRef, req *http.Request) (*http.Response, error) {
	f.gotPath, f.gotMethod = req.URL.Path, req.Method
	b, _ := io.ReadAll(req.Body)
	f.gotBody = string(b)
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{StatusCode: f.status, Body: io.NopCloser(bytes.NewReader([]byte("nope")))}, nil
}

func (f *fakeTransport) Status(context.Context, transport.AgentRef) (*transport.AgentStatus, error) {
	return nil, errors.New("unused")
}

type refs struct{ ok bool }

func (r refs) Ref(id string) (transport.AgentRef, bool) { return transport.AgentRef{ID: id}, r.ok }

func TestTransportModeSetter(t *testing.T) {
	ctx := context.Background()
	mk := func(tr *fakeTransport, ok bool) (api.TransportModeSetter, *memtest.Store, *int) {
		st := memtest.New()
		if _, err := st.Agents().Create(ctx, store.Agent{ID: "fra-1", Name: "fra-1", URL: "https://1.2.3.4:8443", Mode: store.ModeDial, Weight: 10}); err != nil {
			t.Fatal(err)
		}
		n := 0
		return api.TransportModeSetter{Agents: st.Agents(), Refs: refs{ok}, Transport: tr, Refresh: func(context.Context) error { n++; return nil }}, st, &n
	}

	tr := &fakeTransport{status: 200}
	m, st, n := mk(tr, true)
	if err := m.SetMode(ctx, "fra-1", config.AgentModeReverse, "https://srv:8444", ""); err != nil {
		t.Fatal(err)
	}
	if tr.gotMethod != "PUT" || tr.gotPath != "/_agent/config" {
		t.Errorf("запрос %s %s", tr.gotMethod, tr.gotPath)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(tr.gotBody), &body); err != nil || body["mode"] != "reverse" || body["server_url"] != "https://srv:8444" {
		t.Errorf("тело %s", tr.gotBody)
	}
	if a, _ := st.Agents().Get(ctx, "fra-1"); a.Mode != store.ModeReverse || *n != 1 {
		t.Errorf("после reverse: %+v refresh=%d", a, *n)
	}

	// both хранится как both с новым адресом
	if err := m.SetMode(ctx, "fra-1", config.AgentModeBoth, "https://srv:8444", "https://9.9.9.9:8443"); err != nil {
		t.Fatal(err)
	}
	if a, _ := st.Agents().Get(ctx, "fra-1"); a.Mode != store.ModeBoth || a.URL != "https://9.9.9.9:8443" {
		t.Errorf("после both: %+v", a)
	}
	if err := m.SetMode(ctx, "fra-1", config.AgentModeDial, "", ""); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("dial без адреса: %v", err)
	}

	// агент отклонил: запись не меняется
	tr = &fakeTransport{status: 409}
	m, st, n = mk(tr, true)
	if err := m.SetMode(ctx, "fra-1", config.AgentModeReverse, "https://srv:8444", ""); !errors.Is(err, api.ErrAgentRejected) {
		t.Errorf("rejected: %v", err)
	}
	if a, _ := st.Agents().Get(ctx, "fra-1"); a.Mode != store.ModeDial || *n != 0 {
		t.Errorf("запись изменена при отказе: %+v", a)
	}
	// транспорт недоступен
	m, _, _ = mk(&fakeTransport{err: errors.New("dial tcp")}, true)
	if err := m.SetMode(ctx, "fra-1", config.AgentModeReverse, "https://srv:8444", ""); !errors.Is(err, api.ErrAgentUnreachable) {
		t.Errorf("unreachable: %v", err)
	}
	// агента нет в реестре
	m, _, _ = mk(&fakeTransport{status: 200}, false)
	if err := m.SetMode(ctx, "fra-1", config.AgentModeReverse, "x", ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
}

func TestAgentWeight(t *testing.T) {
	e := newAgentsEnv(t, nil)
	for _, bad := range []string{`{"weight":0}`, `{"weight":101}`, `{"weight":-5}`, `{}`} {
		if rec := e.call("POST", "/api/v1/agents/fra-1/weight", bad); rec.Code != 422 || !strings.Contains(rec.Body.String(), "weight") {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	if rec := e.call("POST", "/api/v1/agents/fra-1/weight", `{"weight":5,"x":1}`); rec.Code != 400 {
		t.Errorf("лишнее поле: %d", rec.Code)
	}
	if rec := e.call("POST", "/api/v1/agents/nope/weight", `{"weight":5}`); rec.Code != 404 {
		t.Errorf("нет агента: %d", rec.Code)
	}
	if len(e.fleet.calls) != 0 {
		t.Fatalf("вызовы при невалидном вводе: %v", e.fleet.calls)
	}
	if rec := e.call("POST", "/api/v1/agents/fra-1/weight", `{"weight":42}`); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(e.fleet.calls) != 1 || e.fleet.calls[0] != "weight:fra-1:42" {
		t.Fatalf("calls %v", e.fleet.calls)
	}
	au := e.audit(t)
	if len(au) != 1 || au[0].Action != api.AuditAgentWeight || au[0].Target != "fra-1" || au[0].Detail != "weight=42" {
		t.Fatalf("audit %+v", au)
	}
	e = newAgentsEnv(t, func(c *api.AgentsConfig, _ *fleet) { c.Weight = nil })
	if rec := e.call("POST", "/api/v1/agents/fra-1/weight", `{"weight":5}`); rec.Code == 200 {
		t.Errorf("без WeightSetter: %d", rec.Code)
	}
}
