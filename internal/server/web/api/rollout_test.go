package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/rollout"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type fakeRollouts struct {
	started []rollout.Params
	stops   int
	err     error
	status  rollout.Status
}

func (f *fakeRollouts) Start(_ context.Context, p rollout.Params) (rollout.Status, error) {
	f.started = append(f.started, p)
	return f.status, f.err
}

func (f *fakeRollouts) Stop(context.Context) (rollout.Status, error) {
	f.stops++
	return f.status, f.err
}

func (f *fakeRollouts) Current(context.Context) (rollout.Status, error) { return f.status, f.err }

func sampleStatus() rollout.Status {
	return rollout.Status{
		Rollout: store.Rollout{ID: "r1", Version: "1.2.0", BatchSize: 2, Canary: 1, State: store.RolloutRunning, Actor: "admin", CreatedAt: t0},
		Steps: []store.RolloutStep{
			{RolloutID: "r1", AgentID: "a1", Seq: 1, Phase: store.PhaseCanary, State: store.StepDone, FromVersion: "1.1.0", UpdatedAt: t0},
			{RolloutID: "r1", AgentID: "a2", Seq: 2, Phase: store.PhaseBatch, State: store.StepRunning, UpdatedAt: t0},
			{RolloutID: "r1", AgentID: "a3", Seq: 3, Phase: store.PhaseBatch, State: store.StepPending, UpdatedAt: t0},
			{RolloutID: "r1", AgentID: "a4", Seq: 4, Phase: store.PhaseBatch, State: store.StepSkipped, UpdatedAt: t0},
			{RolloutID: "r1", AgentID: "a5", Seq: 5, Phase: store.PhaseBatch, State: store.StepFailed, Error: "boom", UpdatedAt: t0},
		},
	}
}

type rolloutEnv struct {
	mux *http.ServeMux
	fm  *fakeRollouts
	st  *memtest.Store
}

func newRolloutEnv(t *testing.T, wrap api.Wrap) *rolloutEnv {
	t.Helper()
	e := &rolloutEnv{mux: http.NewServeMux(), fm: &fakeRollouts{status: sampleStatus()}, st: memtest.New()}
	(&api.RolloutAPI{Manager: e.fm, Audit: e.st.Audit(), Now: func() time.Time { return t0 }}).Routes(e.mux, wrap)
	return e
}

func (e *rolloutEnv) call(method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	e.mux.ServeHTTP(rec, req)
	return rec
}

func TestRolloutStartAudited(t *testing.T) {
	e := newRolloutEnv(t, nil)
	rec := e.call(http.MethodPost, "/api/v1/rollouts", `{"version":"1.2.0","batch_size":2,"allow_downtime":true}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(e.fm.started) != 1 || e.fm.started[0].Version != "1.2.0" || e.fm.started[0].BatchSize != 2 ||
		!e.fm.started[0].AllowDowntime || len(e.fm.started[0].Agents) != 0 || e.fm.started[0].NoCanary {
		t.Fatalf("params %+v", e.fm.started)
	}
	var out api.RolloutJSON
	decode(t, rec, &out)
	if out.ID != "r1" || !out.Active || out.Progress != (api.RolloutProgress{Total: 5, Pending: 1, Running: 1, Done: 1, Skipped: 1, Failed: 1}) ||
		out.Steps[0].Phase != "canary" || out.Steps[0].FromVersion != "1.1.0" || out.Steps[4].Error != "boom" {
		t.Fatalf("json %+v", out)
	}
	au, _ := e.st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 1 || au[0].Action != api.AuditRolloutStart || au[0].Target != "1.2.0" || !strings.Contains(au[0].Detail, "rollout=r1") {
		t.Fatalf("audit %+v", au)
	}
}

func TestRolloutErrorsMapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
		kind string
	}{
		{rollout.ErrBusy, 409, "rollout_busy"},
		{rollout.ErrNoPackage, 422, "no_package"},
		{rollout.ErrBadVersion, 422, "bad_version"},
		{rollout.ErrBadParams, 422, "validation"},
		{rollout.ErrUnknownAgent, 404, "not_found"},
		{rollout.ErrAgentDown, 409, "agent_down"},
		{errors.New("db exploded: secret"), 500, "internal"},
	} {
		e := newRolloutEnv(t, nil)
		e.fm.err = tc.err
		rec := e.call(http.MethodPost, "/api/v1/rollouts", `{"version":"1.2.0"}`)
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.kind) || strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("%v: %d %s", tc.err, rec.Code, rec.Body)
		}
		if au, _ := e.st.Audit().List(context.Background(), store.AuditQuery{}); len(au) != 0 {
			t.Errorf("%v: неуспешный запуск записан в аудит", tc.err)
		}
	}
}

func TestRolloutBadBody(t *testing.T) {
	e := newRolloutEnv(t, nil)
	for _, body := range []string{"", "{", `{"version":"1.2.0","evil":1}`} {
		if rec := e.call(http.MethodPost, "/api/v1/rollouts", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", body, rec.Code)
		}
	}
	if len(e.fm.started) != 0 {
		t.Error("менеджер вызван на неверном теле")
	}
}

func TestRolloutCurrentAndStop(t *testing.T) {
	e := newRolloutEnv(t, nil)
	rec := e.call(http.MethodGet, "/api/v1/rollouts/current", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"running"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec = e.call(http.MethodPost, "/api/v1/rollouts/current/stop", ""); rec.Code != http.StatusAccepted || e.fm.stops != 1 {
		t.Fatalf("stop %d %s", rec.Code, rec.Body)
	}
	if au, _ := e.st.Audit().List(context.Background(), store.AuditQuery{}); len(au) != 1 || au[0].Action != api.AuditRolloutStop {
		t.Fatalf("audit %+v", au)
	}
	e.fm.err = rollout.ErrNoActive
	if rec = e.call(http.MethodPost, "/api/v1/rollouts/current/stop", ""); rec.Code != http.StatusConflict {
		t.Errorf("stop без раскатки: %d", rec.Code)
	}
	e.fm.err = store.ErrNotFound
	if rec = e.call(http.MethodGet, "/api/v1/rollouts/current", ""); rec.Code != http.StatusNotFound {
		t.Errorf("current без раскаток: %d", rec.Code)
	}
}

func TestAgentUpdateStartsSingleAgentRollout(t *testing.T) {
	e := newRolloutEnv(t, nil)
	rec := e.call(http.MethodPost, "/api/v1/agents/ams-1/update", `{"version":"1.2.0"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	p := e.fm.started[0]
	if p.Version != "1.2.0" || len(p.Agents) != 1 || p.Agents[0] != "ams-1" || !p.NoCanary {
		t.Fatalf("params %+v", p)
	}
	if au, _ := e.st.Audit().List(context.Background(), store.AuditQuery{}); len(au) != 1 || au[0].Action != api.AuditAgentUpdate || au[0].Target != "ams-1" {
		t.Fatalf("audit %+v", au)
	}
	if rec = e.call(http.MethodPost, "/api/v1/agents/..%2Fx/update", `{"version":"1.2.0"}`); rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
		t.Errorf("плохой id: %d", rec.Code)
	}
}

func TestRolloutRoutesAreProtected(t *testing.T) {
	deny := api.Wrap(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	})
	e := newRolloutEnv(t, deny)
	for _, r := range [][2]string{
		{"POST", "/api/v1/rollouts"}, {"GET", "/api/v1/rollouts/current"}, {"POST", "/api/v1/rollouts/current/stop"},
		{"POST", "/api/v1/agents/a1/update"},
	} {
		if rec := e.call(r[0], r[1], `{"version":"1.2.0"}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: %d без сессии", r[0], r[1], rec.Code)
		}
	}
	if len(e.fm.started) != 0 || e.fm.stops != 0 {
		t.Error("менеджер вызван без авторизации")
	}
}
