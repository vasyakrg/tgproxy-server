package screens_test

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/server/rollout"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type fakeMgr struct {
	mu      sync.Mutex
	cur     *rollout.Status
	started []rollout.Params
	stops   int
	err     error
}

func (f *fakeMgr) Start(_ context.Context, p rollout.Params) (rollout.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return rollout.Status{}, f.err
	}
	f.started = append(f.started, p)
	st := rollout.Status{Rollout: store.Rollout{ID: "r1", Version: p.Version, BatchSize: p.BatchSize, State: store.RolloutRunning}}
	f.cur = &st
	return st, nil
}

func (f *fakeMgr) Stop(context.Context) (rollout.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	if f.err != nil {
		return rollout.Status{}, f.err
	}
	return *f.cur, nil
}

func (f *fakeMgr) Current(context.Context) (rollout.Status, error) {
	if f.cur == nil {
		return rollout.Status{}, store.ErrNotFound
	}
	return *f.cur, nil
}

type pkgs bool

func (p pkgs) Has(string) bool { return bool(p) }

func withRollout(a *agFx, has bool) *fakeMgr {
	m := &fakeMgr{}
	a.rh = &screens.RolloutHandle{API: &api.RolloutAPI{Manager: m, Audit: a.st.Audit()}, Packages: pkgs(has)}
	return m
}

func active(state string) *rollout.Status {
	return &rollout.Status{
		Rollout: store.Rollout{ID: "r1", Version: "1.4.1", BatchSize: 2, State: state},
		Steps: []store.RolloutStep{
			{AgentID: "hel-1", Phase: store.PhaseCanary, State: store.StepDone},
			{AgentID: "fra-1", Phase: store.PhaseBatch, State: store.StepRunning},
			{AgentID: "waw-1", Phase: store.PhaseBatch, State: store.StepFailed, Error: "таймаут"},
		},
	}
}

func TestUpdateButtonsOnlyForLaggingAgents(t *testing.T) {
	a := newAgFx(t, agOpts{})
	withRollout(a, true)
	_, body, _ := a.call("GET", "/agents", nil, false)
	contains(t, "кнопки", body, `aria-label="Обновить отстающие до v1.4.1"`, `aria-label="Обновить до v1.4.1: hel-1"`)
	if strings.Contains(body, `aria-label="Обновить до v1.4.1: fra-1"`) || strings.Contains(body, "Откат") {
		t.Error("кнопка обновления у актуального агента")
	}
	// релиза нет в кэше
	withRollout(a, false)
	_, body, _ = a.call("GET", "/agents", nil, false)
	if strings.Contains(body, "Обновить") {
		t.Error("кнопки без релиза в кэше")
	}
	// раскатка не настроена
	a.rh = nil
	_, body, _ = a.call("GET", "/agents", nil, false)
	if strings.Contains(body, "Обновить") || strings.Contains(body, "ro-banner") {
		t.Error("раскатка не настроена, а UI есть")
	}
	if c, _, _ := a.call("GET", "/agents/rollout/start", nil, true); c != 501 {
		t.Errorf("start: %d", c)
	}
}

func TestRolloutBannerAndStop(t *testing.T) {
	a := newAgFx(t, agOpts{})
	m := withRollout(a, true)
	m.cur = active(store.RolloutRunning)
	_, body, _ := a.call("GET", "/agents", nil, true)
	contains(t, "баннер", body, "Раскатка v1.4.1 · канарейка → батчи по 2", "1 / 3", "канарейка", "выполняется", "таймаут", `aria-label="Остановить раскатку"`)
	assertStrictCSP(t, body)
	if strings.Contains(body, `aria-label="Обновить отстающие`) || strings.Contains(body, `aria-label="Обновить до`) {
		t.Error("обновления во время раскатки недоступны")
	}
	_, conf, _ := a.call("GET", "/agents/rollout/stop", nil, true)
	contains(t, "confirm", conf, "Остановить раскатку?", `name="confirm" value="yes"`)
	if c, _, _ := a.call("POST", "/agents/rollout/stop", nil, true); c != 400 || m.stops != 0 {
		t.Fatalf("без confirm: %d stops=%d", c, m.stops)
	}
	code, _, hdr := a.call("POST", "/agents/rollout/stop", url.Values{"confirm": {"yes"}}, true)
	if code != 200 || m.stops != 1 || !strings.Contains(hdr.Get("HX-Trigger"), "ok") {
		t.Errorf("stop: %d %d", code, m.stops)
	}
	if au := a.audit(); len(au) != 1 || au[0].Action != api.AuditRolloutStop {
		t.Errorf("audit %+v", au)
	}
	m.err = rollout.ErrNoActive
	if code, body, _ := a.call("POST", "/agents/rollout/stop", url.Values{"confirm": {"yes"}}, true); code != 422 || !strings.Contains(body, "Нет выполняющейся") {
		t.Errorf("no active: %d %s", code, body)
	}
	m.err = nil
	m.cur = active(store.RolloutStopping)
	_, body, _ = a.call("GET", "/agents", nil, true)
	if !strings.Contains(body, "останавливается") || strings.Contains(body, `aria-label="Остановить раскатку"`) {
		t.Error("состояние stopping")
	}
	m.cur = active(store.RolloutDone)
	_, body, _ = a.call("GET", "/agents", nil, true)
	if strings.Contains(body, "ro-banner") {
		t.Error("баннер у завершённой раскатки")
	}
}

func TestRolloutStartFlow(t *testing.T) {
	a := newAgFx(t, agOpts{})
	m := withRollout(a, true)
	_, form, _ := a.call("GET", "/agents/rollout/start", nil, true)
	contains(t, "форма", form, "Обновить отстающие до v1.4.1", "<strong>1</strong>", `name="batch_size"`, `name="allow_downtime"`, "Разрешить простой", "перерыв в проксировании")
	for _, bad := range []string{"0", "abc", "99"} {
		if c, b, _ := a.call("POST", "/agents/rollout/start", url.Values{"batch_size": {bad}}, true); c != 422 || !strings.Contains(b, "field-error") {
			t.Errorf("batch %s: %d", bad, c)
		}
	}
	code, conf, _ := a.call("POST", "/agents/rollout/start", url.Values{"batch_size": {"3"}, "allow_downtime": {"1"}}, true)
	contains(t, "подтверждение", conf, "Запустить раскатку v1.4.1?", `name="batch_size" value="3"`, `name="allow_downtime" value="1"`, `name="confirm" value="yes"`, "Разрешён простой")
	if code != 200 || len(m.started) != 0 {
		t.Fatalf("старт до подтверждения: %d %d", code, len(m.started))
	}
	code, body, hdr := a.call("POST", "/agents/rollout/start", url.Values{"batch_size": {"3"}, "allow_downtime": {"1"}, "confirm": {"yes"}}, true)
	if code != 200 || len(m.started) != 1 || !strings.Contains(hdr.Get("HX-Trigger"), "ok") || !strings.Contains(body, "hx-swap-oob") {
		t.Fatalf("start: %d %d %s", code, len(m.started), body)
	}
	if p := m.started[0]; p.Version != "v1.4.1" || p.BatchSize != 3 || !p.AllowDowntime || p.Actor != "alice" {
		t.Errorf("params %+v", p)
	}
	if au := a.audit(); len(au) != 1 || au[0].Action != api.AuditRolloutStart {
		t.Errorf("audit %+v", au)
	}
	for err, want := range map[error]string{rollout.ErrBusy: "другая раскатка", rollout.ErrNoPackage: "не найден в кэше"} {
		m.err = err
		if code, b, _ := a.call("POST", "/agents/rollout/start", url.Values{"batch_size": {"1"}, "confirm": {"yes"}}, true); code != 422 || !strings.Contains(b, want) {
			t.Errorf("%v: %d %s", err, code, b)
		}
	}
}

func TestSingleAgentUpdate(t *testing.T) {
	a := newAgFx(t, agOpts{})
	m := withRollout(a, true)
	_, conf, _ := a.call("GET", "/agents/hel-1/update", nil, true)
	contains(t, "confirm", conf, "Обновить агент?", `hx-post="/agents/hel-1/update"`)
	if c, _, _ := a.call("POST", "/agents/hel-1/update", nil, true); c != 400 || len(m.started) != 0 {
		t.Fatalf("без confirm: %d", c)
	}
	if c, _, _ := a.call("POST", "/agents/hel-1/update", url.Values{"confirm": {"yes"}}, true); c != 200 || len(m.started) != 1 {
		t.Fatalf("update: %d", c)
	}
	if p := m.started[0]; len(p.Agents) != 1 || p.Agents[0] != "hel-1" || !p.NoCanary {
		t.Errorf("params %+v", p)
	}
	m.err = rollout.ErrAgentDown
	if c, b, _ := a.call("POST", "/agents/hel-1/update", url.Values{"confirm": {"yes"}}, true); c != 422 || !strings.Contains(b, "недоступен") {
		t.Errorf("down: %d %s", c, b)
	}
	if c, _, _ := a.call("GET", "/agents/nope/update", nil, true); c != 404 {
		t.Errorf("unknown: %d", c)
	}
}
