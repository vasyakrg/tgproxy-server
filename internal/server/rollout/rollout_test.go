package rollout

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

func start(t *testing.T, m *Manager, p Params) Status {
	t.Helper()
	if p.Version == "" {
		p.Version = "1.2.0"
	}
	st, err := m.Start(context.Background(), p)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return st
}

func TestSuccessCanaryThenBatches(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2", "a3", "a4", "a5")
	m := newManager(t, f, nil, &alerts{})
	events, cancel := m.Subscribe()
	defer cancel()

	plan := start(t, m, Params{BatchSize: 2, Actor: "admin"})
	phases := map[string]string{}
	for _, s := range plan.Steps {
		phases[s.AgentID] = s.Phase
	}
	if phases["a1"] != store.PhaseCanary || phases["a2"] != store.PhaseBatch || plan.Rollout.Canary != 1 {
		t.Fatalf("план: %+v", plan.Steps)
	}
	st := waitDone(t, m, plan.Rollout.ID)
	if st.Rollout.State != store.RolloutDone || st.Rollout.FinishedAt == nil || st.Rollout.Actor != "admin" {
		t.Fatalf("rollout %+v", st.Rollout)
	}
	for id, s := range stepStates(st) {
		if s != store.StepDone {
			t.Errorf("%s: %s", id, s)
		}
		if f.isDraining(id) {
			t.Errorf("%s остался в drain", id)
		}
		a := f.agent(id)
		if a.ver() != "1.2.0" || a.postCount() != 1 || a.gateway() != "https://gw.example:8444" {
			t.Errorf("%s: version=%s posts=%d gw=%q", id, a.ver(), a.postCount(), a.gateway())
		}
	}
	if d := f.drainOrder(); d[0] != "a1" {
		t.Errorf("первой обновлялась не канарейка: %v", d)
	}
	for _, s := range st.Steps {
		if s.FromVersion != "1.1.0" {
			t.Errorf("%s: from_version = %q", s.AgentID, s.FromVersion)
		}
	}
	var got []string
	for len(events) > 0 {
		ev := <-events
		got = append(got, ev.Kind+":"+ev.State)
	}
	if !slices.Contains(got, "rollout:done") || !slices.Contains(got, "step:running") || !slices.Contains(got, "step:done") {
		t.Errorf("события: %v", got)
	}
}

func TestCanaryFailureLeavesOthersUntouched(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2", "a3")
	f.agent("a1").mode = modeRollback
	al := &alerts{}
	m := newManager(t, f, nil, al)

	st := waitDone(t, m, start(t, m, Params{BatchSize: 2}).Rollout.ID)
	if st.Rollout.State != store.RolloutFailed || !strings.Contains(st.Rollout.Error, "a1") {
		t.Fatalf("rollout %+v", st.Rollout)
	}
	ss := stepStates(st)
	if ss["a1"] != store.StepFailed || ss["a2"] != store.StepPending || ss["a3"] != store.StepPending {
		t.Fatalf("шаги: %v", ss)
	}
	for _, id := range []string{"a2", "a3"} {
		if a := f.agent(id); a.postCount() != 0 || a.ver() != "1.1.0" || f.isDraining(id) || a.statusCount() > 1 {
			t.Errorf("%s тронут: posts=%d version=%s drain=%v status=%d", id, a.postCount(), a.ver(), f.isDraining(id), a.statusCount())
		}
	}
	if f.isDraining("a1") {
		t.Error("канарейка после отката (агент жив на прежней версии) должна вернуться в балансировку")
	}
	if got := al.all(); len(got) != 1 || !strings.HasPrefix(got[0], "a1|1.2.0|") {
		t.Fatalf("алерты: %v", got)
	}
}

func TestBatchFailureStopsRolloutAndAlerts(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2", "a3", "a4", "a5", "a6")
	f.agent("a4").mode = modeRollback // второй батч: a4 откатывается сам
	al := &alerts{}
	m := newManager(t, f, nil, al)

	st := waitDone(t, m, start(t, m, Params{BatchSize: 2}).Rollout.ID)
	if st.Rollout.State != store.RolloutFailed {
		t.Fatalf("rollout %+v", st.Rollout)
	}
	ss := stepStates(st)
	want := map[string]string{
		"a1": store.StepDone, "a2": store.StepDone, "a3": store.StepDone,
		"a4": store.StepFailed, "a5": store.StepDone, // соседа по батчу дожидаемся
		"a6": store.StepPending, // следующий батч не начат
	}
	for id, w := range want {
		if ss[id] != w {
			t.Errorf("%s: %s, want %s", id, ss[id], w)
		}
	}
	if a := f.agent("a6"); a.postCount() != 0 || a.ver() != "1.1.0" {
		t.Errorf("a6 тронут: posts=%d", a.postCount())
	}
	if f.agent("a4").ver() != "1.1.0" || f.isDraining("a4") {
		t.Errorf("a4 должен остаться на прежней версии и вернуться в балансировку")
	}
	if got := al.all(); len(got) != 1 || !strings.HasPrefix(got[0], "a4|1.2.0|") {
		t.Fatalf("алерты: %v", got)
	}
}

func TestRejectedByAgentFailsStep(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2")
	f.agent("a1").mode = modeReject
	m := newManager(t, f, nil, nil)
	st := waitDone(t, m, start(t, m, Params{}).Rollout.ID)
	if st.Rollout.State != store.RolloutFailed || !strings.Contains(st.Steps[0].Error, "422") {
		t.Fatalf("%+v %+v", st.Rollout, st.Steps)
	}
	if f.agent("a2").postCount() != 0 {
		t.Error("a2 не должен трогаться")
	}
}

func TestWaitTimeoutFailsStep(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2")
	f.agent("a1").mode = modeHang
	m := newManager(t, f, nil, nil)
	st := waitDone(t, m, start(t, m, Params{}).Rollout.ID)
	if st.Rollout.State != store.RolloutFailed || !strings.Contains(st.Steps[0].Error, "не вернулся") {
		t.Fatalf("%+v %+v", st.Rollout, st.Steps)
	}
}

func TestUnreachableAfterFailureStaysDrained(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2")
	f.agent("a1").mode = modeHang
	m := newManager(t, f, nil, nil)
	plan := start(t, m, Params{})
	// агент «умер» после команды
	deadline := time.Now().Add(5 * time.Second)
	for f.agent("a1").postCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	f.agent("a1").mu.Lock()
	f.agent("a1").down = true
	f.agent("a1").mu.Unlock()
	st := waitDone(t, m, plan.Rollout.ID)
	if st.Rollout.State != store.RolloutFailed || !f.isDraining("a1") || !strings.Contains(st.Steps[0].Error, "drain") {
		t.Fatalf("%+v %+v drain=%v", st.Rollout, st.Steps, f.isDraining("a1"))
	}
}

func TestRerunIsIdempotent(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2", "a3")
	m := newManager(t, f, nil, nil)
	waitDone(t, m, start(t, m, Params{BatchSize: 2}).Rollout.ID)
	posts := func() int {
		n := 0
		for _, a := range f.agents {
			n += a.postCount()
		}
		return n
	}
	before := posts()

	again := start(t, m, Params{BatchSize: 2})
	if again.Rollout.State != store.RolloutDone || again.Rollout.FinishedAt == nil {
		t.Fatalf("повтор: %+v", again.Rollout)
	}
	for _, s := range again.Steps {
		if s.State != store.StepSkipped {
			t.Errorf("%s: %s, want skipped", s.AgentID, s.State)
		}
	}
	if posts() != before {
		t.Errorf("повторная раскатка отправила команды: %d -> %d", before, posts())
	}
	if n := f.drainCount(); n != 3 {
		t.Errorf("повтор вывел агентов из балансировки: %d", n)
	}
}

func TestPartialRerunSkipsAlreadyUpdated(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2", "a3")
	f.agent("a1").version = "1.2.0" // уже на версии (с префиксом v тоже считается)
	f.agent("a2").version = "v1.2.0"
	m := newManager(t, f, nil, nil)
	st := waitDone(t, m, start(t, m, Params{}).Rollout.ID)
	ss := stepStates(st)
	if ss["a1"] != store.StepSkipped || ss["a2"] != store.StepSkipped || ss["a3"] != store.StepDone {
		t.Fatalf("%v", ss)
	}
	if f.agent("a1").postCount()+f.agent("a2").postCount() != 0 {
		t.Error("агенты на версии получили команду")
	}
	if st.Steps[0].Phase != store.PhaseCanary || st.Steps[0].AgentID != "a3" {
		t.Errorf("канарейка должна быть первым реально обновляемым: %+v", st.Steps)
	}
}

func TestDownAgentsAreSkippedAtPlanning(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2", "a3")
	f.up["a3"] = false
	m := newManager(t, f, nil, nil)
	st := waitDone(t, m, start(t, m, Params{}).Rollout.ID)
	ss := stepStates(st)
	if st.Rollout.State != store.RolloutDone || ss["a1"] != store.StepDone || ss["a2"] != store.StepDone || ss["a3"] != store.StepSkipped {
		t.Fatalf("%+v %v", st.Rollout, ss)
	}
}

func TestStopWaitsForCurrentAndStartsNoNew(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2", "a3", "a4")
	gate := make(chan struct{})
	f.agent("a2").gate = gate
	f.agent("a2").started = make(chan struct{})
	m := newManager(t, f, nil, nil)
	plan := start(t, m, Params{BatchSize: 1})

	select {
	case <-f.agent("a2").started:
	case <-time.After(5 * time.Second):
		t.Fatal("a2 не начал обновление")
	}
	cur, err := m.Stop(context.Background())
	if err != nil || cur.Rollout.State != store.RolloutStopping {
		t.Fatalf("Stop: %+v %v", cur.Rollout, err)
	}
	if a, err := m.Current(context.Background()); err != nil || a.Rollout.State != store.RolloutStopping {
		t.Fatalf("Current: %+v %v", a.Rollout, err)
	}
	if _, err := m.Start(context.Background(), Params{Version: "1.2.0"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("Start во время остановки: %v", err)
	}
	close(gate) // текущий агент дорабатывает
	st := waitDone(t, m, plan.Rollout.ID)
	ss := stepStates(st)
	if st.Rollout.State != store.RolloutStopped || ss["a1"] != store.StepDone || ss["a2"] != store.StepDone ||
		ss["a3"] != store.StepPending || ss["a4"] != store.StepPending {
		t.Fatalf("%+v %v", st.Rollout, ss)
	}
	if f.agent("a3").postCount() != 0 || f.agent("a4").postCount() != 0 {
		t.Error("после Stop начаты новые агенты")
	}
	if _, err := m.Stop(context.Background()); !errors.Is(err, ErrNoActive) {
		t.Errorf("повторный Stop: %v", err)
	}
}

func TestSecondStartWhileRunningIsBusy(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2")
	gate := make(chan struct{})
	f.agent("a1").gate = gate
	f.agent("a1").started = make(chan struct{})
	m := newManager(t, f, nil, nil)
	plan := start(t, m, Params{})
	<-f.agent("a1").started
	if _, err := m.Start(context.Background(), Params{Version: "1.2.0"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	close(gate)
	waitDone(t, m, plan.Rollout.ID)
}

func TestSingleAgentRequiresOtherActiveAgent(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1")
	m := newManager(t, f, nil, nil)
	st := waitDone(t, m, start(t, m, Params{}).Rollout.ID)
	if st.Rollout.State != store.RolloutFailed || !strings.Contains(st.Steps[0].Error, "нет другого активного") || f.agent("a1").postCount() != 0 {
		t.Fatalf("%+v %+v", st.Rollout, st.Steps)
	}
	// С явным разрешением простоя — обновляется.
	st = waitDone(t, m, start(t, m, Params{AllowDowntime: true}).Rollout.ID)
	if st.Rollout.State != store.RolloutDone || f.agent("a1").ver() != "1.2.0" {
		t.Fatalf("%+v", st.Rollout)
	}
}

func TestOnlyOneOfTwoDrainedWhenBatchIsLarge(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2", "a3")
	m := newManager(t, f, nil, nil)
	// канарейка a1 + батч из a2,a3 размера 5: a2 и a3 одновременно, но a1 уже на новой версии и активна.
	st := waitDone(t, m, start(t, m, Params{BatchSize: 5}).Rollout.ID)
	if st.Rollout.State != store.RolloutDone {
		t.Fatalf("%+v %+v", st.Rollout, st.Steps)
	}
}

func TestUpdateOneAgentNoCanary(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2")
	m := newManager(t, f, nil, nil)
	plan := start(t, m, Params{Agents: []string{"a2"}, NoCanary: true})
	if len(plan.Steps) != 1 || plan.Steps[0].AgentID != "a2" || plan.Rollout.Canary != 0 {
		t.Fatalf("%+v", plan)
	}
	waitDone(t, m, plan.Rollout.ID)
	if f.agent("a1").postCount() != 0 || f.agent("a2").ver() != "1.2.0" {
		t.Error("обновлён не тот агент")
	}
	if _, err := m.Start(context.Background(), Params{Version: "1.2.0", Agents: []string{"ghost"}}); !errors.Is(err, ErrUnknownAgent) {
		t.Errorf("ghost: %v", err)
	}
	f.up["a1"] = false
	if _, err := m.Start(context.Background(), Params{Version: "1.2.1", Agents: []string{"a1"}}); !errors.Is(err, ErrNoPackage) {
		t.Errorf("нет пакета: %v", err)
	}
}

func TestStartValidation(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1")
	m := newManager(t, f, nil, nil)
	for name, tc := range map[string]struct {
		p   Params
		err error
	}{
		"версия":       {Params{Version: "../x"}, ErrBadVersion},
		"пустая":       {Params{}, ErrBadVersion},
		"нет пакета":   {Params{Version: "9.9.9"}, ErrNoPackage},
		"большой батч": {Params{Version: "1.2.0", BatchSize: 1000}, ErrBadParams},
		"минус":        {Params{Version: "1.2.0", BatchSize: -1}, ErrBadParams},
	} {
		if _, err := m.Start(context.Background(), tc.p); !errors.Is(err, tc.err) {
			t.Errorf("%s: %v, want %v", name, err, tc.err)
		}
	}
	if _, err := New(Config{}); err == nil {
		t.Error("New без зависимостей должен отказать")
	}
}

func TestRecoverMarksInterruptedRollout(t *testing.T) {
	f := newFakes(t, "1.1.0", "a1", "a2")
	st := memtest.New()
	ctx := context.Background()
	err := st.Rollouts().Create(ctx, store.Rollout{ID: "r1", Version: "1.2.0", BatchSize: 1, State: store.RolloutRunning}, []store.RolloutStep{
		{AgentID: "a1", Seq: 1, Phase: store.PhaseCanary, State: store.StepRunning},
		{AgentID: "a2", Seq: 2, Phase: store.PhaseBatch, State: store.StepPending},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := newManager(t, f, st, nil)
	if err := m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	cur, err := m.Current(ctx)
	if err != nil || cur.Rollout.State != store.RolloutFailed || cur.Steps[0].State != store.StepFailed || cur.Steps[1].State != store.StepPending {
		t.Fatalf("%+v %v", cur, err)
	}
	if _, err := m.Start(ctx, Params{Version: "1.2.0"}); err != nil {
		t.Fatalf("после Recover новая раскатка должна стартовать: %v", err)
	}
}

func TestCurrentWithoutRollouts(t *testing.T) {
	m := newManager(t, newFakes(t, "1.1.0", "a1"), nil, nil)
	if _, err := m.Current(context.Background()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// reverse/both-агент берёт релиз со своего server_url: сервер gateway_url ему не передаёт.
func TestGatewayURLSentOnlyToDialAgents(t *testing.T) {
	f := newFakes(t, "1.1.0", "d1", "r1")
	f.agent("r1").reverse = true
	m := newManager(t, f, nil, nil)
	waitDone(t, m, start(t, m, Params{}).Rollout.ID)
	d, r := f.agent("d1"), f.agent("r1")
	d.mu.Lock()
	r.mu.Lock()
	defer d.mu.Unlock()
	defer r.mu.Unlock()
	if !d.sentGW || d.gwURL != "https://gw.example:8444" || r.sentGW || r.posts != 1 {
		t.Fatalf("dial: sent=%v url=%q; reverse: sent=%v posts=%d", d.sentGW, d.gwURL, r.sentGW, r.posts)
	}
}
