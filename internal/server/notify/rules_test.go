package notify

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

func st(id string, up bool, s *transport.AgentStatus) agents.State {
	return agents.State{Agent: store.Agent{ID: id}, Up: up, LastStatus: s, LastSeen: time.Unix(1, 0)}
}

func newEval(reg Registry, al Alerter, mut ...func(*EvalOptions)) (*Evaluator, *fakeClock) {
	c := newClock()
	o := EvalOptions{Registry: reg, Alerter: al, Clock: c.Now, Version: "1.2.3"}
	for _, m := range mut {
		m(&o)
	}
	return NewEvaluator(o), c
}

func TestEvaluateThresholds(t *testing.T) {
	c := newClock()
	healthy := &transport.AgentStatus{Version: "1.2.3", Inflight: 1, CertNotAfter: c.Now().Add(90 * 24 * time.Hour)}
	bad := &transport.AgentStatus{Version: "0.9", Inflight: 500, CertNotAfter: c.Now().Add(24 * time.Hour)}
	reg := newFakeRegistry(st("ok", true, healthy), st("bad", true, bad))
	al := &fakeAlerter{}
	ev, _ := newEval(reg, al, func(o *EvalOptions) { o.Clock = c.Now })
	ev.Evaluate(context.Background())

	got := map[string]bool{}
	for _, a := range al.fired {
		got[a.Key+"|"+a.AgentID] = true
		if a.AgentID == "ok" {
			t.Fatalf("healthy agent fired %s", a.Type)
		}
	}
	for _, ty := range []AlertType{Overload, CertExpiring, VersionMismatch} {
		if !got["|bad"] && !slices.Contains(al.firedTypes(), ty) {
			t.Fatalf("%s not fired", ty)
		}
	}
	if len(al.fired) != 3 {
		t.Fatalf("fired %v", al.firedTypes())
	}
	if al.flushes != 1 {
		t.Fatal("Evaluate must flush")
	}
	// healthy resolve-ы вызываются для ok
	if !slices.Contains(al.resolved, "overload:ok") || !slices.Contains(al.resolved, "version_mismatch:ok") {
		t.Fatalf("resolved = %v", al.resolved)
	}
}

func TestDegradedNeedsMinRequests(t *testing.T) {
	reg := newFakeRegistry(st("a", true, &transport.AgentStatus{}))
	al := &fakeAlerter{}
	ev, _ := newEval(reg, al, func(o *EvalOptions) { o.Errors = fakeErrRates{1.0, 5} })
	ev.Evaluate(context.Background())
	if slices.Contains(al.firedTypes(), AgentDegraded) || slices.Contains(al.resolved, "agent_degraded:a") {
		t.Fatalf("few requests must not change state: fired=%v resolved=%v", al.firedTypes(), al.resolved)
	}
	ev.o.Errors = fakeErrRates{0.01, 1000}
	ev.Evaluate(context.Background())
	if !slices.Contains(al.resolved, "agent_degraded:a") {
		t.Fatal("low error rate must resolve")
	}
	ev.o.Errors = fakeErrRates{0.2, 1000}
	ev.Evaluate(context.Background())
	if !slices.Contains(al.firedTypes(), AgentDegraded) {
		t.Fatal("high rate must fire")
	}
}

func TestDownAgentSkipsThresholds(t *testing.T) {
	reg := newFakeRegistry(st("a", false, &transport.AgentStatus{Inflight: 9999}), st("b", true, &transport.AgentStatus{}))
	al := &fakeAlerter{}
	ev, _ := newEval(reg, al)
	ev.Evaluate(context.Background())
	if slices.Contains(al.firedTypes(), Overload) {
		t.Fatal("down agent must be skipped")
	}
}

func TestEventsAndAllDown(t *testing.T) {
	ctx := context.Background()
	a := st("a", false, nil)
	b := st("b", true, nil)
	reg := newFakeRegistry(a, b)
	al := &fakeAlerter{}
	ev, _ := newEval(reg, al)

	ev.HandleEvent(ctx, agents.Event{Type: agents.AgentDown, AgentID: "a", At: time.Now()})
	if !slices.Equal(al.firedTypes(), []AlertType{AgentDown}) {
		t.Fatalf("fired %v", al.firedTypes())
	}
	if !slices.Contains(al.resolved, "all_agents_down") {
		t.Fatal("not all down: must resolve all_agents_down")
	}
	al.reset()
	reg.set(a, st("b", false, nil))
	ev.HandleEvent(ctx, agents.Event{Type: agents.AgentDown, AgentID: "b"})
	if !slices.Contains(al.firedTypes(), AllAgentsDown) {
		t.Fatalf("all_agents_down not fired: %v", al.firedTypes())
	}
	al.reset()
	reg.set(st("a", true, nil), st("b", false, nil))
	ev.HandleEvent(ctx, agents.Event{Type: agents.AgentUp, AgentID: "a"})
	if !slices.Contains(al.resolved, "agent_down:a") {
		t.Fatalf("resolved %v", al.resolved)
	}
	al.reset()
	ev.HandleEvent(ctx, agents.Event{Type: agents.AgentRemoved, AgentID: "b"})
	if !slices.Contains(al.resolved, "agent_down:b") {
		t.Fatal("removed must resolve agent_down")
	}
	al.reset()
	ev.HandleEvent(ctx, agents.Event{Type: agents.AgentAdded, AgentID: "c"})
	if len(al.fired)+len(al.resolved) != 0 {
		t.Fatal("added/draining are ignored")
	}
}

func TestAllDownIgnoresNeverPolled(t *testing.T) {
	fresh := agents.State{Agent: store.Agent{ID: "a"}}
	reg := newFakeRegistry(fresh)
	al := &fakeAlerter{}
	ev, _ := newEval(reg, al)
	ev.Evaluate(context.Background())
	if len(al.fired) != 0 {
		t.Fatalf("startup false alarm: %v", al.firedTypes())
	}
	reg.set(agents.State{Agent: store.Agent{ID: "a"}, ConsecutiveFails: 2})
	ev.Evaluate(context.Background())
	if !slices.Contains(al.firedTypes(), AllAgentsDown) {
		t.Fatal("failed polls → all down")
	}
	reg.set()
	al.reset()
	ev.Evaluate(context.Background())
	if len(al.fired) != 0 {
		t.Fatal("no agents → no all_agents_down")
	}
}

func TestPublicReporters(t *testing.T) {
	ctx := context.Background()
	al := &fakeAlerter{}
	ev, c := newEval(newFakeRegistry(), al)

	ev.ReportIngressCert(ctx, c.Now().Add(100*24*time.Hour), nil)
	if len(al.fired) != 0 || !slices.Contains(al.resolved, "ingress_cert_invalid") || !slices.Contains(al.resolved, "ingress_cert_expiring") {
		t.Fatalf("fired %v resolved %v", al.firedTypes(), al.resolved)
	}
	ev.ReportIngressCert(ctx, c.Now().Add(3*24*time.Hour), errors.New("key mismatch "+testToken))
	types := al.firedTypes()
	if !slices.Contains(types, IngressCertInvalid) || !slices.Contains(types, IngressCertExpiring) {
		t.Fatalf("fired %v", types)
	}
	if tokenRe.MatchString(al.fired[0].Text) {
		t.Fatal("token leaked into alert text")
	}
	al.reset()
	ev.ReportIngressCert(ctx, time.Time{}, nil) // срок неизвестен

	ev.LoginLockout(ctx, "admin", "1.2.3.4")
	ev.HostKeyMismatch(ctx, "fra-1", "10.0.0.1")
	ev.AgentEnrolled(ctx, "ams-2")
	want := []AlertType{LoginLockout, HostKeyMismatch, AgentEnrolled}
	if !slices.Equal(al.firedTypes(), want) {
		t.Fatalf("fired %v", al.firedTypes())
	}
	if al.fired[0].Key != "login_lockout:admin" {
		t.Fatalf("key %s", al.fired[0].Key)
	}
}

type errAlerter struct{}

func (*errAlerter) Fire(context.Context, Alert) error     { return errors.New("db") }
func (*errAlerter) Resolve(context.Context, string) error { return errors.New("db") }
func (*errAlerter) Flush(context.Context) error           { return errors.New("db") }

func TestAlerterErrorsAreLogged(*testing.T) {
	reg := newFakeRegistry(st("a", true, &transport.AgentStatus{Inflight: 9999}))
	ev, _ := newEval(reg, &errAlerter{})
	ev.Evaluate(context.Background()) // не паникует
}

func TestRunProcessesEventsAndTicks(t *testing.T) {
	reg := newFakeRegistry(st("a", true, &transport.AgentStatus{Version: "1.2.3", Inflight: 9999}))
	al := &fakeAlerter{}
	tick := make(chan time.Time)
	ev, _ := newEval(reg, al, func(o *EvalOptions) {
		o.Tick = func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ev.Run(ctx); close(done) }()
	reg.ch <- agents.Event{Type: agents.AgentDown, AgentID: "a"}
	for deadline := time.Now().Add(5 * time.Second); !slices.Contains(al.firedTypes(), AgentDown) && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	tick <- time.Now()
	cancel()
	<-done
	al.mu.Lock()
	defer al.mu.Unlock()
	var down, over bool
	for _, a := range al.fired {
		down = down || a.Type == AgentDown
		over = over || a.Type == Overload
	}
	if !down || !over {
		t.Fatalf("down=%v overload=%v", down, over)
	}
}

func TestRunStopsOnClosedEvents(t *testing.T) {
	reg := newFakeRegistry()
	close(reg.ch)
	ev, _ := newEval(reg, &fakeAlerter{})
	done := make(chan struct{})
	go func() { ev.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run must stop when events close")
	}
}

func TestDefaultsAndHumanLeft(t *testing.T) {
	ev := NewEvaluator(EvalOptions{Registry: newFakeRegistry(), Alerter: &fakeAlerter{}})
	if ev.o.Version == "" || ev.o.Interval == 0 || ev.o.Tick == nil {
		t.Fatal("defaults")
	}
	ch, stop := ev.o.Tick(time.Hour)
	if ch == nil {
		t.Fatal("tick")
	}
	stop()
	for d, want := range map[time.Duration]string{-time.Hour: "уже истёк", 5 * time.Hour: "5 ч", 72 * time.Hour: "3 дн"} {
		if humanLeft(d) != want {
			t.Fatalf("%v → %s", d, humanLeft(d))
		}
	}
}

func TestEvaluatorWithRealNotifierDedups(t *testing.T) {
	n, s, c := newNotifier(t)
	reg := newFakeRegistry(st("a", true, &transport.AgentStatus{Inflight: 9999}))
	ev := NewEvaluator(EvalOptions{Registry: reg, Alerter: n, Clock: c.Now})
	for range 5 {
		ev.Evaluate(context.Background())
		c.Add(30 * time.Second)
	}
	if got := len(pending(t, s)); got != 1 {
		t.Fatalf("overload deduped to %d items, want 1", got)
	}
}
