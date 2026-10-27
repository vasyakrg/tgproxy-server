package notify

import (
	"context"
	"slices"
	"testing"
	"time"
)

func mtpEval(t *testing.T) (*Evaluator, *fakeAlerter, *fakeClock) {
	t.Helper()
	al := &fakeAlerter{}
	ev, c := newEval(newFakeRegistry(), al)
	return ev, al, c
}

func agentDC(id string, up map[int]bool) MTProtoAgent { return MTProtoAgent{ID: id, DCUp: up} }

func firedKeys(al *fakeAlerter) []string {
	var out []string
	for _, a := range al.fired {
		out = append(out, a.key())
	}
	return out
}

func TestMTProtoDCUnreachableAfterMinute(t *testing.T) {
	ev, al, c := mtpEval(t)
	ctx := context.Background()
	snap := MTProtoSnapshot{Enabled: true, Agents: []MTProtoAgent{agentDC("a", map[int]bool{2: false}), agentDC("b", map[int]bool{2: false})}}
	ev.ObserveMTProto(ctx, snap)
	c.Add(time.Minute)
	ev.ObserveMTProto(ctx, snap)
	if len(al.fired) != 0 {
		t.Fatalf("fired before >1m: %v", firedKeys(al))
	}
	c.Add(time.Second)
	ev.ObserveMTProto(ctx, snap)
	if !slices.Equal(firedKeys(al), []string{"mtproto_dc_unreachable:dc2"}) {
		t.Fatalf("fired = %v", firedKeys(al))
	}
}

func TestMTProtoDCRecoveryOnOneAgentResolves(t *testing.T) {
	ev, al, c := mtpEval(t)
	ctx := context.Background()
	down := MTProtoSnapshot{Enabled: true, Agents: []MTProtoAgent{agentDC("a", map[int]bool{2: false}), agentDC("b", map[int]bool{2: false})}}
	ev.ObserveMTProto(ctx, down)
	c.Add(2 * time.Minute)
	ev.ObserveMTProto(ctx, down)
	al.reset()
	up := MTProtoSnapshot{Enabled: true, Agents: []MTProtoAgent{agentDC("a", map[int]bool{2: false}), agentDC("b", map[int]bool{2: true})}}
	ev.ObserveMTProto(ctx, up)
	if !slices.Contains(al.resolved, "mtproto_dc_unreachable:dc2") {
		t.Fatalf("resolved = %v", al.resolved)
	}
	// флап сбрасывает отсчёт: снова down — через минуту не стреляет
	c.Add(time.Second)
	ev.ObserveMTProto(ctx, down)
	c.Add(30 * time.Second)
	ev.ObserveMTProto(ctx, down)
	if len(al.fired) != 0 {
		t.Fatalf("fired after flap: %v", firedKeys(al))
	}
}

func TestMTProtoDCDownOnlyOnSomeAgentsNoAlert(t *testing.T) {
	ev, al, c := mtpEval(t)
	ctx := context.Background()
	snap := MTProtoSnapshot{Enabled: true, Agents: []MTProtoAgent{agentDC("a", map[int]bool{2: false}), agentDC("b", map[int]bool{2: true})}}
	ev.ObserveMTProto(ctx, snap)
	c.Add(10 * time.Minute)
	ev.ObserveMTProto(ctx, snap)
	if len(al.fired) != 0 {
		t.Fatalf("fired = %v", firedKeys(al))
	}
}

func TestMTProtoDCKeysPerDC(t *testing.T) {
	ev, al, c := mtpEval(t)
	ctx := context.Background()
	snap := MTProtoSnapshot{Enabled: true, Agents: []MTProtoAgent{agentDC("a", map[int]bool{1: false, 2: true, 3: false})}}
	ev.ObserveMTProto(ctx, snap)
	c.Add(2 * time.Minute)
	ev.ObserveMTProto(ctx, snap)
	if !slices.Equal(firedKeys(al), []string{"mtproto_dc_unreachable:dc1", "mtproto_dc_unreachable:dc3"}) {
		t.Fatalf("fired = %v", firedKeys(al))
	}
}

func TestMTProtoNoCapableAgents(t *testing.T) {
	ev, al, _ := mtpEval(t)
	ctx := context.Background()
	ev.ObserveMTProto(ctx, MTProtoSnapshot{Enabled: true})
	if !slices.Contains(al.firedTypes(), MTProtoNoCapableAgents) {
		t.Fatalf("fired = %v", al.firedTypes())
	}
	al.reset()
	ev.ObserveMTProto(ctx, MTProtoSnapshot{Enabled: true, Agents: []MTProtoAgent{agentDC("a", nil)}})
	if len(al.fired) != 0 || !slices.Contains(al.resolved, "mtproto_no_capable_agents") {
		t.Fatalf("fired=%v resolved=%v", al.fired, al.resolved)
	}
}

func TestMTProtoDisabledNoFiringAndResolves(t *testing.T) {
	ev, al, c := mtpEval(t)
	ctx := context.Background()
	ev.ObserveMTProto(ctx, MTProtoSnapshot{Enabled: false, ActiveConns: 100, MaxConns: 10})
	c.Add(time.Hour)
	ev.ObserveMTProto(ctx, MTProtoSnapshot{Enabled: false, ActiveConns: 100, MaxConns: 10})
	if len(al.fired) != 0 {
		t.Fatalf("fired = %v", al.firedTypes())
	}
	if !slices.Contains(al.resolved, "mtproto_no_capable_agents") || !slices.Contains(al.resolved, "mtproto_overload") {
		t.Fatalf("resolved = %v", al.resolved)
	}
}

func TestMTProtoOverload(t *testing.T) {
	ev, al, c := mtpEval(t)
	ctx := context.Background()
	ags := []MTProtoAgent{agentDC("a", nil)}
	hot := MTProtoSnapshot{Enabled: true, Agents: ags, ActiveConns: 91, MaxConns: 100}
	ev.ObserveMTProto(ctx, hot)
	c.Add(4 * time.Minute)
	ev.ObserveMTProto(ctx, hot)
	if len(al.fired) != 0 {
		t.Fatalf("fired early: %v", al.firedTypes())
	}
	c.Add(time.Minute)
	ev.ObserveMTProto(ctx, hot)
	if !slices.Equal(al.firedTypes(), []AlertType{MTProtoOverload}) {
		t.Fatalf("fired = %v", al.firedTypes())
	}
	al.reset()
	ev.ObserveMTProto(ctx, MTProtoSnapshot{Enabled: true, Agents: ags, ActiveConns: 50, MaxConns: 100})
	if !slices.Contains(al.resolved, "mtproto_overload") {
		t.Fatalf("resolved = %v", al.resolved)
	}
}

func TestMTProtoOverloadExactly90NotFiring(t *testing.T) {
	ev, al, c := mtpEval(t)
	ctx := context.Background()
	snap := MTProtoSnapshot{Enabled: true, Agents: []MTProtoAgent{agentDC("a", nil)}, ActiveConns: 90, MaxConns: 100}
	ev.ObserveMTProto(ctx, snap)
	c.Add(time.Hour)
	ev.ObserveMTProto(ctx, snap)
	if len(al.fired) != 0 {
		t.Fatalf("fired = %v", al.firedTypes())
	}
}

func TestMTProtoOverloadDipResetsTimer(t *testing.T) {
	ev, al, c := mtpEval(t)
	ctx := context.Background()
	ags := []MTProtoAgent{agentDC("a", nil)}
	hot := MTProtoSnapshot{Enabled: true, Agents: ags, ActiveConns: 95, MaxConns: 100}
	ev.ObserveMTProto(ctx, hot)
	c.Add(4 * time.Minute)
	ev.ObserveMTProto(ctx, MTProtoSnapshot{Enabled: true, Agents: ags, ActiveConns: 10, MaxConns: 100})
	c.Add(2 * time.Minute)
	ev.ObserveMTProto(ctx, hot)
	if len(al.fired) != 0 {
		t.Fatalf("fired = %v", al.firedTypes())
	}
}

// Дедуп и лимиты общие: повторный Fire через настоящий Notifier не плодит сообщений.
func TestMTProtoAlertsDedupViaNotifier(t *testing.T) {
	n, s, c := newNotifier(t)
	ev := NewEvaluator(EvalOptions{Registry: newFakeRegistry(), Alerter: n, Clock: c.Now})
	ctx := context.Background()
	for range 3 {
		ev.ObserveMTProto(ctx, MTProtoSnapshot{Enabled: true})
		c.Add(time.Minute)
	}
	if got := len(pending(t, s)); got != 1 {
		t.Fatalf("pending = %d, want 1", got)
	}
	ev.ObserveMTProto(ctx, MTProtoSnapshot{Enabled: true, Agents: []MTProtoAgent{agentDC("a", nil)}})
	if got := all(t, s, "mtproto_no_capable_agents"); got.State != "resolved" {
		t.Fatalf("state = %s", got.State)
	}
}
