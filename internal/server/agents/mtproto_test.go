package agents

import (
	"context"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

func TestMTProtoViewAndCandidate(t *testing.T) {
	s := State{Agent: store.Agent{ID: "a", Weight: 3}, Up: true, LastStatus: &transport.AgentStatus{
		Capabilities: []string{transport.CapMTProto},
		MTProto: &transport.MTProtoStatus{DC: map[string]transport.DCStatus{
			"2": {Up: true, RTTMs: 12.5}, "x": {Up: true}, "4": {Up: false},
		}},
	}}
	c := s.KeyedCandidate()
	if !c.Capable || !c.Healthy || c.Weight != 3 || len(c.DC) != 2 {
		t.Fatalf("%+v", c)
	}
	if c.DC[2] != (balancer.DCState{Up: true, RTT: 12500 * time.Microsecond}) || c.DC[4].Up {
		t.Fatalf("%+v", c.DC)
	}
	if ok, dc := (State{}).MTProtoView(); ok || dc != nil {
		t.Fatal("no status")
	}
	old := State{LastStatus: &transport.AgentStatus{Capabilities: []string{"x"}}}
	if ok, dc := old.MTProtoView(); ok || dc != nil {
		t.Fatal("old agent")
	}
}

func TestMTProtoChanged(t *testing.T) {
	mk := func(caps []string, m *transport.MTProtoStatus) *transport.AgentStatus {
		return &transport.AgentStatus{Capabilities: caps, MTProto: m}
	}
	dc := func(up bool, rtt float64, streams int) *transport.MTProtoStatus {
		return &transport.MTProtoStatus{Streams: streams, DC: map[string]transport.DCStatus{"2": {Up: up, RTTMs: rtt}}}
	}
	cp := []string{transport.CapMTProto}
	cases := []struct {
		name     string
		old, cur *transport.AgentStatus
		want     bool
	}{
		{"old agent unchanged", mk(nil, nil), mk(nil, nil), false},
		{"nil old, no mtproto", nil, mk(nil, nil), false},
		{"caps appear", mk(nil, nil), mk(cp, dc(true, 1, 0)), true},
		{"streams only", mk(cp, dc(true, 1, 0)), mk(cp, dc(true, 1, 9)), false},
		{"dc down", mk(cp, dc(true, 1, 0)), mk(cp, dc(false, 1, 0)), true},
		{"rtt", mk(cp, dc(true, 1, 0)), mk(cp, dc(true, 2, 0)), true},
		{"section vanished", mk(cp, dc(true, 1, 0)), mk(cp, nil), true},
		{"dc set size", mk(cp, dc(true, 1, 0)), mk(cp, &transport.MTProtoStatus{DC: map[string]transport.DCStatus{}}), true},
		{"dc key differs", mk(cp, dc(true, 1, 0)), mk(cp, &transport.MTProtoStatus{DC: map[string]transport.DCStatus{"4": {Up: true, RTTMs: 1}}}), true},
	}
	for _, c := range cases {
		if got := mtprotoChanged(c.old, c.cur); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestPollPublishesMTProtoEventOnlyOnChange(t *testing.T) {
	e := newEnv(t, "a1")
	ch, cancel := e.reg.Subscribe()
	defer cancel()
	e.poll("a1")
	drain(ch) // AgentUp
	set := func(up bool, streams int) {
		e.reg.status = func(context.Context, transport.AgentRef) (*transport.AgentStatus, error) {
			return &transport.AgentStatus{Capabilities: []string{transport.CapMTProto},
				MTProto: &transport.MTProtoStatus{Streams: streams, DC: map[string]transport.DCStatus{"2": {Up: up, RTTMs: 5}}}}, nil
		}
	}
	count := func() int {
		n := 0
		for _, ev := range drain(ch) {
			if ev.Type == AgentMTProto {
				n++
			}
		}
		return n
	}
	set(true, 0)
	e.poll("a1")
	if count() != 1 {
		t.Fatal("first status with mtproto must publish")
	}
	set(true, 7)
	e.poll("a1")
	if count() != 0 {
		t.Fatal("streams-only change must not publish")
	}
	set(false, 7)
	e.poll("a1")
	if count() != 1 {
		t.Fatal("dc down must publish")
	}
	s, _ := e.reg.Get("a1")
	if c, dc := s.MTProtoView(); !c || dc[2].Up {
		t.Fatalf("view: %v %v", c, dc)
	}
}
