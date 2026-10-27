package mtproto

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

type recMR struct {
	mu       sync.Mutex
	conns    []string
	sessions []time.Duration
	hs       []string
	ft       int
}

func (r *recMR) MTProtoConnection(s, res string) {
	r.mu.Lock()
	r.conns = append(r.conns, s+":"+res)
	r.mu.Unlock()
}
func (r *recMR) MTProtoSession(d time.Duration) {
	r.mu.Lock()
	r.sessions = append(r.sessions, d)
	r.mu.Unlock()
}
func (r *recMR) MTProtoHandshakeFailure(s string) { r.mu.Lock(); r.hs = append(r.hs, s); r.mu.Unlock() }
func (r *recMR) MTProtoFallthrough()              { r.mu.Lock(); r.ft++; r.mu.Unlock() }

type fixedNames map[int64]string

func (f fixedNames) SecretName(id int64) (string, bool) { n, ok := f[id]; return n, ok }

func TestMetricsObserverLifecycle(t *testing.T) {
	rec := &recMR{}
	o := NewMetricsObserver(rec, fixedNames{1: "alice"})
	now := time.Unix(100, 0)
	o.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.9")

	o.Start(1, "s1", ip)
	o.ConnectedToDC(1, "s1", 2)
	o.ConnectedToDC(1, "s1", 4) // повтор не считается
	o.Traffic(1, "s1", 10, true)
	now = now.Add(3 * time.Second)
	o.Finish(1, "s1")

	o.Start(9, "s2", ip) // неизвестный секрет, до DC не дошёл
	o.Finish(9, "s2")
	o.Finish(9, "s2") // повторный Finish игнорируется

	if got := rec.conns; len(got) != 2 || got[0] != "alice:ok" || got[1] != "unknown:closed" {
		t.Fatalf("conns = %v", got)
	}
	if len(rec.sessions) != 2 || rec.sessions[0] != 3*time.Second {
		t.Fatalf("sessions = %v", rec.sessions)
	}
	if len(o.live) != 0 {
		t.Fatalf("live leak: %d", len(o.live))
	}
}

type hookReason string

func TestMetricsObserverHooks(t *testing.T) {
	rec := &recMR{}
	o := NewMetricsObserver(rec, nil)
	h := RejectHook[hookReason](o)
	h(netip.Addr{}, "handshake_timeout")
	h(netip.Addr{}, "conn_limit")
	o.Fallthrough()
	if len(rec.hs) != 2 || rec.hs[0] != "timeout" || rec.hs[1] != "conn_limit" || rec.ft != 1 {
		t.Fatalf("hs=%v ft=%d", rec.hs, rec.ft)
	}
}

type seqObs struct {
	name string
	log  *[]string
}

func (s seqObs) Start(int64, string, netip.Addr)   { *s.log = append(*s.log, s.name+".start") }
func (s seqObs) ConnectedToDC(int64, string, int)  { *s.log = append(*s.log, s.name+".dc") }
func (s seqObs) Traffic(int64, string, uint, bool) { *s.log = append(*s.log, s.name+".traffic") }
func (s seqObs) Finish(int64, string)              { *s.log = append(*s.log, s.name+".finish") }

func TestMultiObserver(t *testing.T) {
	if MultiObserver() != nil || MultiObserver(nil, nil) != nil {
		t.Fatal("пустой набор должен давать nil")
	}
	var log []string
	a, b := seqObs{"a", &log}, seqObs{"b", &log}
	if got := MultiObserver(nil, a); got != Observer(a) {
		t.Fatal("один наблюдатель возвращается как есть")
	}
	m := MultiObserver(a, nil, b)
	m.Start(1, "s", netip.Addr{})
	m.ConnectedToDC(1, "s", 2)
	m.Traffic(1, "s", 1, true)
	m.Finish(1, "s")
	want := []string{"a.start", "b.start", "a.dc", "b.dc", "a.traffic", "b.traffic", "a.finish", "b.finish"}
	if len(log) != len(want) {
		t.Fatalf("log = %v", log)
	}
	for i := range want {
		if log[i] != want[i] {
			t.Fatalf("log = %v", log)
		}
	}
}
