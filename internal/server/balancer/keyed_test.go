package balancer

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"
	"time"
)

func kc(id string, w int, dcs ...int) KeyedCandidate {
	m := map[int]DCState{}
	for _, d := range dcs {
		m[d] = DCState{Up: true, RTT: 50 * time.Millisecond}
	}
	return KeyedCandidate{ID: id, Weight: w, Healthy: true, Capable: true, DC: m}
}

func pickAgent(t *testing.T, k *Keyed, dc int, ex ...string) string {
	t.Helper()
	l, err := k.Pick(bg, dc, ex...)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	return l.Agent()
}

func TestKeyedIncapableNotPicked(t *testing.T) {
	k := NewKeyed()
	a := kc("a", 1, 2)
	a.Capable = false
	k.Update([]KeyedCandidate{a, kc("b", 1, 2)})
	for i := 0; i < 50; i++ {
		if got := pickAgent(t, k, 2); got != "b" {
			t.Fatalf("got %s", got)
		}
	}
	k.Update([]KeyedCandidate{a})
	if _, err := k.Pick(bg, 2); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("err=%v", err)
	}
}

func TestKeyedDCDownOnlyForThatDC(t *testing.T) {
	k := NewKeyed()
	a := kc("a", 1, 2, 4)
	a.DC[2] = DCState{Up: false}
	k.Update([]KeyedCandidate{a})
	if _, err := k.Pick(bg, 2); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("dc2: %v", err)
	}
	if got := pickAgent(t, k, 4); got != "a" {
		t.Fatalf("dc4 got %s", got)
	}
	if _, err := k.Pick(bg, 5); !errors.Is(err, ErrNoCandidates) { // неизвестный DC
		t.Fatalf("dc5: %v", err)
	}
}

func TestKeyedAgentFlags(t *testing.T) {
	for name, mut := range map[string]func(*KeyedCandidate){
		"unhealthy": func(c *KeyedCandidate) { c.Healthy = false },
		"draining":  func(c *KeyedCandidate) { c.Draining = true },
		"weight0":   func(c *KeyedCandidate) { c.Weight = 0 },
	} {
		k := NewKeyed()
		a := kc("a", 1, 2)
		mut(&a)
		k.Update([]KeyedCandidate{a, kc("b", 1, 2)})
		for i := 0; i < 20; i++ {
			if got := pickAgent(t, k, 2); got != "b" {
				t.Fatalf("%s: got %s", name, got)
			}
		}
	}
}

func TestKeyedExclude(t *testing.T) {
	k := NewKeyed()
	k.Update([]KeyedCandidate{kc("a", 1, 2), kc("b", 1, 2)})
	if got := pickAgent(t, k, 2, "a"); got != "b" {
		t.Fatalf("got %s", got)
	}
	if _, err := k.Pick(bg, 2, "a", "b"); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("err=%v", err)
	}
}

func TestKeyedCtxCanceled(t *testing.T) {
	k := NewKeyed()
	k.Update([]KeyedCandidate{kc("a", 1, 2)})
	ctx, cancel := ctxCancel()
	cancel()
	if _, err := k.Pick(ctx, 2); err == nil {
		t.Fatal("want ctx error")
	}
}

func TestKeyedEWMASeededFromRTT(t *testing.T) {
	k := NewKeyed()
	a := kc("a", 1, 2)
	a.DC[2] = DCState{Up: true, RTT: 300 * time.Millisecond}
	k.Update([]KeyedCandidate{a})
	ks := k.keys[keyID{"a", 2}]
	if v := ks.ewma.Value(); v < 0.299 || v > 0.301 {
		t.Fatalf("seed=%v", v)
	}
	// обновление RTT до трафика перезасевает
	a.DC[2] = DCState{Up: true, RTT: 100 * time.Millisecond}
	k.Update([]KeyedCandidate{a})
	if v := ks.ewma.Value(); v < 0.099 || v > 0.101 {
		t.Fatalf("reseed=%v", v)
	}
	// после реального наблюдения RTT пробы не затирает EWMA
	l, _ := k.Pick(bg, 2)
	l.Report(Result{Latency: 10 * time.Millisecond})
	l.Release()
	before := ks.ewma.Value()
	a.DC[2] = DCState{Up: true, RTT: 900 * time.Millisecond}
	k.Update([]KeyedCandidate{a})
	if ks.ewma.Value() != before {
		t.Fatal("seed overwrote observed ewma")
	}
}

func TestKeyedSeedPrefersFasterDC(t *testing.T) {
	k := NewKeyed(WithKeyedRand(seq(0, 0)))
	a, b := kc("a", 1, 2), kc("b", 1, 2)
	a.DC[2] = DCState{Up: true, RTT: 400 * time.Millisecond}
	b.DC[2] = DCState{Up: true, RTT: 20 * time.Millisecond}
	k.Update([]KeyedCandidate{a, b})
	if got := pickAgent(t, k, 2); got != "b" {
		t.Fatalf("got %s", got)
	}
}

func TestKeyedScoreInflightAndWeight(t *testing.T) {
	k := NewKeyed(WithKeyedRand(seq(0, 0)))
	k.Update([]KeyedCandidate{kc("a", 1, 2), kc("b", 1, 2)})
	k.keys[keyID{"a", 2}].inflight = 3
	if got := pickAgent(t, k, 2); got != "b" {
		t.Fatalf("inflight: got %s", got)
	}
	k.keys[keyID{"a", 2}].inflight = 0
	k.keys[keyID{"b", 2}].inflight = 1 // score b = 2x; вес a=1, b=4 → b: 2/4 < a: 1
	k.Update([]KeyedCandidate{kc("a", 1, 2), kc("b", 4, 2)})
	if got := pickAgent(t, k, 2); got != "b" {
		t.Fatalf("weight: got %s", got)
	}
}

func TestKeyedDistributionProportionalToWeight(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	k := NewKeyed(WithKeyedRand(r.Uint64))
	k.Update([]KeyedCandidate{kc("a", 1, 2), kc("b", 3, 2)})
	cnt := map[string]int{}
	for i := 0; i < 10000; i++ {
		l, err := k.Pick(bg, 2)
		if err != nil {
			t.Fatal(err)
		}
		cnt[l.Agent()]++ // стримы не закрываются: inflight растёт
	}
	ratio := float64(cnt["b"]) / float64(cnt["a"])
	if ratio < 2.6 || ratio > 3.4 {
		t.Fatalf("ratio=%v cnt=%v", ratio, cnt)
	}
}

func TestKeyedBreakerIsolatedPerKey(t *testing.T) {
	fc := &fakeClock{t: time.Unix(1000, 0)}
	k := NewKeyed(WithKeyedClock(fc.Now))
	b := New(WithClock(fc.Now))
	b.Update([]Candidate{{"a", 1}})
	k.Update([]KeyedCandidate{kc("a", 1, 2, 4)})
	for i := 0; i < breakerThreshold; i++ {
		l, err := k.Pick(bg, 2)
		if err != nil {
			t.Fatal(err)
		}
		l.Report(Result{TransportError: true})
		l.Release()
	}
	if _, err := k.Pick(bg, 2); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("dc2 must be open: %v", err)
	}
	if got := pickAgent(t, k, 4); got != "a" {
		t.Fatal("dc4 affected")
	}
	if _, _, err := b.Pick(bg, nil); err != nil {
		t.Fatalf("bot api affected: %v", err)
	}
	// half-open после таймаута
	fc.Advance(breakerOpenFor)
	l, err := k.Pick(bg, 2)
	if err != nil {
		t.Fatalf("half-open: %v", err)
	}
	l.Report(Result{Latency: time.Millisecond})
	l.Release()
	if got := pickAgent(t, k, 2); got != "a" {
		t.Fatal("not closed")
	}
}

func TestKeyedReleaseDecrementsOnceAndDefaultsToCancel(t *testing.T) {
	k := NewKeyed()
	k.Update([]KeyedCandidate{kc("a", 1, 2)})
	l, _ := k.Pick(bg, 2)
	ks := k.keys[keyID{"a", 2}]
	l.Report(Result{Latency: time.Millisecond})
	if ks.inflight != 1 {
		t.Fatal("Report must not release")
	}
	l.Report(Result{TransportError: true}) // игнорируется
	l.Release()
	l.Release()
	if ks.inflight != 0 || ks.br.fails != 0 {
		t.Fatalf("inflight=%d fails=%d", ks.inflight, ks.br.fails)
	}
	l2, _ := k.Pick(bg, 2)
	l2.Release() // без Report = отмена
	if ks.inflight != 0 || ks.br.fails != 0 || ks.observed && ks.ewma.Value() > 0.5 {
		t.Fatal("cancel affected state")
	}
}

func TestKeyedCanceledAndLongPollSkipEWMA(t *testing.T) {
	k := NewKeyed()
	k.Update([]KeyedCandidate{kc("a", 1, 2)})
	ks := k.keys[keyID{"a", 2}]
	before := ks.ewma.Value()
	l, _ := k.Pick(bg, 2)
	l.Report(Result{Canceled: true, Latency: time.Hour})
	l.Release()
	l, _ = k.Pick(bg, 2)
	l.Report(Result{LongPoll: true, Latency: time.Hour})
	l.Release()
	if ks.ewma.Value() != before {
		t.Fatal("ewma changed")
	}
}

func TestKeyedUpdateKeepsStateAndDropsRemoved(t *testing.T) {
	k := NewKeyed()
	k.Update([]KeyedCandidate{kc("a", 1, 2), kc("b", 1, 2)})
	l, _ := k.Pick(bg, 2, "b")
	k.Update([]KeyedCandidate{kc("a", 2, 2)})
	if k.keys[keyID{"a", 2}].inflight != 1 {
		t.Fatal("state lost")
	}
	if _, ok := k.keys[keyID{"b", 2}]; ok {
		t.Fatal("removed agent key kept")
	}
	l.Release() // после удаления/обновления безопасно
}

func TestKeyedConcurrent(t *testing.T) {
	k := NewKeyed()
	k.Update([]KeyedCandidate{kc("a", 1, 2), kc("b", 1, 2)})
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 500; i++ {
				l, err := k.Pick(bg, 2)
				if err != nil {
					continue
				}
				l.Report(Result{Latency: time.Millisecond})
				l.Release()
				if i%100 == 0 {
					k.Update([]KeyedCandidate{kc("a", 1, 2), kc("b", 1, 2)})
				}
			}
		}()
	}
	for g := 0; g < 8; g++ {
		<-done
	}
	for id, ks := range k.keys {
		if ks.inflight != 0 {
			t.Fatalf("%v inflight=%d", id, ks.inflight)
		}
	}
}

func ctxCancel() (context.Context, context.CancelFunc) { return context.WithCancel(bg) }
