package balancer

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func seq(vals ...uint64) func() uint64 {
	i := 0
	return func() uint64 {
		v := vals[i%len(vals)]
		i++
		return v
	}
}

var bg = context.Background()

func newClocked() (*Balancer, *fakeClock) {
	fc := &fakeClock{t: time.Unix(1000, 0)}
	return New(WithClock(fc.Now)), fc
}

func TestP2CPicksLowerScore(t *testing.T) {
	b := New(WithRand(seq(0, 0))) // i=0 (a), j=0 -> 1 (b)
	b.Update([]Candidate{{"a", 1}, {"b", 1}})
	// нагружаем "a" двумя in-flight, чтобы score выше
	b.agents["a"].inflight = 2
	id, rel, err := b.Pick(bg, nil)
	if err != nil || id != "b" {
		t.Fatalf("want b, got %q err=%v", id, err)
	}
	rel(Result{Latency: 100 * time.Millisecond})
	// теперь нагружаем b сильнее
	b.agents["a"].inflight = 0
	b.agents["b"].inflight = 5
	id, rel, _ = b.Pick(bg, nil)
	if id != "a" {
		t.Fatalf("want a, got %q", id)
	}
	rel(Result{})
}

func TestScoreUsesEWMA(t *testing.T) {
	b := New(WithRand(seq(0, 0)))
	b.Update([]Candidate{{"a", 1}, {"b", 1}})
	b.agents["a"].ewma.Observe(500 * time.Millisecond)
	b.agents["b"].ewma.Observe(10 * time.Millisecond)
	id, _, _ := b.Pick(bg, nil)
	if id != "b" {
		t.Fatalf("want b, got %s", id)
	}
}

// Один медленный запрос не должен навсегда выключать агента из P2C: пока
// агент простаивает, его оценка затухает к дефолту и он снова выбирается.
func TestIdleEWMADecaysBackIntoRotation(t *testing.T) {
	now := time.Unix(1000, 0)
	b := New(WithRand(seq(0, 0)), WithClock(func() time.Time { return now }))
	b.Update([]Candidate{{"a", 1}, {"b", 1}})
	b.agents["a"].ewma.ObserveAt(900*time.Millisecond, now)
	b.agents["b"].ewma.ObserveAt(250*time.Millisecond, now)
	if id, _, _ := b.Pick(bg, nil); id != "b" {
		t.Fatalf("сразу после медленного запроса want b, got %s", id)
	}
	// b продолжает работать на 250ms, a простаивает 30s.
	now = now.Add(30 * time.Second)
	b.agents["b"].ewma.ObserveAt(250*time.Millisecond, now)
	if id, _, _ := b.Pick(bg, nil); id != "a" {
		t.Fatalf("после простоя want a, got %s", id)
	}
	if v := b.agents["a"].ewma.ValueAt(now); v > 0.15 {
		t.Fatalf("оценка a не затухла: %.3fs", v)
	}
}

func TestExclude(t *testing.T) {
	b := New()
	b.Update([]Candidate{{"a", 1}, {"b", 1}})
	for range 50 {
		id, rel, err := b.Pick(bg, []AgentID{"a"})
		if err != nil || id != "b" {
			t.Fatalf("got %q %v", id, err)
		}
		rel(Result{})
	}
	if _, _, err := b.Pick(bg, []AgentID{"a", "b"}); !errors.Is(err, ErrNoHealthyAgents) {
		t.Fatalf("want ErrNoHealthyAgents, got %v", err)
	}
}

func TestZeroWeightAndFlags(t *testing.T) {
	b := New()
	b.Update([]Candidate{{"a", 0}, {"b", 1}, {"c", 1}})
	b.SetHealthy("c", false)
	for range 20 {
		id, rel, err := b.Pick(bg, nil)
		if err != nil || id != "b" {
			t.Fatalf("got %q %v", id, err)
		}
		rel(Result{})
	}
	b.SetDraining("b", true)
	if _, _, err := b.Pick(bg, nil); !errors.Is(err, ErrNoHealthyAgents) {
		t.Fatalf("want ErrNoHealthyAgents, got %v", err)
	}
	b.SetDraining("b", false)
	b.SetHealthy("c", true)
	b.SetHealthy("nope", true) // не паникует
	b.SetDraining("nope", true)
	if _, _, err := b.Pick(bg, nil); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyAndCanceledCtx(t *testing.T) {
	b := New()
	if _, _, err := b.Pick(bg, nil); !errors.Is(err, ErrNoHealthyAgents) {
		t.Fatalf("got %v", err)
	}
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, _, err := b.Pick(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestSingleCandidate(t *testing.T) {
	b := New(WithRand(func() uint64 { panic("rand must not be used") }))
	b.Update([]Candidate{{"only", 3}})
	id, rel, err := b.Pick(bg, nil)
	if err != nil || id != "only" {
		t.Fatalf("got %q %v", id, err)
	}
	rel(Result{})
}

func TestLongPollAndCanceledDoNotChangeEWMA(t *testing.T) {
	b := New()
	b.Update([]Candidate{{"a", 1}})
	a := b.agents["a"]
	before := a.ewma.Value()

	_, rel, _ := b.Pick(bg, nil)
	rel(Result{Latency: 50 * time.Second, LongPoll: true})
	if a.ewma.Value() != before {
		t.Fatal("long-poll changed EWMA")
	}
	_, rel, _ = b.Pick(bg, nil)
	rel(Result{Latency: 50 * time.Second, Canceled: true})
	if a.ewma.Value() != before {
		t.Fatal("canceled changed EWMA")
	}
	_, rel, _ = b.Pick(bg, nil)
	rel(Result{Latency: 200 * time.Millisecond})
	if a.ewma.Value() == before {
		t.Fatal("normal result must change EWMA")
	}
	if a.inflight != 0 {
		t.Fatalf("inflight=%d", a.inflight)
	}
}

func TestEWMAMath(t *testing.T) {
	var e ewma
	if e.Value() != defaultEWMALatency.Seconds() {
		t.Fatal("default")
	}
	e.Observe(100 * time.Millisecond)
	e.Observe(200 * time.Millisecond)
	want := 0.3*0.2 + 0.7*0.1
	if d := e.Value() - want; d > 1e-9 || d < -1e-9 {
		t.Fatalf("got %v want %v", e.Value(), want)
	}
	e.Observe(-time.Second)
	if e.Value() < 0 {
		t.Fatal("negative")
	}
}

func TestReleaseIdempotent(t *testing.T) {
	b := New()
	b.Update([]Candidate{{"a", 1}})
	_, rel, _ := b.Pick(bg, nil)
	_, rel2, _ := b.Pick(bg, nil)
	rel(Result{})
	rel(Result{})
	if b.agents["a"].inflight != 1 {
		t.Fatalf("inflight=%d", b.agents["a"].inflight)
	}
	rel2(Result{})
}

func failN(t *testing.T, b *Balancer, n int) {
	t.Helper()
	for range n {
		_, rel, err := b.Pick(bg, nil)
		if err != nil {
			t.Fatal(err)
		}
		rel(Result{TransportError: true})
	}
}

func TestBreakerFourErrorsThenSuccess(t *testing.T) {
	b, _ := newClocked()
	b.Update([]Candidate{{"a", 1}})
	failN(t, b, 4)
	_, rel, err := b.Pick(bg, nil)
	if err != nil {
		t.Fatal(err)
	}
	rel(Result{})
	failN(t, b, 4) // счётчик сброшен успехом
	if _, _, err := b.Pick(bg, nil); err != nil {
		t.Fatal(err)
	}
}

func TestBreakerOpensAfterFive(t *testing.T) {
	b, fc := newClocked()
	b.Update([]Candidate{{"a", 1}})
	failN(t, b, 5)
	if _, _, err := b.Pick(bg, nil); !errors.Is(err, ErrNoHealthyAgents) {
		t.Fatalf("want open breaker, got %v", err)
	}
	fc.Advance(29 * time.Second)
	if _, _, err := b.Pick(bg, nil); !errors.Is(err, ErrNoHealthyAgents) {
		t.Fatal("still open at 29s")
	}
	fc.Advance(time.Second)
	if _, _, err := b.Pick(bg, nil); err != nil {
		t.Fatalf("half-open at 30s: %v", err)
	}
}

func TestBreakerHalfOpenSingleProbe(t *testing.T) {
	b, fc := newClocked()
	b.Update([]Candidate{{"a", 1}})
	failN(t, b, 5)
	fc.Advance(30 * time.Second)

	_, probe, err := b.Pick(bg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Pick(bg, nil); !errors.Is(err, ErrNoHealthyAgents) {
		t.Fatalf("second probe must be refused, got %v", err)
	}
	probe(Result{}) // успех -> closed
	for range 3 {
		if _, rel, err := b.Pick(bg, nil); err != nil {
			t.Fatal(err)
		} else {
			rel(Result{})
		}
	}
}

func TestBreakerHalfOpenFailureReopens(t *testing.T) {
	b, fc := newClocked()
	b.Update([]Candidate{{"a", 1}})
	failN(t, b, 5)
	fc.Advance(30 * time.Second)
	_, probe, _ := b.Pick(bg, nil)
	probe(Result{TransportError: true})
	if _, _, err := b.Pick(bg, nil); !errors.Is(err, ErrNoHealthyAgents) {
		t.Fatal("must be open again")
	}
	fc.Advance(30 * time.Second)
	if _, _, err := b.Pick(bg, nil); err != nil {
		t.Fatal(err)
	}
}

func TestBreakerHalfOpenCanceledFreesProbe(t *testing.T) {
	b, fc := newClocked()
	b.Update([]Candidate{{"a", 1}})
	failN(t, b, 5)
	fc.Advance(30 * time.Second)
	_, probe, _ := b.Pick(bg, nil)
	probe(Result{Canceled: true})
	if _, _, err := b.Pick(bg, nil); err != nil {
		t.Fatalf("probe must be available again: %v", err)
	}
}

func TestBreakerLateResultsWhileOpenIgnored(t *testing.T) {
	b, fc := newClocked()
	b.Update([]Candidate{{"a", 1}})
	_, late1, _ := b.Pick(bg, nil)
	_, late2, _ := b.Pick(bg, nil)
	failN(t, b, 5)
	late1(Result{})                     // success в open — игнор
	late2(Result{TransportError: true}) // failure в open — игнор
	late2(Result{Canceled: true})       // cancel вне half-open — noop
	fc.Advance(30 * time.Second)
	if _, _, err := b.Pick(bg, nil); err != nil {
		t.Fatalf("openedAt must not be extended: %v", err)
	}
}

func TestUpdateKeepsStateAndRemoves(t *testing.T) {
	b := New()
	b.Update([]Candidate{{"a", 1}, {"b", 1}})
	b.SetHealthy("a", false)
	b.Update([]Candidate{{"a", 5}})
	if b.agents["a"].healthy || b.agents["a"].weight != 5 {
		t.Fatal("state lost")
	}
	if _, ok := b.agents["b"]; ok {
		t.Fatal("b must be removed")
	}
	// release для удалённого агента не паникует
	b.Update([]Candidate{{"b", 1}})
	_, rel, _ := b.Pick(bg, nil)
	b.Update(nil)
	rel(Result{})
}

func TestDistributionEqual(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	b := New(WithRand(r.Uint64))
	b.Update([]Candidate{{"a", 1}, {"b", 1}, {"c", 1}, {"d", 1}})
	for _, a := range b.agents {
		// Одинаковая стартовая оценка ровно 10ms и одинаковое время наблюдения:
		// иначе микроскопическая разница решала бы все ничьи P2C.
		a.ewma.value, a.ewma.init, a.ewma.last = (10 * time.Millisecond).Seconds(), true, time.Now()
	}
	const n = 10000
	cnt := map[AgentID]int{}
	for range n {
		id, rel, err := b.Pick(bg, nil)
		if err != nil {
			t.Fatal(err)
		}
		cnt[id]++
		rel(Result{Latency: 10 * time.Millisecond})
	}
	exp := float64(n) / 4
	for id, c := range cnt {
		if d := (float64(c) - exp) / exp; d > 0.05 || d < -0.05 {
			t.Fatalf("%s: %d deviates %.1f%%", id, c, d*100)
		}
	}
}

func TestDistributionWeights(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	b := New(WithRand(r.Uint64))
	b.Update([]Candidate{{"a", 2}, {"b", 1}})
	cnt := map[AgentID]int{}
	for range 3000 { // без release: inflight растёт пропорционально весу
		id, _, err := b.Pick(bg, nil)
		if err != nil {
			t.Fatal(err)
		}
		cnt[id]++
	}
	ratio := float64(cnt["a"]) / float64(cnt["b"])
	if ratio < 1.8 || ratio > 2.2 {
		t.Fatalf("ratio %.2f (%v)", ratio, cnt)
	}
}

func TestConcurrentRace(_ *testing.T) {
	b := New()
	b.Update([]Candidate{{"a", 1}, {"b", 2}, {"c", 1}})
	var wg sync.WaitGroup
	for g := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				id, rel, err := b.Pick(bg, nil)
				if err != nil {
					continue
				}
				rel(Result{Latency: time.Millisecond, TransportError: (g+i)%17 == 0, LongPoll: i%11 == 0})
				if i%50 == 0 {
					b.SetHealthy(id, i%100 != 0)
					b.Update([]Candidate{{"a", 1}, {"b", 2}, {"c", 1}})
				}
			}
		}()
	}
	wg.Wait()
}
