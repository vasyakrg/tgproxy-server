package history

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Outcome — итог запроса для метрик.
type Outcome int

// Итоги запроса.
const (
	OutcomeOK       Outcome = iota // успех
	OutcomeProxyErr                // ошибка прокси/агента (dial, tls, timeout…) → Sample.Err
	OutcomeTG429                   // Telegram ответил 429 → Sample.RateLimited
	OutcomeTGErr                   // Telegram ответил 4xx/5xx (кроме 429): прокси отработал → считается в Sample.OK
)

type acc struct {
	ok, perr, r429 atomic.Int64
	buckets        []atomic.Int64
	inflight       atomic.Int64 // текущее значение (гауж)
	inflightMax    atomic.Int64 // максимум за интервал
}

func newAcc() *acc { return &acc{buckets: make([]atomic.Int64, NumBuckets())} }

type window struct{ agents map[string]*acc }

// Collector — потокобезопасный приёмник событий горячего пути. БД не трогает.
// Hot path держит RLock + атомики; Drain берёт Lock, поэтому снимок целостный.
type Collector struct {
	mu sync.RWMutex
	w  *window
}

// NewCollector создаёт пустой сборщик.
func NewCollector() *Collector { return &Collector{w: &window{agents: map[string]*acc{}}} }

func (c *Collector) with(agent string, f func(a *acc)) {
	c.mu.RLock()
	if a, ok := c.w.agents[agent]; ok {
		f(a)
		c.mu.RUnlock()
		return
	}
	c.mu.RUnlock()
	c.mu.Lock()
	a, ok := c.w.agents[agent]
	if !ok {
		a = newAcc()
		c.w.agents[agent] = a
	}
	f(a)
	c.mu.Unlock()
}

// ObserveRequest учитывает завершённый запрос. Long-poll (getUpdates) не попадает в
// гистограмму латентности — иначе p95 всегда равен таймауту long-poll.
func (c *Collector) ObserveRequest(agent string, outcome Outcome, latency time.Duration, longPoll bool) {
	c.with(agent, func(a *acc) {
		switch outcome {
		case OutcomeOK, OutcomeTGErr:
			a.ok.Add(1)
		case OutcomeProxyErr:
			a.perr.Add(1)
		case OutcomeTG429:
			a.r429.Add(1)
		default:
			return
		}
		if !longPoll {
			a.buckets[bucketIndex(latency)].Add(1)
		}
	})
}

// SetInflight выставляет текущее число запросов в полёте на агенте.
func (c *Collector) SetInflight(agent string, n int) {
	c.with(agent, func(a *acc) {
		v := int64(max(n, 0))
		a.inflight.Store(v)
		for {
			m := a.inflightMax.Load()
			if v <= m || a.inflightMax.CompareAndSwap(m, v) {
				return
			}
		}
	})
}

// Drain атомарно забирает накопленное за интервал и обнуляет счётчики. Возвращает
// по строке на агента плюс агрегат AggregateID (всегда, даже при нулевом трафике).
// Sample.At не заполняется — это делает Sampler. Простаивающие агенты в следующее
// окно не переносятся; текущий inflight переносится.
func (c *Collector) Drain() []store.Sample {
	c.mu.Lock()
	old := c.w
	next := &window{agents: map[string]*acc{}}
	for id, a := range old.agents {
		if cur := a.inflight.Load(); cur > 0 {
			n := newAcc()
			n.inflight.Store(cur)
			n.inflightMax.Store(cur)
			next.agents[id] = n
		}
	}
	c.w = next
	c.mu.Unlock()

	ids := make([]string, 0, len(old.agents))
	for id := range old.agents {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	total := store.Sample{AgentID: AggregateID, Buckets: make([]int64, NumBuckets())}
	out := make([]store.Sample, 0, len(ids)+1)
	for _, id := range ids {
		a := old.agents[id]
		s := store.Sample{
			AgentID: id, OK: a.ok.Load(), Err: a.perr.Load(), RateLimited: a.r429.Load(),
			Inflight: int(a.inflightMax.Load()), Buckets: make([]int64, NumBuckets()),
		}
		for i := range a.buckets {
			s.Buckets[i] = a.buckets[i].Load()
		}
		s.P95Ms = P95(s.Buckets)
		if s.OK+s.Err+s.RateLimited == 0 && s.Inflight == 0 {
			continue
		}
		total.OK += s.OK
		total.Err += s.Err
		total.RateLimited += s.RateLimited
		total.Inflight += s.Inflight
		total.Buckets = addBuckets(total.Buckets, s.Buckets)
		out = append(out, s)
	}
	total.P95Ms = P95(total.Buckets)
	return append(out, total)
}
