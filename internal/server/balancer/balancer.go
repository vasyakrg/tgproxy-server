// Package balancer реализует выбор агента: P2C + EWMA задержки + circuit breaker.
package balancer

import (
	"context"
	"math/rand/v2"
	"sort"
	"sync"
	"time"
)

// AgentID — идентификатор агента.
type AgentID = string

// Candidate — агент и его вес от реестра.
type Candidate struct {
	ID     AgentID
	Weight int
}

// Result — исход запроса, передаётся в release.
type Result struct {
	Latency        time.Duration
	TransportError bool // ошибка транспорта агента (ответы Telegram 4xx/5xx/429 — нет)
	LongPoll       bool // не обновляет EWMA
	Canceled       bool // отмена клиентом: не влияет ни на EWMA, ни на breaker
}

type agentState struct {
	weight   int
	healthy  bool
	draining bool
	inflight int
	ewma     ewma
	br       breaker
}

// Balancer выбирает агента по P2C.
type Balancer struct {
	mu     sync.Mutex
	agents map[AgentID]*agentState
	rnd    func() uint64
	clock  func() time.Time
}

// Option настраивает Balancer.
type Option func(*Balancer)

// WithRand задаёт источник случайных чисел (для детерминированных тестов).
func WithRand(f func() uint64) Option {
	return func(b *Balancer) {
		if f != nil {
			b.rnd = f
		}
	}
}

// WithClock задаёт источник времени.
func WithClock(f func() time.Time) Option {
	return func(b *Balancer) {
		if f != nil {
			b.clock = f
		}
	}
}

// New создаёт балансировщик.
func New(opts ...Option) *Balancer {
	b := &Balancer{
		agents: make(map[AgentID]*agentState),
		rnd:    rand.Uint64,
		clock:  time.Now,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Update синхронизирует набор агентов и веса; состояние сохранившихся агентов не сбрасывается.
func (b *Balancer) Update(cands []Candidate) {
	b.mu.Lock()
	defer b.mu.Unlock()
	next := make(map[AgentID]*agentState, len(cands))
	for _, c := range cands {
		a, ok := b.agents[c.ID]
		if !ok {
			a = &agentState{healthy: true}
		}
		a.weight = c.Weight
		next[c.ID] = a
	}
	b.agents = next
}

// SetHealthy задаёт health агента (неизвестный ID игнорируется).
func (b *Balancer) SetHealthy(id AgentID, healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if a, ok := b.agents[id]; ok {
		a.healthy = healthy
	}
}

// SetDraining включает/выключает draining (неизвестный ID игнорируется).
func (b *Balancer) SetDraining(id AgentID, draining bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if a, ok := b.agents[id]; ok {
		a.draining = draining
	}
}

func (a *agentState) score(now time.Time) float64 {
	return float64(a.inflight+1) * a.ewma.ValueAt(now) / float64(a.weight)
}

// Pick выбирает агента, исключая exclude. release нужно вызвать ровно один раз
// (повторные вызовы игнорируются).
func (b *Balancer) Pick(ctx context.Context, exclude []AgentID) (AgentID, func(Result), error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.clock()
	ids := make([]AgentID, 0, len(b.agents))
	for id, a := range b.agents {
		if a.eligible(now) && !contains(exclude, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return "", nil, ErrNoHealthyAgents
	}
	sort.Strings(ids) // детерминированный порядок для воспроизводимого rand

	chosen := ids[0]
	if n := len(ids); n > 1 {
		i := randIndex(b.rnd(), n)
		j := randIndex(b.rnd(), n-1)
		if j >= i {
			j++
		}
		chosen = ids[i]
		if b.agents[ids[j]].score(now) < b.agents[ids[i]].score(now) {
			chosen = ids[j]
		}
	}

	a := b.agents[chosen]
	a.inflight++
	a.br.acquire(now)

	var once sync.Once
	release := func(r Result) {
		once.Do(func() { b.release(a, r) })
	}
	return chosen, release, nil
}

func (b *Balancer) release(a *agentState, r Result) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.inflight > 0 {
		a.inflight--
	}
	switch {
	case r.Canceled:
		a.br.cancel()
	case r.TransportError:
		a.br.failure(b.clock())
	default:
		if !r.LongPoll {
			a.ewma.ObserveAt(r.Latency, b.clock())
		}
		a.br.success()
	}
}

func contains(s []AgentID, id AgentID) bool {
	for _, v := range s {
		if v == id {
			return true
		}
	}
	return false
}

// randIndex возвращает индекс в [0, n) без небезопасного преобразования типов.
func randIndex(r uint64, n int) int {
	return int(r % uint64(n)) //nolint:gosec // n > 0, результат < n
}
