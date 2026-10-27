package balancer

import (
	"context"
	"errors"
	"math/rand/v2"
	"sort"
	"sync"
	"time"
)

// ErrNoCandidates — для DC нет ни одного пригодного агента.
var ErrNoCandidates = errors.New("balancer: no candidates for dc")

// DCState — результат пробы DC на агенте.
type DCState struct {
	Up  bool
	RTT time.Duration
}

// KeyedCandidate — агент и его состояние для Keyed-балансировщика.
// Health, draining и weight относятся к агенту целиком; DC — к ключу (agent, dc).
type KeyedCandidate struct {
	ID       AgentID
	Weight   int
	Healthy  bool
	Draining bool
	Capable  bool // агент объявил нужную capability (mtproto/1)
	// DC — состояние DC по номеру. Отсутствие записи = состояние неизвестно:
	// агент для такого DC не выбирается.
	DC map[int]DCState
}

type keyID struct {
	agent AgentID
	dc    int
}

// keyState — состояние пары (agent, dc): стримы, EWMA и breaker изолированы по ключу.
type keyState struct {
	inflight int
	ewma     ewma
	br       breaker
	observed bool // EWMA получила реальное наблюдение (RTT пробы больше не перезасевает)
}

type keyedAgent struct {
	weight   int
	healthy  bool
	draining bool
	capable  bool
	dc       map[int]DCState
}

// Keyed выбирает агента для DC: P2C по score = (streams+1)×EWMA/weight.
type Keyed struct {
	mu     sync.Mutex
	agents map[AgentID]*keyedAgent
	keys   map[keyID]*keyState
	rnd    func() uint64
	clock  func() time.Time
}

// KeyedOption настраивает Keyed.
type KeyedOption func(*Keyed)

// WithKeyedRand задаёт источник случайных чисел (для детерминированных тестов).
func WithKeyedRand(f func() uint64) KeyedOption {
	return func(k *Keyed) {
		if f != nil {
			k.rnd = f
		}
	}
}

// WithKeyedClock задаёт источник времени.
func WithKeyedClock(f func() time.Time) KeyedOption {
	return func(k *Keyed) {
		if f != nil {
			k.clock = f
		}
	}
}

// NewKeyed создаёт Keyed-балансировщик.
func NewKeyed(opts ...KeyedOption) *Keyed {
	k := &Keyed{
		agents: make(map[AgentID]*keyedAgent),
		keys:   make(map[keyID]*keyState),
		rnd:    rand.Uint64,
		clock:  time.Now,
	}
	for _, o := range opts {
		o(k)
	}
	return k
}

// Update синхронизирует набор агентов. Состояние ключей сохраняется, пока агент
// есть в списке; EWMA ключа, на котором ещё не было трафика, засевается RTT пробы.
func (k *Keyed) Update(cands []KeyedCandidate) {
	k.mu.Lock()
	defer k.mu.Unlock()
	next := make(map[AgentID]*keyedAgent, len(cands))
	for _, c := range cands {
		dc := make(map[int]DCState, len(c.DC))
		for n, st := range c.DC {
			dc[n] = st
		}
		next[c.ID] = &keyedAgent{
			weight: c.Weight, healthy: c.Healthy, draining: c.Draining,
			capable: c.Capable, dc: dc,
		}
		for n, st := range dc {
			if st.Up && st.RTT > 0 {
				ks := k.keyLocked(keyID{c.ID, n})
				if !ks.observed {
					ks.ewma.seed(st.RTT)
				}
			}
		}
	}
	for id := range k.keys {
		if _, ok := next[id.agent]; !ok {
			delete(k.keys, id)
		}
	}
	k.agents = next
}

func (k *Keyed) keyLocked(id keyID) *keyState {
	ks, ok := k.keys[id]
	if !ok {
		ks = &keyState{}
		k.keys[id] = ks
	}
	return ks
}

func (a *keyedAgent) eligible(dc int) bool {
	if !a.healthy || a.draining || !a.capable || a.weight <= 0 {
		return false
	}
	st, ok := a.dc[dc]
	return ok && st.Up
}

// Lease — захваченный стрим на ключе (agent, dc).
type Lease struct {
	k     *Keyed
	ks    *keyState
	agent AgentID
	rep   sync.Once
	rel   sync.Once
	done  bool // исход зарегистрирован (под k.mu)
}

// Agent возвращает выбранного агента.
func (l *Lease) Agent() AgentID { return l.agent }

// Report фиксирует исход открытия стрима: Latency — время до 200 для EWMA,
// TransportError — для breaker ключа. Не освобождает стрим. Повторные вызовы
// игнорируются.
func (l *Lease) Report(r Result) {
	l.rep.Do(func() {
		k := l.k
		k.mu.Lock()
		defer k.mu.Unlock()
		l.done = true
		now := k.clock()
		switch {
		case r.Canceled:
			l.ks.br.cancel()
		case r.TransportError:
			l.ks.br.failure(now)
		default:
			if !r.LongPoll {
				l.ks.ewma.ObserveAt(r.Latency, now)
				l.ks.observed = true
			}
			l.ks.br.success()
		}
	})
}

// Release уменьшает inflight (вызывать при закрытии стрима, а не при открытии).
// Если исход не был зарегистрирован, он считается отменой. Идемпотентен.
func (l *Lease) Release() {
	l.rel.Do(func() {
		k := l.k
		k.mu.Lock()
		if l.ks.inflight > 0 {
			l.ks.inflight--
		}
		pending := !l.done
		k.mu.Unlock()
		if pending {
			l.Report(Result{Canceled: true})
		}
	})
}

// Pick выбирает агента для dc по P2C, исключая exclude. Нужно вызвать Release.
func (k *Keyed) Pick(ctx context.Context, dc int, exclude ...AgentID) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	now := k.clock()
	type cand struct {
		id AgentID
		ks *keyState
		a  *keyedAgent
	}
	cs := make([]cand, 0, len(k.agents))
	for id, a := range k.agents {
		if !a.eligible(dc) || contains(exclude, id) {
			continue
		}
		ks := k.keyLocked(keyID{id, dc})
		if !ks.br.available(now) {
			continue
		}
		cs = append(cs, cand{id, ks, a})
	}
	if len(cs) == 0 {
		return nil, ErrNoCandidates
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].id < cs[j].id })

	score := func(c cand) float64 {
		return float64(c.ks.inflight+1) * c.ks.ewma.ValueAt(now) / float64(c.a.weight)
	}
	chosen := cs[0]
	if n := len(cs); n > 1 {
		i := randIndex(k.rnd(), n)
		j := randIndex(k.rnd(), n-1)
		if j >= i {
			j++
		}
		chosen = cs[i]
		if score(cs[j]) < score(cs[i]) {
			chosen = cs[j]
		}
	}
	chosen.ks.inflight++
	chosen.ks.br.acquire(now)
	return &Lease{k: k, ks: chosen.ks, agent: chosen.id}, nil
}
