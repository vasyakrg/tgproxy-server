// Package agents — реестр агентов сервера: состав из store.AgentRepo,
// рантайм-состояние (up/down/draining), активный опрос статуса, пассивный
// health по трафику и синхронизация с балансировщиком (architecture §4, §9).
package agents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Параметры по умолчанию (architecture §4).
const (
	DefaultPollInterval   = 5 * time.Second
	DefaultPollTimeout    = 3 * time.Second
	DefaultFailThreshold  = 3
	DefaultReloadInterval = 5 * time.Second
	pollJitter            = 0.10
	eventBuffer           = 64
)

// BalancerSink — узкий интерфейс балансировщика, который синхронизирует реестр.
type BalancerSink interface {
	Update(cands []balancer.Candidate)
	SetHealthy(id string, healthy bool)
	SetDraining(id string, draining bool)
}

var _ BalancerSink = (*balancer.Balancer)(nil)

// StatusFunc — опрос статуса агента (по умолчанию AgentTransport.Status).
type StatusFunc func(ctx context.Context, ref transport.AgentRef) (*transport.AgentStatus, error)

// TimerFunc создаёт одноразовый таймер: канал срабатывания и stop.
type TimerFunc func(d time.Duration) (<-chan time.Time, func() bool)

// EventType — тип события реестра.
type EventType string

// Типы событий.
const (
	AgentUp       EventType = "agent_up"
	AgentDown     EventType = "agent_down"
	AgentAdded    EventType = "agent_added"
	AgentRemoved  EventType = "agent_removed"
	AgentDraining EventType = "agent_draining"
)

// Event — событие реестра. Draining заполнен только для AgentDraining.
type Event struct {
	Type     EventType
	AgentID  string
	At       time.Time
	Draining bool
}

// State — агент и его рантайм-состояние.
type State struct {
	Agent            store.Agent
	Up               bool
	Draining         bool // эффективный: флаг БД или draining из статуса агента
	LastSeen         time.Time
	LastStatus       *transport.AgentStatus
	ConsecutiveFails int
}

type entry struct {
	State
	reportedDraining bool // draining, сообщённый самим агентом
	passiveFails     int
	cancelPoll       context.CancelFunc
}

// Option настраивает Registry.
type Option func(*Registry)

// WithClock задаёт источник времени (LastSeen, At событий).
func WithClock(f func() time.Time) Option {
	return func(r *Registry) {
		if f != nil {
			r.now = f
		}
	}
}

// WithTicker задаёт фабрику таймеров poller'а и цикла перечитывания.
func WithTicker(f TimerFunc) Option {
	return func(r *Registry) {
		if f != nil {
			r.newTimer = f
		}
	}
}

// WithStatusFunc подменяет опрос статуса (для тестов).
func WithStatusFunc(f StatusFunc) Option {
	return func(r *Registry) {
		if f != nil {
			r.status = f
		}
	}
}

// WithPollInterval — период опроса (по умолчанию 5s).
func WithPollInterval(d time.Duration) Option {
	return func(r *Registry) {
		if d > 0 {
			r.pollInterval = d
		}
	}
}

// WithPollTimeout — таймаут одного опроса (по умолчанию 3s).
func WithPollTimeout(d time.Duration) Option {
	return func(r *Registry) {
		if d > 0 {
			r.pollTimeout = d
		}
	}
}

// WithFailThreshold — число неудач подряд до down (по умолчанию 3).
func WithFailThreshold(n int) Option {
	return func(r *Registry) {
		if n > 0 {
			r.failThreshold = n
		}
	}
}

// WithReloadInterval — период проверки store.AgentRepo.Version() в Run
// (по умолчанию 5s; <=0 отключает, остаётся только ручной Refresh).
func WithReloadInterval(d time.Duration) Option {
	return func(r *Registry) { r.reloadInterval = d }
}

// WithRand задаёт источник [0,1) для jitter.
func WithRand(f func() float64) Option {
	return func(r *Registry) {
		if f != nil {
			r.rnd = f
		}
	}
}

// WithLogger задаёт логгер.
func WithLogger(l *slog.Logger) Option {
	return func(r *Registry) {
		if l != nil {
			r.log = l
		}
	}
}

// Registry — источник правды о составе и здоровье агентов.
type Registry struct {
	repo store.AgentRepo
	sink BalancerSink

	now            func() time.Time
	newTimer       TimerFunc
	status         StatusFunc
	rnd            func() float64
	log            *slog.Logger
	pollInterval   time.Duration
	pollTimeout    time.Duration
	failThreshold  int
	reloadInterval time.Duration

	refreshMu sync.Mutex // сериализует Refresh

	mu      sync.Mutex
	agents  map[string]*entry
	version int64
	loaded  bool
	runCtx  context.Context // не nil, пока выполняется Run
	wg      sync.WaitGroup
	subs    map[int]chan Event
	nextSub int
}

// New создаёт реестр. tr может быть nil, если задан WithStatusFunc.
func New(repo store.AgentRepo, tr transport.AgentTransport, sink BalancerSink, opts ...Option) *Registry {
	r := &Registry{
		repo:           repo,
		sink:           sink,
		now:            time.Now,
		rnd:            rand.Float64,
		log:            slog.Default(),
		pollInterval:   DefaultPollInterval,
		pollTimeout:    DefaultPollTimeout,
		failThreshold:  DefaultFailThreshold,
		reloadInterval: DefaultReloadInterval,
		agents:         make(map[string]*entry),
		subs:           make(map[int]chan Event),
	}
	r.newTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
		t := time.NewTimer(d)
		return t.C, t.Stop
	}
	if tr != nil {
		r.status = tr.Status
	}
	for _, o := range opts {
		o(r)
	}
	if r.status == nil {
		r.status = func(context.Context, transport.AgentRef) (*transport.AgentStatus, error) {
			return nil, errors.New("agents: no status transport")
		}
	}
	return r
}

// SeedFromConfig переносит агентов из конфига в БД, если таблица пуста.
// Возвращает число созданных записей.
func SeedFromConfig(ctx context.Context, repo store.AgentRepo, eps []config.AgentEndpoint) (int, error) {
	existing, err := repo.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("agents: seed list: %w", err)
	}
	if len(existing) > 0 {
		return 0, nil
	}
	n := 0
	for _, ep := range eps {
		w := ep.Weight
		if w <= 0 {
			w = 1
		}
		mode := store.AgentMode(ep.Mode)
		if mode == "" {
			mode = store.ModeDial
		}
		if _, err := repo.Create(ctx, store.Agent{ID: ep.ID, Name: ep.ID, URL: ep.URL, Mode: mode, Weight: w}); err != nil {
			return n, fmt.Errorf("agents: seed %q: %w", ep.ID, err)
		}
		n++
	}
	return n, nil
}

// List — снимок всех агентов, отсортированный по ID.
func (r *Registry) List() []State {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]State, 0, len(r.agents))
	for _, e := range r.agents {
		out = append(out, e.snapshot())
	}
	slices.SortFunc(out, func(a, b State) int {
		switch {
		case a.Agent.ID < b.Agent.ID:
			return -1
		case a.Agent.ID > b.Agent.ID:
			return 1
		}
		return 0
	})
	return out
}

// Get возвращает снимок состояния агента.
func (r *Registry) Get(id string) (State, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.agents[id]
	if !ok {
		return State{}, false
	}
	return e.snapshot(), true
}

// Ref возвращает адресата для транспорта (адаптер upstream роутера).
func (r *Registry) Ref(id string) (transport.AgentRef, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.agents[id]
	if !ok {
		return transport.AgentRef{}, false
	}
	return refOf(e.Agent), true
}

func refOf(a store.Agent) transport.AgentRef {
	ref := transport.AgentRef{ID: a.ID, Mode: config.AgentMode(a.Mode)}
	if a.URL != "" {
		if u, err := url.Parse(a.URL); err == nil {
			ref.URL = u
		}
	}
	return ref
}

func (e *entry) snapshot() State {
	s := e.State
	if s.LastStatus != nil {
		st := *s.LastStatus
		s.LastStatus = &st
	}
	return s
}

// SetWeight меняет вес в БД и сразу применяет его в балансировщике.
func (r *Registry) SetWeight(ctx context.Context, id string, w int) error {
	if err := r.repo.SetWeight(ctx, id, w); err != nil {
		return err
	}
	return r.Refresh(ctx)
}

// SetDraining меняет флаг draining в БД и сразу применяет его в балансировщике.
func (r *Registry) SetDraining(ctx context.Context, id string, draining bool) error {
	if err := r.repo.SetDraining(ctx, id, draining); err != nil {
		return err
	}
	return r.Refresh(ctx)
}

// Subscribe подписывает на события. Канал буферизован; при переполнении
// события для медленного подписчика отбрасываются. cancel закрывает канал.
func (r *Registry) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, eventBuffer)
	r.mu.Lock()
	id := r.nextSub
	r.nextSub++
	r.subs[id] = ch
	r.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subs, id)
			close(ch)
			r.mu.Unlock()
		})
	}
}

// publishLocked рассылает событие; вызывать под r.mu.
func (r *Registry) publishLocked(t EventType, id string, draining bool) {
	ev := Event{Type: t, AgentID: id, At: r.now(), Draining: draining}
	for _, ch := range r.subs {
		select {
		case ch <- ev:
		default:
			r.log.Warn("agents: event dropped, slow subscriber", "type", string(t), "agent", id)
		}
	}
}

// Refresh перечитывает состав агентов из БД и синхронизирует балансировщик
// и poller'ы.
func (r *Registry) Refresh(ctx context.Context) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()

	ver, err := r.repo.Version(ctx)
	if err != nil {
		return fmt.Errorf("agents: version: %w", err)
	}
	list, err := r.repo.List(ctx)
	if err != nil {
		return fmt.Errorf("agents: list: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	changed := !r.loaded
	r.loaded = true
	r.version = ver

	seen := make(map[string]struct{}, len(list))
	for _, a := range list {
		seen[a.ID] = struct{}{}
		e, ok := r.agents[a.ID]
		if !ok {
			// Неподтверждённый агент считается down до первого успешного опроса.
			e = &entry{}
			e.Agent = a
			e.Draining = a.Draining
			r.agents[a.ID] = e
			r.publishLocked(AgentAdded, a.ID, false)
			changed = true
			continue
		}
		if e.Agent.Weight != a.Weight {
			changed = true
		}
		e.Agent = a
		if eff := a.Draining || e.reportedDraining; eff != e.Draining {
			e.Draining = eff
			r.sink.SetDraining(a.ID, eff)
			r.publishLocked(AgentDraining, a.ID, eff)
		}
	}
	for id, e := range r.agents {
		if _, ok := seen[id]; ok {
			continue
		}
		if e.cancelPoll != nil {
			e.cancelPoll()
		}
		delete(r.agents, id)
		r.publishLocked(AgentRemoved, id, false)
		changed = true
	}
	if changed {
		r.syncSinkLocked()
	}
	r.ensurePollersLocked(r.runCtx) //nolint:contextcheck // poller живёт на контексте Run, а не Refresh
	return nil
}

// syncSinkLocked отдаёт балансировщику полный набор и перепроставляет health
// и draining (Update создаёт новые записи как healthy).
func (r *Registry) syncSinkLocked() {
	cands := make([]balancer.Candidate, 0, len(r.agents))
	for _, e := range r.agents {
		if e.Agent.Weight > 0 { // вес 0 = агент не получает трафик
			cands = append(cands, balancer.Candidate{ID: e.Agent.ID, Weight: e.Agent.Weight})
		}
	}
	slices.SortFunc(cands, func(a, b balancer.Candidate) int {
		if a.ID < b.ID {
			return -1
		} else if a.ID > b.ID {
			return 1
		}
		return 0
	})
	r.sink.Update(cands)
	for _, c := range cands {
		e := r.agents[c.ID]
		r.sink.SetHealthy(c.ID, e.Up)
		r.sink.SetDraining(c.ID, e.Draining)
	}
}

// Run выполняет начальный Refresh, запускает poller'ы и периодически
// перечитывает БД по Version(). Блокируется до отмены ctx и дожидается
// остановки всех горутин.
func (r *Registry) Run(ctx context.Context) error {
	r.mu.Lock()
	r.runCtx = ctx
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.runCtx = nil
		for _, e := range r.agents {
			if e.cancelPoll != nil {
				e.cancelPoll()
				e.cancelPoll = nil
			}
		}
		r.mu.Unlock()
		r.wg.Wait()
	}()

	if err := r.Refresh(ctx); err != nil {
		return err
	}
	if r.reloadInterval <= 0 {
		<-ctx.Done()
		return nil
	}
	for {
		ch, stop := r.newTimer(r.reloadInterval)
		select {
		case <-ctx.Done():
			stop()
			return nil
		case <-ch:
		}
		ver, err := r.repo.Version(ctx)
		if err != nil {
			r.log.Warn("agents: version check failed", "err", err)
			continue
		}
		r.mu.Lock()
		same := ver == r.version
		r.mu.Unlock()
		if same {
			continue
		}
		if err := r.Refresh(ctx); err != nil {
			r.log.Warn("agents: refresh failed", "err", err)
		}
	}
}
