package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Ошибки Manager.
var (
	ErrBusy         = errors.New("rollout: уже выполняется другая раскатка")
	ErrNoActive     = errors.New("rollout: нет выполняющейся раскатки")
	ErrNoPackage    = errors.New("rollout: релиз версии не найден в кэше загрузок сервера")
	ErrBadVersion   = errors.New("rollout: некорректная версия")
	ErrBadParams    = errors.New("rollout: некорректные параметры")
	ErrUnknownAgent = errors.New("rollout: агент не найден")
	ErrAgentDown    = errors.New("rollout: агент недоступен")
)

// Умолчания.
const (
	DefaultCanary        = 1
	DefaultBatchSize     = 1
	MaxBatchSize         = 50
	DefaultDrainTimeout  = 30 * time.Second
	DefaultDrainInterval = time.Second
	DefaultPollInterval  = 2 * time.Second
	DefaultWaitTimeout   = 5 * time.Minute  // скачивание + apply + health 60s на агенте
	DefaultUpdateTimeout = 10 * time.Minute // POST /_agent/update: агент качает и проверяет релиз синхронно
	persistTimeout       = 10 * time.Second
	cleanupTimeout       = 15 * time.Second
	eventBuffer          = 64

	updatePath = "/_agent/update"
)

// Registry — реестр агентов (*agents.Registry).
type Registry interface {
	List() []agents.State
	Get(id string) (agents.State, bool)
	Ref(id string) (transport.AgentRef, bool)
	SetDraining(ctx context.Context, id string, draining bool) error
}

// Packages сообщает, что релиз версии есть в кэше загрузок сервера (updater.Cache).
type Packages interface {
	Has(version string) bool
}

// Alerter получает алерт rollout_failed (*notify.Evaluator).
type Alerter interface {
	RolloutFailed(ctx context.Context, agentID, version, reason string)
}

// Config — зависимости и тайминги Manager.
type Config struct {
	Store     store.Store
	Registry  Registry
	Transport transport.AgentTransport
	Packages  Packages
	Alerter   Alerter // nil — без алертов
	// GatewayURL — публичный https-URL agent_gateway: агент качает пакеты оттуда
	// (одинаково для dial- и reverse-агентов). Обязателен.
	GatewayURL string
	Logger     *slog.Logger

	DrainTimeout  time.Duration // 30s
	DrainInterval time.Duration // 1s
	PollInterval  time.Duration // 2s
	WaitTimeout   time.Duration // 5m
	UpdateTimeout time.Duration // 10m
}

// Params — запрос на раскатку.
type Params struct {
	Version   string
	BatchSize int  // 0 → 1
	Canary    int  // 0 → 1 (если не NoCanary)
	NoCanary  bool // без канарейки (обновление одного агента)
	// AllowDowntime разрешает вывести из балансировки последнего активного агента.
	AllowDowntime bool
	// Agents ограничивает раскатку перечисленными агентами (пусто — все).
	Agents []string
	Actor  string
}

// Status — снимок раскатки.
type Status struct {
	Rollout store.Rollout
	Steps   []store.RolloutStep
}

// Event — событие раскатки для UI. Kind: "rollout" (смена состояния раскатки) или "step".
type Event struct {
	RolloutID string
	Kind      string
	AgentID   string
	Phase     string
	State     string
	Message   string
	At        time.Time
}

// Manager запускает и ведёт раскатки; одновременно активна не более одной.
type Manager struct {
	cfg  Config
	log  *slog.Logger
	base context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu      sync.Mutex
	cur     *run
	subs    map[int]chan Event
	nextSub int

	capMu sync.Mutex // проверка «остаётся активный агент» + drain — атомарно
}

type run struct {
	id      string
	version string
	stopReq chan struct{}
	once    sync.Once
}

func (r *run) stopRequested() bool {
	select {
	case <-r.stopReq:
		return true
	default:
		return false
	}
}

// New создаёт Manager.
func New(cfg Config) (*Manager, error) {
	switch {
	case cfg.Store == nil || cfg.Registry == nil || cfg.Transport == nil || cfg.Packages == nil:
		return nil, errors.New("rollout: Store, Registry, Transport и Packages обязательны")
	case cfg.GatewayURL == "":
		return nil, errors.New("rollout: GatewayURL обязателен (агенты качают пакеты с agent_gateway)")
	}
	def := func(p *time.Duration, v time.Duration) {
		if *p <= 0 {
			*p = v
		}
	}
	def(&cfg.DrainTimeout, DefaultDrainTimeout)
	def(&cfg.DrainInterval, DefaultDrainInterval)
	def(&cfg.PollInterval, DefaultPollInterval)
	def(&cfg.WaitTimeout, DefaultWaitTimeout)
	def(&cfg.UpdateTimeout, DefaultUpdateTimeout)
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{cfg: cfg, log: lg.With("component", "rollout"), base: ctx, stop: cancel, subs: map[int]chan Event{}}, nil
}

// Close прерывает активную раскатку (агенты возвращаются в балансировку) и ждёт завершения.
func (m *Manager) Close() {
	m.stop()
	m.wg.Wait()
}

// Recover помечает раскатки, прерванные рестартом сервера, как failed (вызывать при старте).
func (m *Manager) Recover(ctx context.Context) error {
	repo := m.cfg.Store.Rollouts()
	ro, err := repo.Active(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	steps, err := repo.Steps(ctx, ro.ID)
	if err != nil {
		return err
	}
	for _, st := range steps {
		if st.State == store.StepRunning {
			_ = repo.SetStep(ctx, ro.ID, st.AgentID, store.StepFailed, "", "прервано перезапуском сервера")
		}
	}
	m.log.Warn("rollout interrupted by restart", "rollout", ro.ID, "version", ro.Version)
	return repo.SetState(ctx, ro.ID, store.RolloutFailed, "прервана перезапуском сервера")
}

// Subscribe подписывает на события раскатки. При переполнении события отбрасываются.
func (m *Manager) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, eventBuffer)
	m.mu.Lock()
	id := m.nextSub
	m.nextSub++
	m.subs[id] = ch
	m.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			m.mu.Lock()
			delete(m.subs, id)
			close(ch)
			m.mu.Unlock()
		})
	}
}

func (m *Manager) emit(ev Event) {
	ev.At = time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ch := range m.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (m *Manager) persistCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(m.base), persistTimeout)
}

func normVersion(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

func sameVersion(a, b string) bool { return a != "" && normVersion(a) == normVersion(b) }

// Start планирует и запускает раскатку. Возвращает снимок сразу после создания; сама
// раскатка идёт в фоне. Агенты, уже работающие на версии (или недоступные при старте),
// получают шаг skipped — повторный запуск идемпотентен.
func (m *Manager) Start(ctx context.Context, p Params) (Status, error) {
	version := normVersion(p.Version)
	if _, err := verify.ParseVersion(version); err != nil || strings.ContainsAny(version, "/\\") {
		return Status{}, fmt.Errorf("%w: %q", ErrBadVersion, p.Version)
	}
	if p.BatchSize < 0 || p.BatchSize > MaxBatchSize || p.Canary < 0 || p.Canary > MaxBatchSize {
		return Status{}, fmt.Errorf("%w: batch_size 1..%d, canary 0..%d", ErrBadParams, MaxBatchSize, MaxBatchSize)
	}
	if p.BatchSize == 0 {
		p.BatchSize = DefaultBatchSize
	}
	switch {
	case p.NoCanary:
		p.Canary = 0
	case p.Canary == 0:
		p.Canary = DefaultCanary
	}
	if !m.cfg.Packages.Has(version) {
		return Status{}, fmt.Errorf("%w: %s", ErrNoPackage, version)
	}
	steps, err := m.plan(version, p)
	if err != nil {
		return Status{}, err
	}

	ro := store.Rollout{
		ID: ulid.Make().String(), Version: version, BatchSize: p.BatchSize, Canary: p.Canary,
		AllowDowntime: p.AllowDowntime, State: store.RolloutRunning, Actor: p.Actor, CreatedAt: time.Now(),
	}
	pending := 0
	for _, s := range steps {
		if s.State == store.StepPending {
			pending++
		}
	}
	if pending == 0 { // нечего обновлять: всё на версии — раскатка завершена сразу
		fin := time.Now()
		ro.State, ro.FinishedAt = store.RolloutDone, &fin
	}

	m.mu.Lock()
	if m.cur != nil {
		m.mu.Unlock()
		return Status{}, ErrBusy
	}
	if err := m.cfg.Store.Rollouts().Create(ctx, ro, steps); err != nil {
		m.mu.Unlock()
		if errors.Is(err, store.ErrConflict) {
			return Status{}, ErrBusy
		}
		return Status{}, err
	}
	var r *run
	if pending > 0 {
		r = &run{id: ro.ID, version: version, stopReq: make(chan struct{})}
		m.cur = r
	}
	m.mu.Unlock()

	m.log.Info("rollout started", "rollout", ro.ID, "version", version, "pending", pending, "batch", p.BatchSize, "canary", p.Canary, "actor", p.Actor)
	m.emit(Event{RolloutID: ro.ID, Kind: "rollout", State: ro.State, Message: "Раскатка " + version})
	if r != nil {
		m.wg.Add(1)
		go func() { //nolint:contextcheck // раскатка живёт дольше HTTP-запроса и ограничена base-контекстом Manager
			defer m.wg.Done()
			m.execute(r, ro, steps)
		}()
	}
	return Status{Rollout: ro, Steps: steps}, nil
}

// plan строит шаги: ожидающие (канарейка, затем батч) и пропущенные.
func (m *Manager) plan(version string, p Params) ([]store.RolloutStep, error) {
	states := m.cfg.Registry.List()
	if len(p.Agents) > 0 {
		var sel []agents.State
		for _, id := range p.Agents {
			i := slices.IndexFunc(states, func(s agents.State) bool { return s.Agent.ID == id })
			if i < 0 {
				return nil, fmt.Errorf("%w: %s", ErrUnknownAgent, id)
			}
			sel = append(sel, states[i])
		}
		states = sel
	}
	if len(states) == 0 {
		return nil, fmt.Errorf("%w: в реестре нет агентов", ErrBadParams)
	}
	var pending, skipped []store.RolloutStep
	for _, s := range states {
		step := store.RolloutStep{AgentID: s.Agent.ID, State: store.StepPending}
		if s.LastStatus != nil {
			step.FromVersion = s.LastStatus.Version
		}
		switch {
		case s.LastStatus != nil && sameVersion(s.LastStatus.Version, version):
			step.State, step.Error = store.StepSkipped, "уже на версии "+version
			skipped = append(skipped, step)
		case !s.Up:
			if len(p.Agents) > 0 {
				return nil, fmt.Errorf("%w: %s", ErrAgentDown, s.Agent.ID)
			}
			step.State, step.Error = store.StepSkipped, "недоступен при старте раскатки"
			skipped = append(skipped, step)
		default:
			pending = append(pending, step)
		}
	}
	seq := 0
	for i := range pending {
		seq++
		pending[i].Seq = seq
		pending[i].Phase = store.PhaseBatch
		if i < p.Canary {
			pending[i].Phase = store.PhaseCanary
		}
	}
	for i := range skipped {
		seq++
		skipped[i].Seq, skipped[i].Phase = seq, store.PhaseBatch
	}
	return append(pending, skipped...), nil
}

// Stop просит остановить раскатку: текущие шаги дорабатывают, новые не начинаются.
func (m *Manager) Stop(ctx context.Context) (Status, error) {
	m.mu.Lock()
	r := m.cur
	m.mu.Unlock()
	if r == nil {
		return Status{}, ErrNoActive
	}
	r.once.Do(func() {
		close(r.stopReq)
		if err := m.cfg.Store.Rollouts().SetState(ctx, r.id, store.RolloutStopping, ""); err != nil {
			m.log.Warn("rollout stopping state not saved", "rollout", r.id, "err", err)
		}
		m.emit(Event{RolloutID: r.id, Kind: "rollout", State: store.RolloutStopping, Message: "Остановка: дожидаемся текущих агентов"})
	})
	return m.Get(ctx, r.id)
}

// Get возвращает раскатку с шагами.
func (m *Manager) Get(ctx context.Context, id string) (Status, error) {
	ro, err := m.cfg.Store.Rollouts().Get(ctx, id)
	if err != nil {
		return Status{}, err
	}
	return m.status(ctx, ro)
}

// Current возвращает выполняющуюся раскатку, а если её нет — последнюю завершённую
// (store.ErrNotFound, если раскаток не было).
func (m *Manager) Current(ctx context.Context) (Status, error) {
	repo := m.cfg.Store.Rollouts()
	ro, err := repo.Active(ctx)
	if errors.Is(err, store.ErrNotFound) {
		ro, err = repo.Latest(ctx)
	}
	if err != nil {
		return Status{}, err
	}
	return m.status(ctx, ro)
}

func (m *Manager) status(ctx context.Context, ro store.Rollout) (Status, error) {
	steps, err := m.cfg.Store.Rollouts().Steps(ctx, ro.ID)
	if err != nil {
		return Status{}, err
	}
	return Status{Rollout: ro, Steps: steps}, nil
}

// Wait ждёт завершения раскатки id (тесты, CLI).
func (m *Manager) Wait(ctx context.Context, id string) error {
	for {
		ro, err := m.cfg.Store.Rollouts().Get(ctx, id)
		if err != nil {
			return err
		}
		if !ro.Active() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// failure — итог неуспешного шага.
type failure struct {
	agentID string
	reason  string
}

func (m *Manager) execute(r *run, ro store.Rollout, steps []store.RolloutStep) {
	var canary, batch []store.RolloutStep
	for _, s := range steps {
		switch {
		case s.State != store.StepPending:
		case s.Phase == store.PhaseCanary:
			canary = append(canary, s)
		default:
			batch = append(batch, s)
		}
	}
	var fail *failure
	for _, s := range canary {
		if r.stopRequested() || m.base.Err() != nil {
			break
		}
		if f := m.runStep(ro, s); f != nil {
			fail = f
			break
		}
	}
	for i := 0; fail == nil && i < len(batch); i += ro.BatchSize {
		if r.stopRequested() || m.base.Err() != nil {
			break
		}
		chunk := batch[i:min(i+ro.BatchSize, len(batch))]
		var (
			wg  sync.WaitGroup
			fmu sync.Mutex
		)
		for _, s := range chunk {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if f := m.runStep(ro, s); f != nil {
					fmu.Lock()
					if fail == nil {
						fail = f
					}
					fmu.Unlock()
				}
			}()
		}
		wg.Wait() // «Остановить»/провал дожидаются всех агентов батча
	}
	m.finish(r, ro, fail)
}

func (m *Manager) finish(r *run, ro store.Rollout, fail *failure) {
	ctx, cancel := m.persistCtx()
	defer cancel()
	state, msg := store.RolloutDone, ""
	switch {
	case fail != nil:
		state, msg = store.RolloutFailed, fmt.Sprintf("агент %s: %s", fail.agentID, fail.reason)
	case r.stopRequested() || m.base.Err() != nil:
		left := 0
		if steps, err := m.cfg.Store.Rollouts().Steps(ctx, ro.ID); err == nil {
			for _, s := range steps {
				if s.State == store.StepPending {
					left++
				}
			}
		}
		if left > 0 {
			state, msg = store.RolloutStopped, fmt.Sprintf("остановлена, не обновлено агентов: %d", left)
		}
	}
	if err := m.cfg.Store.Rollouts().SetState(ctx, ro.ID, state, msg); err != nil {
		m.log.Error("rollout final state not saved", "rollout", ro.ID, "err", err)
	}
	m.mu.Lock()
	m.cur = nil
	m.mu.Unlock()
	m.log.Info("rollout finished", "rollout", ro.ID, "version", ro.Version, "state", state, "detail", msg)
	m.emit(Event{RolloutID: ro.ID, Kind: "rollout", State: state, Message: msg})
	if fail != nil && m.cfg.Alerter != nil {
		m.cfg.Alerter.RolloutFailed(ctx, fail.agentID, ro.Version, fail.reason)
	}
}

func (m *Manager) setStep(ro store.Rollout, s store.RolloutStep, state, from, msg string) {
	ctx, cancel := m.persistCtx()
	defer cancel()
	if err := m.cfg.Store.Rollouts().SetStep(ctx, ro.ID, s.AgentID, state, from, msg); err != nil {
		m.log.Error("rollout step not saved", "rollout", ro.ID, "agent", s.AgentID, "err", err)
	}
	m.emit(Event{RolloutID: ro.ID, Kind: "step", AgentID: s.AgentID, Phase: s.Phase, State: state, Message: msg})
}

// runStep обновляет одного агента и фиксирует результат; nil — успех или пропуск.
func (m *Manager) runStep(ro store.Rollout, s store.RolloutStep) *failure {
	m.setStep(ro, s, store.StepRunning, "", "")
	state, from, err := m.updateAgent(m.base, ro, s)
	switch {
	case err != nil:
		reason := redact.String(err.Error())
		m.log.Warn("rollout step failed", "rollout", ro.ID, "agent", s.AgentID, "phase", s.Phase, "err", reason)
		m.setStep(ro, s, store.StepFailed, from, reason)
		return &failure{agentID: s.AgentID, reason: reason}
	case state == store.StepSkipped:
		m.setStep(ro, s, store.StepSkipped, from, "уже на версии "+ro.Version)
	default:
		m.setStep(ro, s, store.StepDone, from, "")
	}
	return nil
}

// updateAgent — drain → update → ожидание → undrain. Возвращает итоговое состояние
// шага (done|skipped), версию до обновления и ошибку.
func (m *Manager) updateAgent(ctx context.Context, ro store.Rollout, s store.RolloutStep) (state, from string, err error) {
	id := s.AgentID
	ref, ok := m.cfg.Registry.Ref(id)
	if !ok {
		return "", "", fmt.Errorf("агент %s удалён из реестра", id)
	}
	st, err := m.cfg.Transport.Status(ctx, ref)
	if err != nil {
		return "", "", fmt.Errorf("агент недоступен: %w", err)
	}
	from = st.Version
	if sameVersion(from, ro.Version) {
		return store.StepSkipped, from, nil
	}

	wasDraining := false
	if cur, ok := m.cfg.Registry.Get(id); ok {
		wasDraining = cur.Draining
	}
	drained := false
	if !wasDraining {
		if err := m.drain(ctx, ro, id); err != nil {
			return "", from, err
		}
		drained = true
	}
	// После любого исхода агент возвращается в балансировку, если он ответил (после отката
	// apply — на прежней версии); недоступный остаётся в drain до вмешательства админа.
	defer func() { //nolint:contextcheck // откат после отмены ctx должен завершиться (WithoutCancel внутри restore)
		if !drained {
			return
		}
		m.restore(ro, ref, id, &err)
	}()

	m.waitDrained(ctx, ref)
	if err = m.postUpdate(ctx, ref, ro.Version); err != nil {
		return "", from, err
	}
	if err = m.waitUpdated(ctx, ref, ro.Version); err != nil {
		return "", from, err
	}
	return store.StepDone, from, nil
}

// drain выводит агента из балансировки, не оставляя без активных агентов (кроме AllowDowntime).
func (m *Manager) drain(ctx context.Context, ro store.Rollout, id string) error {
	m.capMu.Lock()
	defer m.capMu.Unlock()
	if !ro.AllowDowntime {
		active := 0
		for _, o := range m.cfg.Registry.List() {
			if o.Agent.ID != id && o.Up && !o.Draining {
				active++
			}
		}
		if active == 0 {
			return errors.New("нет другого активного агента: drain оставил бы прокси без агентов (разрешите простой явно)")
		}
	}
	if err := m.cfg.Registry.SetDraining(ctx, id, true); err != nil {
		return fmt.Errorf("drain: %w", err)
	}
	return nil
}

func (m *Manager) restore(ro store.Rollout, ref transport.AgentRef, id string, runErr *error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(m.base), cleanupTimeout)
	defer cancel()
	if _, serr := m.cfg.Transport.Status(ctx, ref); serr != nil {
		if *runErr != nil {
			*runErr = fmt.Errorf("%w; агент недоступен и оставлен в drain", *runErr)
		} else {
			*runErr = fmt.Errorf("агент недоступен после обновления, оставлен в drain: %w", serr)
		}
		return
	}
	if err := m.cfg.Registry.SetDraining(ctx, id, false); err != nil {
		m.log.Error("rollout: undrain failed", "rollout", ro.ID, "agent", id, "err", err)
		if *runErr == nil {
			*runErr = fmt.Errorf("undrain: %w", err)
		}
	}
}

// waitDrained ждёт inflight == 0; таймаут не ошибка (запросы агента завершатся при рестарте gracefully).
func (m *Manager) waitDrained(ctx context.Context, ref transport.AgentRef) {
	dl := time.NewTimer(m.cfg.DrainTimeout)
	defer dl.Stop()
	for {
		st, err := m.cfg.Transport.Status(ctx, ref)
		if err != nil || st.Inflight <= 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-dl.C:
			m.log.Warn("rollout: drain timeout, continuing", "agent", ref.ID, "inflight", st.Inflight)
			return
		case <-time.After(m.cfg.DrainInterval):
		}
	}
}

type agentReply struct {
	State   string `json:"state"`
	Version string `json:"version"`
	Error   string `json:"error"`
}

func (m *Manager) call(ctx context.Context, ref transport.AgentRef, method string, body []byte) (int, agentReply, error) {
	var rd io.Reader = http.NoBody
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, updatePath, rd)
	if err != nil {
		return 0, agentReply{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(body))
	}
	resp, err := m.cfg.Transport.RoundTrip(ctx, ref, req)
	if err != nil {
		return 0, agentReply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var rep agentReply
	_ = json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&rep)
	return resp.StatusCode, rep, nil
}

func (m *Manager) postUpdate(ctx context.Context, ref transport.AgentRef, version string) error {
	// reverse/both-агент берёт релиз с СВОЕГО server_url (он уже знает, куда коннектиться), поэтому
	// gateway_url передаётся только dial-агентам, у которых server_url нет.
	req := map[string]string{"version": version}
	if ref.Mode == config.AgentModeDial {
		req["gateway_url"] = m.cfg.GatewayURL
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, m.cfg.UpdateTimeout)
	defer cancel()
	code, rep, err := m.call(cctx, ref, http.MethodPost, body)
	if err != nil {
		return fmt.Errorf("команда обновления не доставлена: %w", err)
	}
	if code != http.StatusAccepted {
		return fmt.Errorf("агент отклонил обновление (HTTP %d): %s", code, rep.Error)
	}
	return nil
}

// waitUpdated ждёт, пока агент вернётся на целевой версии (рестарт через apply) и apply отчитается об успехе. Быстрый провал:
// агент сообщил failed для этой версии (отказ загрузки/проверки либо откат apply).
func (m *Manager) waitUpdated(ctx context.Context, ref transport.AgentRef, version string) error {
	deadline := time.NewTimer(m.cfg.WaitTimeout)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("агент не вернулся на версию %s за %s", version, m.cfg.WaitTimeout)
		case <-time.After(m.cfg.PollInterval):
		}
		// Успех — когда агент вернулся на целевой версии И root-apply завершился (result.json ok):
		// пока идёт окно стабильности apply (и возможный откат), агента нельзя возвращать в балансировку.
		code, rep, err := m.call(ctx, ref, http.MethodGet, nil)
		if err != nil || code != http.StatusOK || !sameVersion(rep.Version, version) {
			continue
		}
		switch rep.State {
		case "failed":
			return fmt.Errorf("обновление не удалось на агенте (откат выполнен самим агентом): %s", rep.Error)
		case "applied":
			if st, err := m.cfg.Transport.Status(ctx, ref); err == nil && sameVersion(st.Version, version) {
				return nil
			}
		}
	}
}
