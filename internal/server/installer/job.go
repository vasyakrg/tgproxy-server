package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"golang.org/x/crypto/ssh"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Виды событий задачи (SSE `event:`).
const (
	EventStep  = "step"  // смена статуса шага
	EventLog   = "log"   // строка журнала
	EventDone  = "done"  // успешное завершение (терминальное)
	EventError = "error" // неуспех (терминальное, после отката)
)

// Статусы шага (поле Event.Status для EventStep).
const (
	StepPending    = "pending"
	StepRunning    = "running"
	StepOK         = "ok"
	StepFailed     = "failed"
	StepRolledBack = "rolled_back"
)

const jobKindInstall = "install"

// Event — событие задачи. Seq монотонно растёт (он же Last-Event-ID).
type Event struct {
	Seq     int64
	JobID   string
	At      time.Time
	Kind    string
	Step    string // ключ шага (для step и log внутри шага)
	Status  string // для Kind == EventStep
	Level   string // info | warn | error
	Message string // без секретов
}

func eventFromStore(e store.InstallJobEvent) Event {
	ev := Event{Seq: e.ID, JobID: e.JobID, At: e.At, Kind: e.Kind, Step: e.Step, Level: e.Level, Message: e.Message}
	if e.Kind == EventStep {
		ev.Status, ev.Level = e.Level, "info"
	}
	return ev
}

// StepStatus — состояние шага в чеклисте.
type StepStatus struct {
	Key    string
	Label  string
	Status string
}

// JobStatus — снимок задачи; восстанавливается из БД (переживает рестарт).
type JobStatus struct {
	ID         string
	AgentID    string
	Host       string
	State      string // store.Install*
	Error      string
	Steps      []StepStatus
	CreatedAt  time.Time
	FinishedAt *time.Time
	LastSeq    int64
}

// Request — запрос на установку агента. Срезы в Auth Install копирует и
// затирает сам; свои буферы вызывающий затирает самостоятельно.
type Request struct {
	Name      string // id и имя агента (slug)
	Host      string
	SSHPort   int
	User      string // администратор с sudo (или root)
	AgentPort int    // порт mTLS агента
	Weight    int
	Auth      Auth
	// ConfirmedFingerprint — отпечаток, подтверждённый администратором в UI
	// (обязателен, пока ключ хоста не закреплён).
	ConfirmedFingerprint string
	// PackageVersion — версия пакета из кэша; пусто — новейшая.
	PackageVersion string
}

// CertIssuer — выпуск сертификата агента (pki.Authority).
type CertIssuer interface {
	SignAgentCSR(ctx context.Context, csrPEM []byte, agentID string, ttl time.Duration) (certPEM []byte, serial string, err error)
	CertPEM() []byte
}

// HealthChecker — проверка mTLS и доступа агента к Telegram (wiring передаёт транспорт).
type HealthChecker interface {
	Check(ctx context.Context, agentURL, agentID string) error
}

// Config — зависимости и параметры установщика.
type Config struct {
	Store     store.Store
	CA        CertIssuer
	Health    HealthChecker
	Alerter   HostKeyAlerter // nil — без алертов
	ServerKey ssh.Signer     // LoadOrCreateServerKey

	PackagesDir      string // локальный кэш deb: tgproxy_<версия>_<arch>.deb
	AllowedClientSAN string // allowed_client_san агента; по умолчанию tgproxy-server
	RemoteTmpDir     string // временные файлы на хосте; по умолчанию /tmp

	// ExpectedSHA256 — ожидаемый sha256 пакета (из подписанных checksums, M6); nil — не проверять.
	ExpectedSHA256 func(filename string) (hexSum string, ok bool)

	StepTimeout    time.Duration // 0 → 10m
	DialTimeout    time.Duration // 0 → DefaultDialTimeout
	HealthTimeout  time.Duration // 0 → 30s
	HealthInterval time.Duration // 0 → 1s

	Logger *slog.Logger
}

// Installer — менеджер задач установки.
type Installer struct {
	cfg  Config
	log  *slog.Logger
	base context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu   sync.Mutex
	live map[string]*liveJob

	hook func(*run) // тестовый хук: вызывается при создании run
}

// New создаёт установщик.
func New(cfg Config) (*Installer, error) {
	switch {
	case cfg.Store == nil || cfg.CA == nil || cfg.Health == nil || cfg.ServerKey == nil:
		return nil, errors.New("installer: Store, CA, Health и ServerKey обязательны")
	case cfg.PackagesDir == "":
		return nil, errors.New("installer: PackagesDir обязателен")
	}
	if cfg.AllowedClientSAN == "" {
		cfg.AllowedClientSAN = "tgproxy-server"
	}
	if cfg.RemoteTmpDir == "" {
		cfg.RemoteTmpDir = "/tmp"
	}
	if !absPathRe.MatchString(cfg.RemoteTmpDir) || strings.Contains(cfg.RemoteTmpDir, "..") {
		return nil, fmt.Errorf("installer: некорректный RemoteTmpDir %q", cfg.RemoteTmpDir)
	}
	if !sanRe.MatchString(cfg.AllowedClientSAN) {
		return nil, fmt.Errorf("installer: некорректный AllowedClientSAN %q", cfg.AllowedClientSAN)
	}
	if cfg.StepTimeout <= 0 {
		cfg.StepTimeout = 10 * time.Minute
	}
	if cfg.HealthTimeout <= 0 {
		cfg.HealthTimeout = 30 * time.Second
	}
	if cfg.HealthInterval <= 0 {
		cfg.HealthInterval = time.Second
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Installer{cfg: cfg, log: lg.With("component", "installer"), base: ctx, stop: cancel, live: map[string]*liveJob{}}, nil
}

// Close отменяет активные задачи (с откатом) и ждёт их завершения.
func (i *Installer) Close() {
	i.stop()
	i.wg.Wait()
}

// liveJob — рассылка событий выполняющейся задачи.
type liveJob struct {
	id     string
	bg     context.Context // запись событий переживает отмену запроса и Close
	repo   store.InstallJobRepo
	log    *slog.Logger
	scrubs [][]byte
	mu     sync.Mutex
	subs   map[chan Event]struct{}
	done   chan struct{}
	closed bool
}

const subBuffer = 512

// scrub заменяет известные секреты в сообщении.
func (l *liveJob) scrub(msg string) string {
	b := []byte(msg)
	for _, s := range l.scrubs {
		if len(s) > 0 {
			b = bytes.ReplaceAll(b, s, []byte("***"))
		}
	}
	return string(b)
}

const maxMessage = 2000

func (l *liveJob) emit(ev Event) Event {
	ev.Message = l.scrub(ev.Message)
	if len(ev.Message) > maxMessage {
		ev.Message = ev.Message[:maxMessage] + "…"
	}
	if ev.Level == "" {
		ev.Level = "info"
	}
	level := ev.Level
	if ev.Kind == EventStep {
		level = ev.Status
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	se, err := l.repo.AppendEvent(l.bg, store.InstallJobEvent{
		JobID: l.id, Kind: ev.Kind, Step: ev.Step, Level: level, Message: ev.Message,
	})
	if err != nil {
		l.log.Error("install event not persisted", "job", l.id, "err", err)
		return ev
	}
	out := eventFromStore(se)
	for ch := range l.subs {
		select {
		case ch <- out:
		default: // подписчик отстал: закрываем, переподключится с Last-Event-ID
			close(ch)
			delete(l.subs, ch)
		}
	}
	return out
}

func (l *liveJob) finish() {
	l.mu.Lock()
	l.closed = true
	for _, s := range l.scrubs {
		clear(s)
	}
	for ch := range l.subs {
		close(ch)
		delete(l.subs, ch)
	}
	l.mu.Unlock()
	close(l.done)
}

// Install проверяет запрос и запускает установку в фоне; возвращает id задачи.
// Контекст ctx относится только к проверкам: сама задача не зависит от
// HTTP-запроса и отменяется через Close.
func (i *Installer) Install(ctx context.Context, req Request) (string, error) {
	if err := validateName(req.Name); err != nil {
		return "", err
	}
	target := Target{Host: req.Host, Port: req.SSHPort, User: req.User}
	if err := target.validate(); err != nil {
		return "", err
	}
	if err := validatePort("agent port", req.AgentPort); err != nil {
		return "", err
	}
	if req.Weight < 1 {
		return "", fmt.Errorf("installer: вес должен быть >= 1, получено %d", req.Weight)
	}
	if req.PackageVersion != "" && !versionRe.MatchString(req.PackageVersion) {
		return "", fmt.Errorf("installer: некорректная версия пакета %q", req.PackageVersion)
	}
	if req.Auth.empty() {
		return "", ErrNoAuth
	}
	if err := req.Auth.Validate(); err != nil {
		return "", err
	}
	if _, err := i.cfg.Store.Agents().Get(ctx, req.Name); err == nil {
		return "", fmt.Errorf("installer: агент %q уже существует: %w", req.Name, store.ErrConflict)
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("installer: проверка агента: %w", err)
	}
	if _, err := i.cfg.Store.HostKeys().Get(ctx, target.Addr()); errors.Is(err, store.ErrNotFound) {
		if req.ConfirmedFingerprint == "" {
			return "", &ErrHostKeyUnknown{}
		}
	} else if err != nil {
		return "", fmt.Errorf("installer: чтение ключа хоста: %w", err)
	}
	pkgs, err := findPackages(i.cfg.PackagesDir, req.PackageVersion)
	if err != nil {
		return "", err
	}

	id := ulid.Make().String()
	if err := i.cfg.Store.InstallJobs().Create(ctx, store.InstallJob{
		ID: id, Host: target.Addr(), Kind: jobKindInstall, State: store.InstallRunning,
	}); err != nil {
		return "", fmt.Errorf("installer: создание задачи: %w", err)
	}

	r := &run{i: i, id: id, req: req, target: target, pkgs: pkgs, auth: req.Auth.Clone()}
	r.req.Auth = Auth{} // секреты остаются только в r.auth
	r.lj = &liveJob{
		id: id, bg: context.WithoutCancel(i.base), repo: i.cfg.Store.InstallJobs(), log: i.log, subs: map[chan Event]struct{}{}, done: make(chan struct{}),
		scrubs: cloneAll(r.auth.secrets()),
	}
	r.policy = HostKeyPolicy{Repo: i.cfg.Store.HostKeys(), AgentID: req.Name, Alerter: i.cfg.Alerter, Timeout: i.cfg.DialTimeout}
	i.mu.Lock()
	i.live[id] = r.lj
	i.mu.Unlock()
	if i.hook != nil {
		i.hook(r)
	}
	for _, st := range r.steps() {
		r.lj.emit(Event{JobID: id, Kind: EventStep, Step: st.key, Status: StepPending, Message: st.label(r)})
	}
	i.wg.Add(1)
	go func() {
		defer i.wg.Done()
		r.execute(i.base)
		i.mu.Lock()
		delete(i.live, id)
		i.mu.Unlock()
		r.lj.finish()
	}()
	return id, nil
}

// Wait блокируется до завершения задачи (или ctx). Завершённая задача — сразу.
func (i *Installer) Wait(ctx context.Context, jobID string) error {
	i.mu.Lock()
	l := i.live[jobID]
	i.mu.Unlock()
	if l == nil {
		return nil
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Status возвращает снимок задачи.
func (i *Installer) Status(ctx context.Context, jobID string) (JobStatus, error) {
	j, err := i.cfg.Store.InstallJobs().Get(ctx, jobID)
	if err != nil {
		return JobStatus{}, err
	}
	evs, err := i.cfg.Store.InstallJobs().Events(ctx, jobID, 0)
	if err != nil {
		return JobStatus{}, err
	}
	st := JobStatus{ID: j.ID, AgentID: j.AgentID, Host: j.Host, State: j.State, Error: j.Error, CreatedAt: j.CreatedAt, FinishedAt: j.FinishedAt}
	idx := map[string]int{}
	for _, e := range evs {
		st.LastSeq = e.ID
		if e.Kind != EventStep {
			continue
		}
		k, ok := idx[e.Step]
		if !ok {
			k = len(st.Steps)
			idx[e.Step] = k
			st.Steps = append(st.Steps, StepStatus{Key: e.Step})
		}
		st.Steps[k].Label, st.Steps[k].Status = e.Message, e.Level
	}
	return st, nil
}

// Events возвращает пропущенные события (Seq > afterSeq) и канал живых событий.
// Канал закрывается при завершении задачи, отставании подписчика или отмене ctx;
// для завершённой задачи он уже закрыт. Переподключение — с последним Seq.
func (i *Installer) Events(ctx context.Context, jobID string, afterSeq int64) ([]Event, <-chan Event, error) {
	repo := i.cfg.Store.InstallJobs()
	if _, err := repo.Get(ctx, jobID); err != nil {
		return nil, nil, err
	}
	i.mu.Lock()
	l := i.live[jobID]
	i.mu.Unlock()
	conv := func(in []store.InstallJobEvent) []Event {
		out := make([]Event, len(in))
		for k, e := range in {
			out[k] = eventFromStore(e)
		}
		return out
	}
	if l == nil {
		evs, err := repo.Events(ctx, jobID, afterSeq)
		ch := make(chan Event)
		close(ch)
		return conv(evs), ch, err
	}
	ch := make(chan Event, subBuffer)
	l.mu.Lock()
	evs, err := repo.Events(ctx, jobID, afterSeq)
	if err != nil {
		l.mu.Unlock()
		return nil, nil, err
	}
	if l.closed {
		l.mu.Unlock()
		close(ch)
		return conv(evs), ch, nil
	}
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	context.AfterFunc(ctx, func() {
		l.mu.Lock()
		if _, ok := l.subs[ch]; ok {
			delete(l.subs, ch)
			close(ch)
		}
		l.mu.Unlock()
	})
	return conv(evs), ch, nil
}

func cloneAll(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for k, b := range in {
		out[k] = append([]byte(nil), b...)
	}
	return out
}
