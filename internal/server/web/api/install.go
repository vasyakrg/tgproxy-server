package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// AuditInstallStart — действие аудита запуска установки. Креды и passphrase в аудит не попадают.
const AuditInstallStart = "agent.install"

// Поля формы установки, к которым привязываются ошибки.
const (
	FieldHost       = "host"
	FieldSSHPort    = "ssh_port"
	FieldUser       = "user"
	FieldAgentPort  = "agent_port"
	FieldWeight     = "weight"
	FieldAuth       = "auth"
	FieldPassword   = "password"
	FieldPrivateKey = "private_key"
	FieldPassphrase = "passphrase"
)

// Значения по умолчанию мастера.
const (
	DefaultSSHPort   = 22
	DefaultAgentPort = 8443
	DefaultWeight    = 100
	maxWeight        = 1000
	maxKeyBytes      = 32 << 10
	maxSecretBytes   = 1 << 10
	pendingMax       = 32
	probeTimeout     = 10 * time.Second
)

// Ошибки установки.
var (
	// ErrProbeFailed — не удалось получить ключ хоста.
	ErrProbeFailed = errors.New("api: не удалось получить ключ хоста")
	// ErrPendingGone — подтверждение просрочено, уже использовано или не принадлежит этому пользователю.
	ErrPendingGone = errors.New("api: запрос на установку устарел")
	// ErrHostKeyChanged — закреплённый ключ хоста не совпал с предъявленным (возможна подмена).
	ErrHostKeyChanged = errors.New("api: ключ хоста отличается от закреплённого")
	// ErrBadJob — некорректный идентификатор задачи.
	ErrBadJob = errors.New("api: некорректный идентификатор задачи")
)

var jobIDRe = regexp.MustCompile(`^[0-9A-Za-z]{1,40}$`)

// ValidJobID — идентификатор задачи из URL.
func ValidJobID(id string) bool { return jobIDRe.MatchString(id) }

// Installer — SSH-установщик (реализует *installer.Installer).
type Installer interface {
	Install(ctx context.Context, req installer.Request) (string, error)
	Status(ctx context.Context, jobID string) (installer.JobStatus, error)
	Events(ctx context.Context, jobID string, afterSeq int64) ([]installer.Event, <-chan installer.Event, error)
}

// HostKeyProber читает ключ хоста без аутентификации (installer.ProbeHostKey).
type HostKeyProber func(ctx context.Context, t installer.Target) (algo, fingerprint string, err error)

// InstallConfig — зависимости InstallService.
type InstallConfig struct {
	Installer Installer
	// Probe — nil: installer.ProbeHostKey.
	Probe HostKeyProber
	// HostKeys — закреплённые ключи (необязательно): мастер пропускает шаг подтверждения для известного хоста.
	HostKeys store.HostKeyRepo
	Audit    store.AuditRepo
	Logger   *slog.Logger
	Now      func() time.Time
	// PendingTTL — сколько живут введённые креды между шагами мастера; 0 → 5 мин.
	PendingTTL time.Duration
}

// InstallInput — ввод установки. Секреты — срезы, чтобы их можно было затереть.
type InstallInput struct {
	Name       string
	Host       string
	SSHPort    int
	User       string
	AgentPort  int
	Weight     int
	Password   []byte
	PrivateKey []byte
	Passphrase []byte
	// ConfirmedFingerprint — отпечаток, подтверждённый администратором (если хост ещё не закреплён).
	ConfirmedFingerprint string
}

// Zero затирает секреты ввода.
func (in *InstallInput) Zero() {
	clear(in.Password)
	clear(in.PrivateKey)
	clear(in.Passphrase)
	in.Password, in.PrivateKey, in.Passphrase = nil, nil, nil
}

// Validate проверяет ввод без обращения к сети (значения не эхоятся: ошибки — готовые тексты).
func (in InstallInput) Validate() FieldErrors {
	fe := FieldErrors{}
	if !validAgentName(in.Name) {
		fe[FieldName] = "Латиница, цифры, «.», «_», «-»; до 63 символов"
	}
	if h := in.Host; h == "" || len(h) > 253 || strings.ContainsAny(h, " \t\r\n/@\\") {
		fe[FieldHost] = "Укажите имя хоста или IP"
	}
	if in.SSHPort < 1 || in.SSHPort > 65535 {
		fe[FieldSSHPort] = "Порт от 1 до 65535"
	}
	if in.AgentPort < 1 || in.AgentPort > 65535 {
		fe[FieldAgentPort] = "Порт от 1 до 65535"
	}
	if !userRe.MatchString(in.User) {
		fe[FieldUser] = "Строчные латинские буквы, цифры, «_», «-»"
	}
	if in.Weight < 1 || in.Weight > maxWeight {
		fe[FieldWeight] = "Целое от 1 до 1000"
	}
	switch hasKey, hasPw := len(in.PrivateKey) > 0, len(in.Password) > 0; {
	case !hasKey && !hasPw:
		fe[FieldAuth] = "Укажите приватный ключ или пароль"
	case hasKey && hasPw:
		fe[FieldAuth] = "Выберите один способ: ключ или пароль"
	case hasKey && len(in.PrivateKey) > maxKeyBytes:
		fe[FieldPrivateKey] = "Ключ слишком большой"
	case hasPw && len(in.Password) > maxSecretBytes:
		fe[FieldPassword] = "Пароль слишком длинный"
	}
	if len(in.Passphrase) > maxSecretBytes {
		fe[FieldPassphrase] = "Passphrase слишком длинная"
	}
	if len(fe) == 0 {
		return nil
	}
	return fe
}

var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var agentNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func validAgentName(n string) bool { return agentNameRe.MatchString(n) }

// ProbeResult — ключ хоста для подтверждения в мастере.
type ProbeResult struct {
	Addr        string
	Algo        string // «ED25519»
	Fingerprint string // SHA256:...
	// Pinned — ключ хоста уже закреплён; Match — совпал ли он с предъявленным.
	Pinned bool
	Match  bool
}

func algoLabel(algo string) string {
	switch algo {
	case ssh.KeyAlgoED25519:
		return "ED25519"
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return "RSA"
	case ssh.KeyAlgoECDSA256:
		return "ECDSA-256"
	case ssh.KeyAlgoECDSA384:
		return "ECDSA-384"
	case ssh.KeyAlgoECDSA521:
		return "ECDSA-521"
	}
	return algo
}

// Pending — введённые на шаге 1 креды, ожидающие подтверждения отпечатка. Живут только в памяти.
type Pending struct {
	ID      string
	User    string // логин администратора UI (чужую сессию не принимаем)
	Probe   ProbeResult
	Input   InstallInput // секреты внутри; наружу не отдаётся
	expires time.Time
	timer   *time.Timer
}

// Form возвращает несекретные поля формы для повторного показа.
func (p *Pending) Form() InstallInput {
	in := p.Input
	in.Password, in.PrivateKey, in.Passphrase = nil, nil, nil
	return in
}

// InstallService — запуск установки, проверка ключа хоста, промежуточное хранение кредов в памяти.
type InstallService struct {
	cfg InstallConfig
	log *slog.Logger
	now func() time.Time

	mu      sync.Mutex
	pending map[string]*Pending
}

// NewInstallService создаёт сервис.
func NewInstallService(cfg InstallConfig) *InstallService {
	s := &InstallService{cfg: cfg, log: cfg.Logger, now: cfg.Now, pending: map[string]*Pending{}}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.cfg.PendingTTL <= 0 {
		s.cfg.PendingTTL = 5 * time.Minute
	}
	if s.cfg.Probe == nil {
		s.cfg.Probe = installer.ProbeHostKey
	}
	return s
}

// Configured — установщик подключён.
func (s *InstallService) Configured() bool { return s != nil && s.cfg.Installer != nil }

// Probe читает ключ хоста и сверяет его с закреплённым.
func (s *InstallService) Probe(ctx context.Context, host string, port int) (ProbeResult, error) {
	if !s.Configured() {
		return ProbeResult{}, ErrNotConfigured
	}
	fe := FieldErrors{}
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/@\\") {
		fe[FieldHost] = "Укажите имя хоста или IP"
	}
	if port < 1 || port > 65535 {
		fe[FieldSSHPort] = "Порт от 1 до 65535"
	}
	if len(fe) > 0 {
		return ProbeResult{}, &ValidationError{Fields: fe}
	}
	t := installer.Target{Host: host, Port: port}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	algo, fp, err := s.cfg.Probe(pctx, t)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("%w: %s", ErrProbeFailed, redact.String(err.Error()))
	}
	res := ProbeResult{Addr: t.Addr(), Algo: algoLabel(algo), Fingerprint: fp}
	if s.cfg.HostKeys != nil {
		switch rec, gerr := s.cfg.HostKeys.Get(ctx, t.Addr()); {
		case gerr == nil:
			res.Pinned, res.Match = true, rec.Fingerprint == fp
		case !errors.Is(gerr, store.ErrNotFound):
			return ProbeResult{}, fmt.Errorf("чтение закреплённого ключа хоста: %w", gerr)
		}
	}
	return res, nil
}

// Start запускает установку. Копии секретов у вызывающего затирает он сам.
func (s *InstallService) Start(ctx context.Context, act Actor, in InstallInput) (string, error) {
	if !s.Configured() {
		return "", ErrNotConfigured
	}
	if fe := in.Validate(); fe != nil {
		return "", &ValidationError{Fields: fe}
	}
	req := installer.Request{
		Name: in.Name, Host: in.Host, SSHPort: in.SSHPort, User: in.User, AgentPort: in.AgentPort, Weight: in.Weight,
		Auth: installer.Auth{
			Password: in.Password, PrivateKeyPEM: in.PrivateKey, Passphrase: in.Passphrase,
		},
		ConfirmedFingerprint: in.ConfirmedFingerprint,
	}
	id, err := s.cfg.Installer.Install(ctx, req)
	if err != nil {
		return "", s.translate(err, in)
	}
	method := "password"
	if len(in.PrivateKey) > 0 {
		method = "key"
	}
	s.record(ctx, act, in.Name, fmt.Sprintf("job=%s host=%s:%d user=%s auth=%s", id, in.Host, in.SSHPort, in.User, method))
	return id, nil
}

// translate приводит ошибки установщика к ошибкам API (без секретов в тексте).
func (s *InstallService) translate(err error, in InstallInput) error {
	var unknown *installer.ErrHostKeyUnknown
	var ve *ValidationError
	switch {
	case errors.As(err, &unknown), errors.As(err, &ve):
		return err
	case errors.Is(err, installer.ErrHostKeyMismatch):
		return ErrHostKeyChanged
	case errors.Is(err, installer.ErrPassphraseRequired):
		return &ValidationError{Fields: FieldErrors{FieldPassphrase: "Ключ зашифрован: введите passphrase"}} // #nosec G101 -- G101: текст ошибки, не секрет
	case errors.Is(err, installer.ErrBadPassphrase):
		return &ValidationError{Fields: FieldErrors{FieldPassphrase: "Passphrase не подходит к ключу"}} // #nosec G101 -- G101: текст ошибки, не секрет
	case errors.Is(err, installer.ErrNoAuth):
		return &ValidationError{Fields: FieldErrors{FieldAuth: "Укажите приватный ключ или пароль"}}
	case errors.Is(err, store.ErrConflict):
		return &ValidationError{Fields: FieldErrors{FieldName: "Агент с таким именем уже есть"}}
	}
	msg := scrub(err.Error(), in.Password, in.PrivateKey, in.Passphrase)
	if strings.HasPrefix(msg, "installer:") {
		return &ValidationError{Fields: FieldErrors{FieldGeneral: redact.String(msg)}}
	}
	// Неизвестная ошибка уходит в лог: цепочку не сохраняем, чтобы секрет не пережил wrap.
	return errors.New(msg)
}

// scrub заменяет значения секретов в тексте ошибки.
func scrub(msg string, secrets ...[]byte) string {
	for _, sec := range secrets {
		if len(sec) > 0 {
			msg = strings.ReplaceAll(msg, string(sec), "***")
		}
	}
	return msg
}

func (s *InstallService) record(ctx context.Context, act Actor, target, detail string) {
	if s.cfg.Audit == nil {
		return
	}
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	if _, err := s.cfg.Audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: AuditInstallStart, Target: target, IP: act.IP, Detail: detail,
	}); err != nil {
		s.log.ErrorContext(ctx, "install audit failed", "agent", target, "err", err)
	}
}

// Status — снимок задачи.
func (s *InstallService) Status(ctx context.Context, jobID string) (installer.JobStatus, error) {
	if !s.Configured() {
		return installer.JobStatus{}, ErrNotConfigured
	}
	if !ValidJobID(jobID) {
		return installer.JobStatus{}, ErrBadJob
	}
	return s.cfg.Installer.Status(ctx, jobID)
}

// Events — пропущенные события и живой канал.
func (s *InstallService) Events(ctx context.Context, jobID string, after int64) ([]installer.Event, <-chan installer.Event, error) {
	if !s.Configured() {
		return nil, nil, ErrNotConfigured
	}
	if !ValidJobID(jobID) {
		return nil, nil, ErrBadJob
	}
	return s.cfg.Installer.Events(ctx, jobID, after)
}

// Stage кладёт введённые креды в память (на PendingTTL) и возвращает непрозрачный id для шага 2.
// Секреты копируются; буферы вызывающего он затирает сам.
func (s *InstallService) Stage(act Actor, in InstallInput, probe ProbeResult) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	cp := in
	cp.Password, cp.PrivateKey, cp.Passphrase = append([]byte(nil), in.Password...), append([]byte(nil), in.PrivateKey...), append([]byte(nil), in.Passphrase...)
	cp.ConfirmedFingerprint = probe.Fingerprint
	p := &Pending{ID: id, User: act.User, Probe: probe, Input: cp, expires: s.now().Add(s.cfg.PendingTTL)}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if len(s.pending) >= pendingMax {
		p.Input.Zero()
		return "", fmt.Errorf("%w: слишком много незавершённых установок", ErrPendingGone)
	}
	p.timer = time.AfterFunc(s.cfg.PendingTTL, func() { s.Discard(id) })
	s.pending[id] = p
	return id, nil
}

func (s *InstallService) sweepLocked() {
	now := s.now()
	for id, p := range s.pending {
		if !p.expires.After(now) {
			s.dropLocked(id, p)
		}
	}
}

func (s *InstallService) dropLocked(id string, p *Pending) {
	if p.timer != nil {
		p.timer.Stop()
	}
	p.Input.Zero()
	delete(s.pending, id)
}

// Discard забывает и затирает staged-креды.
func (s *InstallService) Discard(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.pending[id]; ok {
		s.dropLocked(id, p)
	}
}

// Pending возвращает несекретное описание staged-запроса (для повторного показа шага 2).
func (s *InstallService) Pending(act Actor, id string) (ProbeResult, InstallInput, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok || !p.expires.After(s.now()) || p.User != act.User {
		return ProbeResult{}, InstallInput{}, false
	}
	return p.Probe, p.Form(), true
}

// Confirm запускает установку по staged-кредам с отпечатком, показанным администратору. Запись одноразовая.
// Вторым значением возвращаются несекретные поля формы (для повторного показа при ошибке).
func (s *InstallService) Confirm(ctx context.Context, act Actor, id string) (string, InstallInput, error) {
	s.mu.Lock()
	p, ok := s.pending[id]
	if !ok || !p.expires.After(s.now()) || p.User != act.User {
		s.mu.Unlock()
		return "", InstallInput{}, ErrPendingGone
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	delete(s.pending, id)
	s.mu.Unlock()
	defer p.Input.Zero()
	job, err := s.Start(ctx, act, p.Input)
	return job, p.Form(), err
}

// Reject отменяет staged-запрос и возвращает его несекретные поля.
func (s *InstallService) Reject(act Actor, id string) (InstallInput, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok || p.User != act.User {
		return InstallInput{}, false
	}
	form := p.Form()
	s.dropLocked(id, p)
	return form, true
}
