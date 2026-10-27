package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/enroll"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// AuditEnrollRevoke — действие аудита отзыва токена (выпуск аудирует enroll.Service). Токен в аудит не попадает.
const AuditEnrollRevoke = "enrollment.revoke"

// Поля формы токена.
const (
	FieldTTL = "ttl"
)

var enrollIDRe = regexp.MustCompile(`^[0-9a-f]{1,32}$`)

// ValidEnrollID — идентификатор токена из URL.
func ValidEnrollID(id string) bool { return enrollIDRe.MatchString(id) }

// EnrollIssuer выпускает токены (реализует *enroll.Service).
type EnrollIssuer interface {
	IssueFor(ctx context.Context, req enroll.IssueRequest) (enroll.Issued, error)
}

// EnrollConfig — зависимости EnrollService.
type EnrollConfig struct {
	Issuer      EnrollIssuer
	Enrollments store.EnrollmentRepo
	// Agents — реестр агентов: по нему определяется, что агент по токену подключился (Status).
	// nil — дальше «зарегистрирован» статус не идёт.
	Agents AgentSource
	Audit  store.AuditRepo
	Logger *slog.Logger
	Now    func() time.Time
}

// EnrollService — выпуск, список и отзыв токенов подключения агентов за NAT.
type EnrollService struct {
	cfg EnrollConfig
	log *slog.Logger
	now func() time.Time
}

// NewEnrollService создаёт сервис.
func NewEnrollService(cfg EnrollConfig) *EnrollService {
	s := &EnrollService{cfg: cfg, log: cfg.Logger, now: cfg.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Configured — выпуск токенов подключён.
func (s *EnrollService) Configured() bool {
	return s != nil && s.cfg.Issuer != nil && s.cfg.Enrollments != nil
}

// storeConfigured — доступно хранилище токенов (список и отзыв не требуют выпускающего сервиса/CA, например в CLI).
func (s *EnrollService) storeConfigured() bool { return s != nil && s.cfg.Enrollments != nil }

// EnrollInput — ввод выпуска токена.
type EnrollInput struct {
	Name   string
	Weight int
	TTL    time.Duration
}

// Issued — результат выпуска. Cmdline содержит токен и показывается один раз.
type Issued struct {
	ID      string
	Cmdline string // установка пакета с сервера + регистрация (чистый хост)
	// CmdlineInstalled — только регистрация (tgproxy уже установлен).
	CmdlineInstalled string
	ExpiresAt        time.Time
}

// Issue выпускает токен.
func (s *EnrollService) Issue(ctx context.Context, act Actor, in EnrollInput) (Issued, error) {
	if !s.Configured() {
		return Issued{}, ErrNotConfigured
	}
	fe := FieldErrors{}
	in.Name = strings.TrimSpace(in.Name)
	if !validAgentName(in.Name) {
		fe[FieldName] = "Латиница, цифры, «.», «_», «-»; до 63 символов"
	}
	if in.Weight < 1 || in.Weight > maxWeight {
		fe[FieldWeight] = "Целое от 1 до 1000"
	}
	if in.TTL < time.Minute || in.TTL > enroll.MaxTTL {
		fe[FieldTTL] = "От 1 минуты до 24 часов"
	}
	if len(fe) > 0 {
		return Issued{}, &ValidationError{Fields: fe}
	}
	is, err := s.cfg.Issuer.IssueFor(ctx, enroll.IssueRequest{Name: in.Name, Weight: in.Weight, CreatedBy: act.User, TTL: in.TTL})
	if err != nil {
		if errors.Is(err, store.ErrInvalid) {
			return Issued{}, &ValidationError{Fields: FieldErrors{FieldGeneral: "Некорректные параметры токена"}}
		}
		if errors.Is(err, enroll.ErrPackageUnavailable) {
			// Текст ошибки — для администратора («загрузите релиз X…»), секретов в нём нет.
			return Issued{}, &ValidationError{Fields: FieldErrors{FieldGeneral: err.Error()}}
		}
		return Issued{}, err
	}
	// Аудит enrollment.create пишет сам enroll.Service (без токена).
	return Issued{ID: is.ID, Cmdline: is.Cmdline, CmdlineInstalled: is.CmdlineInstalled, ExpiresAt: is.ExpiresAt}, nil
}

// errReissueTTL — срок токена перевыпуска вне допустимого диапазона.
var errReissueTTL = FieldErrors{FieldTTL: "От 1 минуты до 24 часов"}

// IssueForAgent выпускает токен перевыпуска для существующего агента: агент остаётся (вес, история),
// при подключении по токену его прежние сертификаты отзываются, режим становится reverse.
// store.ErrNotFound — агента нет.
func (s *EnrollService) IssueForAgent(ctx context.Context, act Actor, agentID string, ttl time.Duration) (Issued, error) {
	if !s.Configured() {
		return Issued{}, ErrNotConfigured
	}
	if !ValidAgentID(agentID) {
		return Issued{}, store.ErrNotFound
	}
	if ttl < time.Minute || ttl > enroll.MaxTTL {
		return Issued{}, &ValidationError{Fields: errReissueTTL}
	}
	is, err := s.cfg.Issuer.IssueFor(ctx, enroll.IssueRequest{AgentID: agentID, CreatedBy: act.User, TTL: ttl})
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrReenrollUnavailable):
			return Issued{}, ErrNotConfigured
		case errors.Is(err, store.ErrInvalid):
			return Issued{}, &ValidationError{Fields: FieldErrors{FieldGeneral: "Некорректные параметры токена"}}
		case errors.Is(err, enroll.ErrPackageUnavailable):
			return Issued{}, &ValidationError{Fields: FieldErrors{FieldGeneral: err.Error()}}
		}
		return Issued{}, err
	}
	return Issued{ID: is.ID, Cmdline: is.Cmdline, CmdlineInstalled: is.CmdlineInstalled, ExpiresAt: is.ExpiresAt}, nil
}

// EnrollmentItem — выпущенные, но не использованные и не просроченные токены (без самих токенов).
type EnrollmentItem struct {
	ID        string
	Name      string
	Weight    int
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	// AgentID — токен перевыпуска для существующего агента; пусто — токен нового агента.
	AgentID string
}

// List возвращает ожидающие токены.
func (s *EnrollService) List(ctx context.Context) ([]EnrollmentItem, error) {
	if !s.storeConfigured() {
		return nil, ErrNotConfigured
	}
	items, err := s.cfg.Enrollments.ListPending(ctx, s.now())
	if err != nil {
		return nil, err
	}
	out := make([]EnrollmentItem, 0, len(items))
	for _, e := range items {
		out = append(out, EnrollmentItem{ID: e.ID, Name: e.Name, Weight: e.Weight, CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt, AgentID: e.AgentID})
	}
	return out, nil
}

// Состояния токена подключения (Status).
const (
	EnrollWaiting   = "waiting"   // токен не использован и не истёк
	EnrollEnrolled  = "enrolled"  // токен использован, агент зарегистрирован, соединения ещё нет
	EnrollConnected = "connected" // агент зарегистрирован и в работе
	EnrollExpired   = "expired"   // истёк неиспользованным
	EnrollRevoked   = "revoked"   // записи нет: отозван (или убран очисткой после истечения)
)

// EnrollStatus — состояние токена для отслеживания подключения. Ни токена, ни хеша здесь нет.
type EnrollStatus struct {
	State   string
	Name    string // имя из токена (пусто для revoked)
	AgentID string // id агента (enrolled и connected; для токена перевыпуска — с самого выпуска)
	// Reissue — токен перевыпуска для существующего агента.
	Reissue   bool
	ExpiresAt time.Time
	Left      time.Duration // сколько жить неиспользованному токену (waiting); иначе 0
}

// Status определяет состояние токена по его id: ErrNotConfigured, если хранилище не подключено.
func (s *EnrollService) Status(ctx context.Context, id string) (EnrollStatus, error) {
	if !s.storeConfigured() {
		return EnrollStatus{}, ErrNotConfigured
	}
	e, err := s.cfg.Enrollments.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return EnrollStatus{State: EnrollRevoked}, nil
	}
	if err != nil {
		return EnrollStatus{}, err
	}
	st := EnrollStatus{Name: e.Name, ExpiresAt: e.ExpiresAt, AgentID: e.AgentID, Reissue: e.AgentID != ""}
	if a, ok := s.cfg.agentByID(e.AgentID); ok && e.AgentID != "" {
		st.Name = agentTitle(a.Agent) // у токена перевыпуска имя — id, в UI показываем имя агента
	}
	if e.UsedAt == nil {
		now := s.now()
		if !e.ExpiresAt.After(now) {
			st.State = EnrollExpired
			return st, nil
		}
		st.State, st.Left = EnrollWaiting, e.ExpiresAt.Sub(now)
		return st, nil
	}
	// Токен использован: агент создаётся сразу после гашения, id — slug имени (возможно с суффиксом),
	// поэтому ищем по имени среди агентов, созданных не раньше выпуска токена.
	st.State = EnrollEnrolled
	if e.AgentID != "" {
		// Перевыпуск: агент уже существовал, поэтому «подключился» — первое успешное
		// наблюдение ПОСЛЕ погашения токена (иначе сработало бы старое соединение).
		if a, ok := s.cfg.agentByID(e.AgentID); ok && a.Up && a.LastSeen.After(*e.UsedAt) {
			st.State = EnrollConnected
		}
		return st, nil
	}
	if a, ok := s.enrolledAgent(e); ok {
		st.AgentID = a.Agent.ID
		if a.Up {
			st.State = EnrollConnected
		}
	}
	return st, nil
}

func (c EnrollConfig) agentByID(id string) (agents.State, bool) {
	if c.Agents == nil {
		return agents.State{}, false
	}
	return c.Agents.Get(id)
}

// enrolledAgent находит агента, созданного по токену; при нескольких предпочитает работающего.
func (s *EnrollService) enrolledAgent(e store.Enrollment) (agents.State, bool) {
	if s.cfg.Agents == nil {
		return agents.State{}, false
	}
	since := e.CreatedAt.Truncate(time.Second)
	var best agents.State
	found := false
	for _, a := range s.cfg.Agents.List() {
		if a.Agent.Name != e.Name || a.Agent.Mode != store.ModeReverse || (!a.Agent.CreatedAt.IsZero() && a.Agent.CreatedAt.Before(since)) {
			continue
		}
		if !found || (a.Up && !best.Up) {
			best, found = a, true
		}
	}
	return best, found
}

// Revoke отзывает неиспользованный токен. confirm обязателен.
func (s *EnrollService) Revoke(ctx context.Context, act Actor, id string, confirm bool) error {
	if !s.storeConfigured() {
		return ErrNotConfigured
	}
	if !confirm {
		return ErrConfirmRequired
	}
	if err := s.cfg.Enrollments.Delete(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return s.revokeNotFound(ctx, id, err)
		}
		return err
	}
	s.record(ctx, act, AuditEnrollRevoke, id, "")
	return nil
}

// EnrollUsedError — отзыв токена, который уже использован, а агент по нему зарегистрирован.
// Unwrap даёт store.ErrNotFound: для вызывающих без различения случаев поведение прежнее.
type EnrollUsedError struct {
	AgentID   string
	AgentName string
}

func (e *EnrollUsedError) Error() string {
	return "токен уже использован: агент «" + e.AgentName + "» зарегистрирован"
}

func (e *EnrollUsedError) Unwrap() error { return store.ErrNotFound }

// revokeNotFound отличает «токен уже использован, агент зарегистрирован» от «не найден, истёк или отозван».
func (s *EnrollService) revokeNotFound(ctx context.Context, id string, notFound error) error {
	e, err := s.cfg.Enrollments.Get(ctx, id)
	if err != nil || e.UsedAt == nil {
		return notFound
	}
	if e.AgentID != "" {
		if a, ok := s.cfg.agentByID(e.AgentID); ok {
			return &EnrollUsedError{AgentID: a.Agent.ID, AgentName: agentTitle(a.Agent)}
		}
		return notFound
	}
	if a, ok := s.enrolledAgent(e); ok {
		return &EnrollUsedError{AgentID: a.Agent.ID, AgentName: agentTitle(a.Agent)}
	}
	return notFound
}

func agentTitle(a store.Agent) string {
	if a.Name != "" {
		return a.Name
	}
	return a.ID
}

func (s *EnrollService) record(ctx context.Context, act Actor, action, target, detail string) {
	if s.cfg.Audit == nil {
		return
	}
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	if _, err := s.cfg.Audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: action, Target: target, IP: act.IP, Detail: detail,
	}); err != nil {
		s.log.ErrorContext(ctx, "enrollment audit failed", "action", action, "target", target, "err", err)
	}
}

// ---------- JSON API ----------

// EnrollAPI — JSON-хендлеры /api/v1/enrollments.
type EnrollAPI struct {
	Service  *EnrollService
	ClientIP func(*http.Request) string
	Log      *slog.Logger
}

// Routes регистрирует маршруты; wrap — Protect + RequireAuth.
func (a *EnrollAPI) Routes(m Registrar, wrap Wrap) {
	m.Handle("GET /api/v1/enrollments", wrap.apply(http.HandlerFunc(a.list)))
	m.Handle("POST /api/v1/enrollments", wrap.apply(http.HandlerFunc(a.create)))
	m.Handle("DELETE /api/v1/enrollments/{id}", wrap.apply(http.HandlerFunc(a.revoke)))
	m.Handle("POST /api/v1/agents/{id}/enroll-token", wrap.apply(http.HandlerFunc(a.reissue)))
}

type enrollJSON struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Weight    int    `json:"weight"`
	CreatedBy string `json:"created_by,omitempty"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

type enrollCreatedJSON struct {
	ID        string `json:"id"`
	Cmdline   string `json:"cmdline"`           // установка + регистрация; содержит токен: показывается один раз
	Installed string `json:"cmdline_installed"` // только регистрация (tgproxy уже установлен)
	ExpiresAt string `json:"expires_at"`
}

func (a *EnrollAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	var used *EnrollUsedError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "validation", Message: "ошибка валидации", Fields: ve.Fields})
	case errors.As(err, &used):
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found", Message: used.Error()})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found"})
	case errors.Is(err, ErrConfirmRequired):
		writeJSON(w, http.StatusBadRequest, errorJSON{Error: "confirm_required", Message: "Требуется подтверждение (confirm=yes)."})
	case errors.Is(err, ErrNotConfigured):
		writeJSON(w, http.StatusNotImplemented, errorJSON{Error: "not_configured", Message: "Подключение агентов за NAT не настроено на сервере."})
	default:
		lg := a.Log
		if lg == nil {
			lg = slog.Default()
		}
		lg.ErrorContext(r.Context(), "enrollments api", "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorJSON{Error: "internal"})
	}
}

func (a *EnrollAPI) list(w http.ResponseWriter, r *http.Request) {
	items, err := a.Service.List(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]enrollJSON, 0, len(items))
	for _, e := range items {
		out = append(out, enrollJSON{
			ID: e.ID, Name: e.Name, Weight: e.Weight, CreatedBy: e.CreatedBy,
			CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (a *EnrollAPI) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name       string `json:"name"`
		Weight     int    `json:"weight"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Weight == 0 {
		in.Weight = DefaultWeight
	}
	if in.TTLMinutes == 0 {
		in.TTLMinutes = 60
	}
	is, err := a.Service.Issue(r.Context(), actorOf(r, a.ClientIP), EnrollInput{
		Name: in.Name, Weight: in.Weight, TTL: time.Duration(in.TTLMinutes) * time.Minute,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/enrollments/"+is.ID)
	writeJSON(w, http.StatusCreated, enrollCreatedJSON{ID: is.ID, Cmdline: is.Cmdline, Installed: is.CmdlineInstalled, ExpiresAt: is.ExpiresAt.UTC().Format(time.RFC3339)})
}

// reissue — POST /api/v1/agents/{id}/enroll-token: токен перевыпуска для существующего агента.
func (a *EnrollAPI) reissue(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !ValidAgentID(id) {
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found"})
		return
	}
	var in struct {
		TTLMinutes int `json:"ttl_minutes"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	if in.TTLMinutes == 0 {
		in.TTLMinutes = 60
	}
	is, err := a.Service.IssueForAgent(r.Context(), actorOf(r, a.ClientIP), id, time.Duration(in.TTLMinutes)*time.Minute)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/enrollments/"+is.ID)
	writeJSON(w, http.StatusCreated, enrollCreatedJSON{ID: is.ID, Cmdline: is.Cmdline, Installed: is.CmdlineInstalled, ExpiresAt: is.ExpiresAt.UTC().Format(time.RFC3339)})
}

func (a *EnrollAPI) revoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !ValidEnrollID(id) {
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found"})
		return
	}
	if err := a.Service.Revoke(r.Context(), actorOf(r, a.ClientIP), id, r.URL.Query().Get("confirm") == ConfirmYes); err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
