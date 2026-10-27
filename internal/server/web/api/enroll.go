package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

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
	Audit       store.AuditRepo
	Logger      *slog.Logger
	Now         func() time.Time
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

// EnrollmentItem — выпущенные, но не использованные и не просроченные токены (без самих токенов).
type EnrollmentItem struct {
	ID        string
	Name      string
	Weight    int
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
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
		out = append(out, EnrollmentItem{ID: e.ID, Name: e.Name, Weight: e.Weight, CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt})
	}
	return out, nil
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
		return err
	}
	s.record(ctx, act, AuditEnrollRevoke, id, "")
	return nil
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
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "validation", Message: "ошибка валидации", Fields: ve.Fields})
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
