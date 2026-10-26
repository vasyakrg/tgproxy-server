package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// AuditAgentEmergency — действие аудита аварийного обновления агента по SSH.
const AuditAgentEmergency = "agent.emergency_update"

// EmergencyUpdater — аварийное обновление по SSH (*installer.Installer).
type EmergencyUpdater interface {
	EmergencyUpdate(ctx context.Context, agentID, version string) (string, error)
}

// EmergencyService — запуск аварийного обновления с подтверждением и аудитом
// (общий для JSON API и HTML-экрана).
type EmergencyService struct {
	Updater EmergencyUpdater
	Audit   store.AuditRepo
	Log     *slog.Logger
	Now     func() time.Time
}

// Configured — установщик подключён.
func (s *EmergencyService) Configured() bool { return s != nil && s.Updater != nil }

// Start запускает аварийное обновление агента id до версии version (с «v» или без) и возвращает id задачи.
// confirm обязателен: действие обходит штатный канал и перезапускает агента.
func (s *EmergencyService) Start(ctx context.Context, act Actor, id, version string, confirm bool) (string, error) {
	if !s.Configured() {
		return "", ErrNotConfigured
	}
	if !ValidAgentID(id) {
		return "", store.ErrNotFound
	}
	if !confirm {
		return "", ErrConfirmRequired
	}
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	// Задача живёт дольше HTTP-запроса: installer берёт ctx только для проверок.
	job, err := s.Updater.EmergencyUpdate(ctx, id, version)
	if err != nil {
		return "", err
	}
	s.record(ctx, act, id, fmt.Sprintf("version=%s job=%s", version, job))
	return job, nil
}

func (s *EmergencyService) record(ctx context.Context, act Actor, target, detail string) {
	if s.Audit == nil {
		return
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	user := act.User
	if user == "" {
		user = "-"
	}
	if _, err := s.Audit.Append(ctx, store.AuditEntry{At: now(), Actor: user, Action: AuditAgentEmergency, Target: target, IP: act.IP, Detail: detail}); err != nil {
		s.log().ErrorContext(ctx, "emergency audit failed", "agent", target, "err", err)
	}
}

func (s *EmergencyService) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// EmergencyFail переводит ошибку запуска в HTTP-код, вид и текст. Тексты не содержат секретов.
func EmergencyFail(err error) (code int, kind, msg string) {
	var unknown *installer.ErrHostKeyUnknown
	switch {
	case errors.Is(err, ErrNotConfigured):
		return http.StatusNotImplemented, "not_configured", "Установка по SSH не настроена на сервере."
	case errors.Is(err, ErrConfirmRequired):
		return http.StatusBadRequest, "confirm_required", "Требуется подтверждение (confirm=yes)."
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not_found", "Агент не найден."
	case errors.Is(err, installer.ErrNoSSHTarget):
		return http.StatusConflict, "no_ssh_target", "У агента нет сохранённой SSH-цели: аварийное обновление недоступно. Переустановите агента по SSH."
	case errors.Is(err, installer.ErrEmergencyBusy):
		return http.StatusConflict, "busy", "Для этого агента аварийное обновление уже выполняется."
	case errors.As(err, &unknown):
		return http.StatusConflict, "host_key_unknown", "Ключ хоста агента не закреплён."
	case errors.Is(err, installer.ErrHostKeyMismatch):
		return http.StatusConflict, "host_key_mismatch", "Ключ хоста отличается от закреплённого: возможна подмена. Если хост переустановлен — выполните на сервере: tgproxy hostkeys forget <host:port>"
	case errors.Is(err, installer.ErrBadVersion):
		return http.StatusUnprocessableEntity, "bad_version", "Некорректная версия (ожидается 1.2.3)."
	case errors.Is(err, installer.ErrNoPackage):
		return http.StatusUnprocessableEntity, "no_package", "Релиз этой версии не найден в кэше загрузок сервера: сначала скачайте его на экране «Система»."
	}
	return http.StatusInternalServerError, "internal", "Внутренняя ошибка."
}

// EmergencyAPI — POST /api/v1/agents/{id}/emergency-update?confirm=yes {version}.
// Ответ 202 {id, events_url}: ход задачи — как у установки (/api/v1/install-jobs/{id}[/events]).
type EmergencyAPI struct {
	Service  *EmergencyService
	ClientIP func(*http.Request) string
	Log      *slog.Logger
}

// Routes регистрирует маршрут; wrap — Protect + RequireAuth.
func (a *EmergencyAPI) Routes(m Registrar, wrap Wrap) {
	m.Handle("POST /api/v1/agents/{id}/emergency-update", wrap.apply(http.HandlerFunc(a.start)))
}

func (a *EmergencyAPI) start(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !ValidAgentID(id) {
		writeErr(w, http.StatusNotFound, "not_found", "Агент не найден.")
		return
	}
	var b updateBody
	if !decodeBody(w, r, &b) {
		return
	}
	job, err := a.Service.Start(r.Context(), actorOf(r, a.ClientIP), id, b.Version, r.URL.Query().Get("confirm") == ConfirmYes)
	if err != nil {
		code, kind, msg := EmergencyFail(err)
		if code == http.StatusInternalServerError {
			l := a.Log
			if l == nil {
				l = slog.Default()
			}
			l.ErrorContext(r.Context(), "emergency api", "agent", id, "err", redact.Error(err))
		}
		writeErr(w, code, kind, msg)
		return
	}
	w.Header().Set("Location", "/api/v1/install-jobs/"+job)
	writeJSON(w, http.StatusAccepted, jobCreatedJSON{ID: job, EventsURL: "/api/v1/install-jobs/" + job + "/events"})
}
