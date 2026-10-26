package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
)

// SystemAPI — JSON-ручки /api/v1/system/*. Сессию и CrossOriginProtection обеспечивает Wrap.
type SystemAPI struct {
	Service  *SystemService
	ClientIP func(*http.Request) string
	Log      *slog.Logger
}

func (a *SystemAPI) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

// Routes регистрирует маршруты; wrap — RequireAuth (+Protect).
func (a *SystemAPI) Routes(mux *http.ServeMux, wrap Wrap) {
	mux.Handle("GET /api/v1/system/version", wrap.apply(http.HandlerFunc(a.version)))
	mux.Handle("GET /api/v1/system/releases", wrap.apply(http.HandlerFunc(a.releases)))
	mux.Handle("POST /api/v1/system/check", wrap.apply(http.HandlerFunc(a.check)))
	mux.Handle("POST /api/v1/system/update", wrap.apply(http.HandlerFunc(a.update)))
	mux.Handle("POST /api/v1/system/upload", wrap.apply(http.HandlerFunc(a.upload)))
}

// failJSON отвечает ошибкой сервиса «Система».
func failJSON(w http.ResponseWriter, r *http.Request, lg *slog.Logger, err error) {
	code, kind, msg := SystemFail(err)
	switch code {
	case http.StatusInternalServerError:
		lg.ErrorContext(r.Context(), "system api", "path", r.URL.Path, "err", redact.Error(err))
	case http.StatusBadGateway:
		lg.WarnContext(r.Context(), "system api: source error", "path", r.URL.Path, "err", redact.Error(err))
	}
	body := errorJSON{Error: kind, Message: msg}
	var ve *ValidationError
	if errors.As(err, &ve) {
		body.Fields = ve.Fields
	}
	writeJSON(w, code, body)
}

func (a *SystemAPI) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Service.Version())
}

func (a *SystemAPI) releases(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": a.Service.Releases()})
}

func (a *SystemAPI) check(w http.ResponseWriter, r *http.Request) {
	v, err := a.Service.Check(r.Context(), actorOf(r, a.ClientIP))
	if err != nil {
		failJSON(w, r, a.log(), err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type updateRequest struct {
	Version string `json:"version"`
}

func (a *SystemAPI) update(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	if !decode(w, r, &req) {
		return
	}
	v, err := a.Service.Install(r.Context(), actorOf(r, a.ClientIP), req.Version, r.URL.Query().Get("confirm") == ConfirmYes)
	if err != nil {
		failJSON(w, r, a.log(), err)
		return
	}
	writeJSON(w, http.StatusAccepted, v)
}

// LimitUpload ограничивает тело запроса загрузки: файл + два мета-файла + служебные части multipart.
func (s *SystemService) LimitUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.c.MaxUpload+2*maxUploadMeta+uploadSlack)
}

func (a *SystemAPI) upload(w http.ResponseWriter, r *http.Request) {
	a.Service.LimitUpload(w, r)
	mr, err := r.MultipartReader()
	if err != nil {
		failJSON(w, r, a.log(), formErr("bad_form", "ожидается multipart/form-data с полями deb, checksums, signature"))
		return
	}
	v, err := a.Service.Upload(r.Context(), actorOf(r, a.ClientIP), mr)
	if err != nil {
		failJSON(w, r, a.log(), err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// NotificationsAPI — JSON-ручки /api/v1/notifications.
type NotificationsAPI struct {
	Service  *NotificationsService
	ClientIP func(*http.Request) string
	Log      *slog.Logger
}

func (a *NotificationsAPI) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

// Routes регистрирует маршруты; wrap — RequireAuth (+Protect).
func (a *NotificationsAPI) Routes(mux *http.ServeMux, wrap Wrap) {
	mux.Handle("GET /api/v1/notifications", wrap.apply(http.HandlerFunc(a.get)))
	mux.Handle("PUT /api/v1/notifications", wrap.apply(http.HandlerFunc(a.put)))
	mux.Handle("POST /api/v1/notifications/test", wrap.apply(http.HandlerFunc(a.test)))
}

func (a *NotificationsAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "validation", Message: "Ошибка валидации.", Fields: ve.Fields})
	case errors.Is(err, ErrNotConfigured):
		writeErr(w, http.StatusNotImplemented, "not_configured", "Уведомления не настроены (notify.bot_token_file).")
	case errors.Is(err, ErrTestTooOften):
		writeErr(w, http.StatusTooManyRequests, "too_often", "Тест отправлялся совсем недавно: подождите несколько секунд.")
	default:
		a.log().ErrorContext(r.Context(), "notifications api", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "Внутренняя ошибка.")
	}
}

func (a *NotificationsAPI) get(w http.ResponseWriter, r *http.Request) {
	info, err := a.Service.Info(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

type notificationsPut struct {
	Events map[string]bool `json:"events"`
}

func (a *NotificationsAPI) put(w http.ResponseWriter, r *http.Request) {
	var req notificationsPut
	if !decode(w, r, &req) {
		return
	}
	info, err := a.Service.SetEvents(r.Context(), actorOf(r, a.ClientIP), req.Events)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (a *NotificationsAPI) test(w http.ResponseWriter, r *http.Request) {
	if err := a.Service.SendTest(r.Context(), actorOf(r, a.ClientIP)); err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"queued": true})
}
