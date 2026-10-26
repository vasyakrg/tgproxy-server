// Package proxy — публичный HTTP-обработчик Bot API прокси.
package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Описания ошибок для ботов.
const (
	descNotFound = "Not Found"
	descDenied   = "tgproxy: access denied"
	descWebhook  = "tgproxy: webhooks unsupported, use getUpdates"
	descTooLarge = "Request Entity Too Large"
)

// Router отправляет запрос агенту (реализует internal/server/router.Router).
// Ошибки со статусом ответа реализуют HTTPStatus() int и Description() string.
type Router interface {
	Do(ctx context.Context, req *http.Request, route tgapi.Route) (*http.Response, error)
}

type statusError interface {
	error
	HTTPStatus() int
	Description() string
}

// Handler — http.Handler публичного прокси.
type Handler struct {
	checker *access.Checker
	router  Router
	cfg     *config.ServerConfig
	log     *slog.Logger
	rec     Recorder
	bots    BotObserver
}

// New создаёт Handler. logger должен быть обёрнут redact-хендлером.
func New(checker *access.Checker, router Router, cfg *config.ServerConfig, logger *slog.Logger, opts ...Option) http.Handler {
	h := &Handler{checker: checker, router: router, cfg: cfg, log: logger, rec: noopRecorder{}}
	for _, o := range opts {
		o(h)
	}
	return h
}

// ServeHTTP обрабатывает запрос бота.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := requestID(r)
	sw := &statusWriter{ResponseWriter: w}
	w = sw
	w.Header().Set(tgapi.HeaderRequestID, id)

	var (
		rule  string
		botID int64
		route tgapi.Route
	)
	internal := notify.IsInternal(r.Context())
	defer func() {
		h.observe(internal, rule, route.Method, botID, sw.status)
		h.log.Info("request",
			"request_id", id, "rule", rule, "bot_id", botID, "method", route.Method,
			"status", sw.status, "duration", time.Since(start))
	}()

	route, err := tgapi.ParsePath(r.URL.EscapedPath())
	if err != nil {
		tgapi.WriteError(w, http.StatusNotFound, descNotFound, 0)
		return
	}
	botID = route.BotID

	info, err := h.checker.Check(r, route)
	if err != nil {
		var rl *access.RateLimitedError
		if errors.As(err, &rl) {
			secs := max(int(math.Ceil(rl.RetryAfter.Seconds())), 1)
			tgapi.WriteError(w, http.StatusTooManyRequests, "Too Many Requests: retry after "+strconv.Itoa(secs), secs)
			return
		}
		tgapi.WriteError(w, http.StatusForbidden, descDenied, 0)
		return
	}
	rule = info.Name

	if tgapi.IsWebhookSetter(route.Method) {
		if h.cfg.WebhookPolicy != config.WebhookPassthrough {
			h.rec.WebhookBlocked()
			tgapi.WriteError(w, http.StatusForbidden, descWebhook, 0)
			return
		}
		h.log.Warn("setWebhook passthrough", "request_id", id, "rule", rule, "bot_id", botID)
	}

	limit := h.cfg.Buffer.BodyMax
	if r.ContentLength > limit {
		tgapi.WriteError(w, http.StatusRequestEntityTooLarge, descTooLarge, 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	cleanRequestHeaders(r.Header, id, botID)

	resp, err := h.router.Do(r.Context(), r, route)
	if err != nil {
		h.writeErr(w, r, err, id)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests {
		h.rec.Telegram429(rule)
	}

	copyResponseHeaders(w.Header(), resp.Header, id)
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(flushWriter{w: w, rc: http.NewResponseController(w)}, resp.Body); err != nil {
		h.log.Debug("response stream aborted", "request_id", id, "error", redact.Error(err))
	}
}

func (h *Handler) writeErr(w http.ResponseWriter, r *http.Request, err error, id string) {
	var mb *http.MaxBytesError
	var se statusError
	switch {
	case errors.As(err, &mb):
		tgapi.WriteError(w, http.StatusRequestEntityTooLarge, descTooLarge, 0)
	case errors.As(err, &se):
		tgapi.WriteError(w, se.HTTPStatus(), se.Description(), 0)
	case r.Context().Err() != nil:
		// клиент ушёл — писать некому
		w.WriteHeader(499)
	default:
		h.log.Error("router failed", "request_id", id, "error", redact.Error(err))
		tgapi.WriteError(w, http.StatusBadGateway, "tgproxy: no healthy agents", 0)
	}
}

// requestID принимает входящий X-Request-ID только если это валидный ULID.
func requestID(r *http.Request) string {
	if v := r.Header.Get(tgapi.HeaderRequestID); v != "" {
		if _, err := ulid.ParseStrict(v); err == nil {
			return v
		}
	}
	return ulid.Make().String()
}

// flushWriter сбрасывает буфер после каждой записи (long-poll, файлы).
type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		_ = f.rc.Flush() // ErrNotSupported игнорируем
	}
	return n, err
}

// statusWriter запоминает код ответа для access-лога.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(p)
}

// Unwrap нужен http.ResponseController.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
