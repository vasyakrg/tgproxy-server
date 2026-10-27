package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// ErrorSource — журнал ошибок (реализует *history.Query).
type ErrorSource interface {
	Errors(ctx context.Context, cursor string, f history.Filters) (history.Page, error)
}

// ErrorsAPI — GET /api/v1/errors.
type ErrorsAPI struct {
	Source ErrorSource
	Log    *slog.Logger // nil — slog.Default()
	// Purge — очистка журнала (POST /api/v1/errors/purge); nil — маршрут не регистрируется.
	Purge    *ErrorsPurgeService
	ClientIP func(*http.Request) string // nil — пустой IP в аудите
}

// ErrorItem — запись журнала в JSON.
type ErrorItem struct {
	ID          int64     `json:"id"`
	At          time.Time `json:"at"`
	RequestID   string    `json:"request_id"`
	BotID       string    `json:"bot_id"`
	AgentID     string    `json:"agent_id"`
	Method      string    `json:"method"`
	Phase       string    `json:"phase"`
	Code        int       `json:"code"`
	Outcome     string    `json:"outcome"`
	Description string    `json:"description"`
	// ClientIP / Reason — только у отказов доступа (phase "access").
	ClientIP string `json:"client_ip,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// ErrorsPage — ответ GET /api/v1/errors.
type ErrorsPage struct {
	Items      []ErrorItem `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

// ToItem переводит запись журнала в JSON-вид; описание повторно проходит redact
// (запись могла быть сделана до очистки или в обход ErrorLog).
func ToItem(e store.ErrorEvent) ErrorItem {
	return ErrorItem{
		ID: e.ID, At: e.At, RequestID: e.RequestID, BotID: e.BotID, AgentID: e.AgentID,
		Method: e.Method, Phase: e.Phase, Code: e.Code, Outcome: string(e.Outcome),
		Description: redact.String(e.Description), ClientIP: e.ClientIP, Reason: e.Reason,
	}
}

// Routes регистрирует GET /api/v1/errors; wrap — RequireAuth (+Protect).
func (a *ErrorsAPI) Routes(mux *http.ServeMux, wrap Wrap) {
	mux.Handle("GET /api/v1/errors", wrap.apply(http.HandlerFunc(a.list)))
	if a.Purge != nil {
		mux.Handle("POST /api/v1/errors/purge", wrap.apply(http.HandlerFunc(a.purge)))
	}
}

// purge — POST /api/v1/errors/purge {"keep_days": 0|3|5|15|30}: 0 — удалить всё, иначе записи старше N дней.
// keep_days обязателен: пустое тело не должно стирать журнал.
func (a *ErrorsAPI) purge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		KeepDays *int `json:"keep_days"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.KeepDays == nil {
		writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "validation", Message: "ошибка валидации",
			Fields: FieldErrors{"keep_days": "Обязательное поле: 0 (всё), 3, 5, 15, 30"}})
		return
	}
	n, err := a.Purge.Purge(r.Context(), actorOf(r, a.ClientIP), *in.KeepDays)
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "validation", Message: "ошибка валидации", Fields: ve.Fields})
		return
	case err != nil:
		a.log().ErrorContext(r.Context(), "api: errors purge", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "Внутренняя ошибка.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": n})
}

func (a *ErrorsAPI) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := history.Filters{
		AgentID: q.Get("agent"), BotID: q.Get("bot_id"), Phase: q.Get("phase"),
		RequestID: q.Get("request_id"), Method: q.Get("method"),
		Outcome: store.ErrorOutcome(q.Get("outcome")),
		Reason:  q.Get("reason"), ClientIP: q.Get("client_ip"),
	}
	if f.Reason != "" && !access.Reason(f.Reason).Valid() {
		writeErr(w, http.StatusBadRequest, "bad_reason", "reason — no_rule, key_required, bad_key, rate_limited или banned.")
		return
	}
	if s := q.Get("code"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 999 {
			writeErr(w, http.StatusBadRequest, "bad_code", "code — HTTP-код (число).")
			return
		}
		f.Code = n
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "bad_limit", "limit — положительное число.")
			return
		}
		f.Limit = n
	}
	page, err := a.Source.Errors(r.Context(), q.Get("cursor"), f)
	if err != nil {
		if errors.Is(err, history.ErrBadCursor) {
			writeErr(w, http.StatusBadRequest, "bad_cursor", "Некорректный cursor.")
			return
		}
		a.log().ErrorContext(r.Context(), "api: errors list", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "Внутренняя ошибка.")
		return
	}
	out := ErrorsPage{Items: make([]ErrorItem, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, e := range page.Items {
		out.Items = append(out.Items, ToItem(e))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *ErrorsAPI) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}
