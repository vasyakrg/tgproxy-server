package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
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
		Description: redact.String(e.Description),
	}
}

// Routes регистрирует GET /api/v1/errors; wrap — RequireAuth (+Protect).
func (a *ErrorsAPI) Routes(mux *http.ServeMux, wrap Wrap) {
	mux.Handle("GET /api/v1/errors", wrap.apply(http.HandlerFunc(a.list)))
}

func (a *ErrorsAPI) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := history.Filters{
		AgentID: q.Get("agent"), BotID: q.Get("bot_id"), Phase: q.Get("phase"),
		RequestID: q.Get("request_id"), Method: q.Get("method"),
		Outcome: store.ErrorOutcome(q.Get("outcome")),
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
