package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
)

// Stats — источник метрик (реализует *history.Query).
type Stats interface {
	Timeseries(ctx context.Context, rng history.Range, agentID string, since time.Time) (history.Series, error)
	Summary(ctx context.Context) (history.KPI, error)
}

// AgentLister — реестр агентов для счётчика «в работе / всего» (реализует *agents.Registry).
type AgentLister interface {
	List() []agents.State
}

// LiveInflight — живой счётчик запросов в полёте.
type LiveInflight interface {
	LiveInflight() int
}

// StatsAPI — /api/v1/stats/{summary,timeseries}.
type StatsAPI struct {
	Stats  Stats
	Agents AgentLister  // nil — agents_up/agents_total = 0
	Live   LiveInflight // nil — inflight из последнего снимка истории
	Log    *slog.Logger // nil — slog.Default()
}

// Summary — ответ GET /api/v1/stats/summary.
type Summary struct {
	RPS         float64   `json:"rps"`
	ProxyErrPct float64   `json:"proxy_err_pct"`
	R429        int64     `json:"r429"`
	Inflight    int       `json:"inflight"`
	PeakRPS     float64   `json:"peak_rps"`
	PeakAt      time.Time `json:"peak_at"`
	AgentsUp    int       `json:"agents_up"`
	AgentsTotal int       `json:"agents_total"`
}

// Routes регистрирует маршруты; wrap — RequireAuth (+Protect), применяется к каждому.
func (a *StatsAPI) Routes(mux *http.ServeMux, wrap Wrap) {
	mux.Handle("GET /api/v1/stats/summary", wrap.apply(http.HandlerFunc(a.summary)))
	mux.Handle("GET /api/v1/stats/timeseries", wrap.apply(http.HandlerFunc(a.timeseries)))
}

func (a *StatsAPI) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func (a *StatsAPI) summary(w http.ResponseWriter, r *http.Request) {
	k, err := a.Stats.Summary(r.Context())
	if err != nil {
		a.log().ErrorContext(r.Context(), "api: stats summary", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "Внутренняя ошибка.")
		return
	}
	if a.Live != nil {
		k.Inflight = a.Live.LiveInflight()
	}
	s := Summary{
		RPS: k.RPS, ProxyErrPct: k.ProxyErrPct, R429: k.R429, Inflight: k.Inflight,
		PeakRPS: k.PeakRPS, PeakAt: k.PeakAt,
	}
	if a.Agents != nil {
		list := a.Agents.List()
		s.AgentsTotal = len(list)
		for _, st := range list {
			if st.Up {
				s.AgentsUp++
			}
		}
	}
	writeJSON(w, http.StatusOK, s)
}

func (a *StatsAPI) timeseries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rangeStr := q.Get("range")
	if rangeStr == "" {
		rangeStr = string(history.Range24h)
	}
	rng, err := history.ParseRange(rangeStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_range", "Допустимые значения range: 1h, 6h, 24h, 7d.")
		return
	}
	var since time.Time
	if s := q.Get("since"); s != "" {
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "bad_since", "since — unix-секунды.")
			return
		}
		since = time.Unix(n, 0)
	}
	series, err := a.Stats.Timeseries(r.Context(), rng, q.Get("agent"), since)
	if err != nil {
		if errors.Is(err, history.ErrBadRange) {
			writeErr(w, http.StatusBadRequest, "bad_range", "Некорректный range.")
			return
		}
		a.log().ErrorContext(r.Context(), "api: stats timeseries", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "Внутренняя ошибка.")
		return
	}
	writeJSON(w, http.StatusOK, series)
}
