package history

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Range — диапазон графика.
type Range string

// Поддерживаемые диапазоны.
const (
	Range1h  Range = "1h"
	Range6h  Range = "6h"
	Range24h Range = "24h"
	Range7d  Range = "7d"
)

// ErrBadRange / ErrBadCursor — ошибки входных данных (→ HTTP 400/422).
var (
	ErrBadRange  = errors.New("history: bad range")
	ErrBadCursor = errors.New("history: bad cursor")
)

// ParseRange проверяет строку диапазона.
func ParseRange(s string) (Range, error) {
	switch r := Range(s); r {
	case Range1h, Range6h, Range24h, Range7d:
		return r, nil
	}
	return "", fmt.Errorf("%w: %q", ErrBadRange, s)
}

func (r Range) spec() (dur time.Duration, res store.Resolution, step time.Duration) {
	switch r {
	case Range1h:
		return time.Hour, store.Res10s, Step10s
	case Range6h:
		return 6 * time.Hour, store.Res10s, Step10s
	case Range24h:
		return 24 * time.Hour, store.Res5m, Step5m
	default: // Range7d
		return 7 * 24 * time.Hour, store.Res5m, Step5m
	}
}

// Point — точка графика (JSON для uPlot; t — unix-секунды начала интервала).
type Point struct {
	T        int64   `json:"t"`
	OKRPS    float64 `json:"ok_rps"`
	ErrRPS   float64 `json:"err_rps"`
	R429RPS  float64 `json:"r429_rps"`
	P95Ms    float64 `json:"p95_ms"`
	Inflight int     `json:"inflight"`
}

// Series — ответ Timeseries.
type Series struct {
	Range   Range   `json:"range"`
	StepSec int     `json:"step_sec"`
	Agent   string  `json:"agent"`
	Points  []Point `json:"points"`
}

// KPI — сводка для экрана «Обзор»: RPS/ошибки/429 за последние 5 минут (10s-данные),
// Inflight — последнее значение, Peak — максимум rps за 24ч.
type KPI struct {
	RPS         float64   `json:"rps"`
	ProxyErrPct float64   `json:"proxy_err_pct"`
	R429        int64     `json:"r429"`
	Inflight    int       `json:"inflight"`
	PeakRPS     float64   `json:"peak_rps"`
	PeakAt      time.Time `json:"peak_at"`
}

// Filters — фильтры журнала ошибок (пустое/0 — не фильтровать).
type Filters struct {
	AgentID   string
	BotID     string
	Phase     string
	Code      int
	RequestID string
	Method    string
	Outcome   store.ErrorOutcome
	Limit     int // 0 → 50, максимум 200
}

// Page — страница журнала ошибок.
type Page struct {
	Items      []store.ErrorEvent `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

// Query — чтение истории для API.
type Query struct {
	History   store.HistoryRepo
	ErrorRepo store.ErrorEventRepo
	Now       func() time.Time // nil → time.Now
}

func (q *Query) now() time.Time {
	if q.Now != nil {
		return q.Now()
	}
	return time.Now()
}

// Timeseries возвращает ряд агрегата (agentID "") или одного агента. 1h/6h берутся из
// 10s, 24h/7d — из 5m (последнее окно появляется после его завершения). since — только
// точки строго новее since (инкрементальный опрос).
func (q *Query) Timeseries(ctx context.Context, rng Range, agentID string, since time.Time) (Series, error) {
	if _, err := ParseRange(string(rng)); err != nil {
		return Series{}, err
	}
	dur, res, step := rng.spec()
	id := agentID
	if id == "" {
		id = AggregateID
	}
	now := q.now()
	from := now.Add(-dur)
	if since.After(from) {
		from = since
	}
	rows, err := q.History.Range(ctx, res, id, from, now)
	if err != nil {
		return Series{}, err
	}
	sec := step.Seconds()
	s := Series{Range: rng, StepSec: int(sec), Agent: agentID, Points: make([]Point, 0, len(rows))}
	for _, r := range rows {
		if !since.IsZero() && !r.At.After(since) {
			continue
		}
		s.Points = append(s.Points, Point{
			T: r.At.Unix(), OKRPS: float64(r.OK) / sec, ErrRPS: float64(r.Err) / sec,
			R429RPS: float64(r.RateLimited) / sec, P95Ms: r.P95Ms, Inflight: r.Inflight,
		})
	}
	return s, nil
}

// Summary считает KPI по агрегату.
func (q *Query) Summary(ctx context.Context) (KPI, error) {
	now := q.now()
	rows, err := q.History.Range(ctx, store.Res10s, AggregateID, now.Add(-Retention10s), now)
	if err != nil {
		return KPI{}, err
	}
	var k KPI
	recent := now.Add(-5 * time.Minute)
	var total, errs int64
	for _, r := range rows {
		n := r.OK + r.Err + r.RateLimited
		if rps := float64(n) / Step10s.Seconds(); rps > k.PeakRPS {
			k.PeakRPS, k.PeakAt = rps, r.At
		}
		if r.At.Before(recent) {
			continue
		}
		total += n
		errs += r.Err
		k.R429 += r.RateLimited
		k.Inflight = r.Inflight // rows отсортированы по времени: останется последнее
	}
	k.RPS = float64(total) / (5 * time.Minute).Seconds()
	if total > 0 {
		k.ProxyErrPct = float64(errs) * 100 / float64(total)
	}
	return k, nil
}

const (
	defaultErrLimit = 50
	maxErrLimit     = 200
)

// Errors возвращает страницу журнала (новые первыми). Курсор — id последней
// записи страницы: вставки новых записей между запросами страницы не сдвигают.
func (q *Query) Errors(ctx context.Context, cursor string, f Filters) (Page, error) {
	before, err := decodeCursor(cursor)
	if err != nil {
		return Page{}, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultErrLimit
	}
	limit = min(limit, maxErrLimit)
	items, err := q.ErrorRepo.List(ctx, store.ErrorQuery{
		BeforeID: before, Limit: limit + 1, AgentID: f.AgentID, BotID: f.BotID, Method: f.Method,
		Outcome: f.Outcome, Phase: f.Phase, Code: f.Code, RequestID: f.RequestID,
	})
	if err != nil {
		return Page{}, err
	}
	p := Page{Items: items}
	if len(items) > limit {
		p.Items = items[:limit]
		p.NextCursor = encodeCursor(items[limit-1].ID)
	}
	return p, nil
}

func encodeCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

func decodeCursor(c string) (int64, error) {
	if c == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, ErrBadCursor
	}
	id, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil || id <= 0 {
		return 0, ErrBadCursor
	}
	return id, nil
}
