package screens

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Пути JSON-API, которые читает charts.js (data-* атрибуты графика).
const (
	TimeseriesPath = "/api/v1/stats/timeseries"
	SummaryPath    = "/api/v1/stats/summary"
)

// Интервал опроса графика: по умолчанию и допустимые границы.
const (
	DefaultPollInterval = 5 * time.Second
	MinPollInterval     = 2 * time.Second
	MaxPollInterval     = 5 * time.Second
	eventsLimit         = 6
	agentWindow         = 5 * time.Minute
)

// Stats — источник метрик Обзора (реализует *history.Query).
type Stats interface {
	Timeseries(ctx context.Context, rng history.Range, agentID string, since time.Time) (history.Series, error)
	Summary(ctx context.Context) (history.KPI, error)
}

// LiveInflight — живой счётчик запросов в полёте (источник KPI «In-flight сейчас»).
type LiveInflight interface {
	LiveInflight() int
}

// Event — уведомление для ленты «События» (обычно строка outbox).
type Event struct {
	At      time.Time
	AgentID string
	Type    string // agent_down, agent_degraded, version_mismatch, ...
	State   string // "firing" | "resolved"
	Text    string // текст алерта; проходит redact при выводе
	Sent    bool   // доставлено в Telegram
}

// EventSource — последние уведомления, новые первыми. Реализацию даёт wiring (поверх store.OutboxRepo).
type EventSource interface {
	RecentEvents(ctx context.Context, limit int) ([]Event, error)
}

// OverviewDeps — зависимости экрана «Обзор».
type OverviewDeps struct {
	Shell         Shell
	Stats         Stats
	Agents        AgentLister    // nil — таблица пуста
	Events        EventSource    // nil — лента пуста
	Live          LiveInflight   // nil — берётся последний снимок истории
	ServerVersion string         // версия агента ≠ серверной подсвечивается
	PollInterval  time.Duration  // 0 → 5 с; зажимается в [2 с, 5 с]
	Location      *time.Location // nil → time.Local
	Now           func() time.Time
	Log           *slog.Logger
}

type overview struct{ OverviewDeps }

// NewOverview возвращает хендлер Обзора: полная страница или (htmx) фрагмент #overview.
// Подключать через web.Router.SetOverview.
func NewOverview(d OverviewDeps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Location == nil {
		d.Location = time.Local
	}
	switch {
	case d.PollInterval <= 0:
		d.PollInterval = DefaultPollInterval
	case d.PollInterval < MinPollInterval:
		d.PollInterval = MinPollInterval
	case d.PollInterval > MaxPollInterval:
		d.PollInterval = MaxPollInterval
	}
	return &overview{d}
}

func (o *overview) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rng := history.Range24h
	if s := r.URL.Query().Get("range"); s != "" {
		if p, err := history.ParseRange(s); err == nil {
			rng = p
		}
	}
	vm := o.build(r.Context(), rng)
	if isFragment(r) {
		renderFragment(w, r, http.StatusOK, OverviewBody(vm)) //nolint:contextcheck // templ
		return
	}
	renderPage(o.Shell, w, r, http.StatusOK, "Обзор", views.NavOverview, OverviewPage(vm)) //nolint:contextcheck // templ
}

// ---------- модель представления ----------

// KPIView — карточка показателя.
type KPIView struct {
	Key, Label, Value, Hint string
	Tone                    views.Tone
}

// RangeOpt — кнопка переключателя периода.
type RangeOpt struct {
	Value, Label string
	Active       bool
}

// AgentRow — строка таблицы агентов.
type AgentRow struct {
	Name, Addr    string
	Status        views.Status
	RPS, P95      string
	P95Hint       string // не пусто — p95 ненадёжен («мало данных»), показывается приглушённо с title
	Err, Inflight string
	InflightLP    string // «lp N» — висящие getUpdates
	Version       string
	VersionStale  bool
}

// EventRow — строка ленты событий.
type EventRow struct {
	Tone       string // ok | warn | err | tg
	Text, Meta string
}

// OverviewVM — всё, что нужно шаблону Обзора.
type OverviewVM struct {
	Range                     history.Range
	Ranges                    []RangeOpt
	PollMS                    int
	PollSec                   int
	KPIs                      []KPIView
	Agents                    []AgentRow
	Events                    []EventRow
	TimeseriesURL, SummaryURL string
}

var rangeLabels = []RangeOpt{{Value: "1h", Label: "1ч"}, {Value: "6h", Label: "6ч"}, {Value: "24h", Label: "24ч"}, {Value: "7d", Label: "7д"}}

func (o *overview) build(ctx context.Context, rng history.Range) OverviewVM {
	now := o.Now()
	vm := OverviewVM{
		Range: rng, PollMS: int(o.PollInterval / time.Millisecond), PollSec: int(o.PollInterval / time.Second),
		TimeseriesURL: TimeseriesPath, SummaryURL: SummaryPath,
	}
	for _, ro := range rangeLabels {
		ro.Active = ro.Value == string(rng)
		vm.Ranges = append(vm.Ranges, ro)
	}

	var kpi history.KPI
	if k, err := o.Stats.Summary(ctx); err != nil {
		o.Log.WarnContext(ctx, "overview: summary", "err", err)
	} else {
		kpi = k
	}
	if o.Live != nil {
		kpi.Inflight = o.Live.LiveInflight()
	}

	var states []agents.State
	if o.Agents != nil {
		states = o.Agents.List()
	}
	up := 0
	for _, s := range states {
		if s.Up {
			up++
		}
	}
	vm.KPIs = kpiViews(kpi, up, len(states))
	vm.Agents = o.agentRows(ctx, states, now)
	vm.Events = o.eventRows(ctx)
	return vm
}

func kpiViews(k history.KPI, up, total int) []KPIView {
	errTone := views.ToneNeutral
	switch {
	case k.ProxyErrPct >= 5:
		errTone = views.ToneErr
	case k.ProxyErrPct >= 1:
		errTone = views.ToneWarn
	}
	agentsHint := "нет агентов"
	switch {
	case total > 0 && up == total:
		agentsHint = "все в работе"
	case total > 0:
		agentsHint = fmtInt(int64(total-up)) + " недоступно"
	}
	agentsTone := views.ToneNeutral
	if total > 0 && up == 0 {
		agentsTone = views.ToneErr
	}
	return []KPIView{
		{"rps", "Запросов в секунду", fmtRPS(k.RPS), peakHint(k.PeakRPS), views.ToneNeutral},
		{"err_pct", "Ошибки прокси", fmtPct(k.ProxyErrPct), "502/504 за 5 мин", errTone},
		{"r429", "Ответов 429", fmtInt(k.R429), "Telegram, за 5 мин", views.ToneTG},
		{"agents", "Агенты в работе", fmtInt(int64(up)) + " / " + fmtInt(int64(total)), agentsHint, agentsTone},
		{"inflight", "In-flight сейчас", fmtInt(int64(k.Inflight)), "запросов в полёте", views.ToneNeutral},
	}
}

func peakHint(peak float64) string { return "пик за 24 ч: " + fmtRPS(peak) }

// agentStatus: down — нет связи; draining — выводится из балансировки; degraded — есть
// подряд идущие неудачи опроса при ещё живом агенте.
func agentStatus(s agents.State) views.Status {
	switch {
	case !s.Up:
		return views.StatusDown
	case s.Draining:
		return views.StatusDraining
	case s.ConsecutiveFails > 0:
		return views.StatusDegraded
	}
	return views.StatusUp
}

func agentAddr(a store.Agent) string {
	if a.Mode == store.ModeReverse || a.URL == "" {
		return "reverse"
	}
	u := strings.TrimPrefix(strings.TrimPrefix(a.URL, "https://"), "http://")
	return strings.TrimSuffix(u, "/")
}

func (o *overview) agentRows(ctx context.Context, states []agents.State, now time.Time) []AgentRow {
	rows := make([]AgentRow, 0, len(states))
	for _, s := range states {
		name := s.Agent.Name
		if name == "" {
			name = s.Agent.ID
		}
		row := AgentRow{
			Name: name, Addr: agentAddr(s.Agent), Status: agentStatus(s),
			RPS: "—", P95: "—", Err: "—", Inflight: "—", Version: "—",
		}
		if st := s.LastStatus; st != nil {
			row.Version = st.Version
			row.VersionStale = o.ServerVersion != "" && st.Version != "" && st.Version != o.ServerVersion
			if s.Up {
				row.RPS = fmtRPS(st.RPS1m)
				row.Inflight, row.InflightLP = inflightSplit(st.Inflight, st.InflightLongPoll)
			}
		}
		if s.Up {
			row.P95, row.P95Hint, row.Err = o.agentWindow(ctx, s.Agent.ID, now)
		}
		rows = append(rows, row)
	}
	return rows
}

// agentWindow — p95 (последняя точка) и доля ошибок за последние 5 минут по истории агента.
func (o *overview) agentWindow(ctx context.Context, id string, now time.Time) (p95, p95Hint, errPct string) {
	series, err := o.Stats.Timeseries(ctx, history.Range1h, id, now.Add(-agentWindow))
	if err != nil {
		o.Log.WarnContext(ctx, "overview: agent series", "agent", id, "err", err)
		return "—", "", "—"
	}
	if len(series.Points) == 0 {
		return "—", "", "—"
	}
	var total, errs float64
	var n int64
	for _, p := range series.Points {
		total += p.OKRPS + p.ErrRPS + p.R429RPS
		errs += p.ErrRPS
		n += p.P95N
	}
	last := series.Points[len(series.Points)-1]
	p95 = "—"
	if last.P95Ms > 0 {
		p95 = fmtMs(last.P95Ms)
	}
	if n < history.MinP95Samples {
		p95 = "—"
		p95Hint = fmt.Sprintf("Мало данных: %d запросов за окно, p95 считается от %d", n, history.MinP95Samples)
	}
	if total == 0 {
		return p95, p95Hint, "0,0 %"
	}
	return p95, p95Hint, fmtPct(errs * 100 / total)
}

func eventTone(e Event) string {
	switch {
	case e.State == string(store.OutboxResolved):
		return "ok"
	case strings.Contains(e.Type, "down"), strings.Contains(e.Type, "invalid"), strings.Contains(e.Type, "mismatch") && strings.Contains(e.Type, "hostkey"):
		return "err"
	case strings.Contains(e.Type, "429"), strings.Contains(e.Type, "rate"):
		return "tg"
	}
	return "warn"
}

func (o *overview) eventRows(ctx context.Context) []EventRow {
	if o.Events == nil {
		return nil
	}
	evs, err := o.Events.RecentEvents(ctx, eventsLimit)
	if err != nil {
		o.Log.WarnContext(ctx, "overview: events", "err", err)
		return nil
	}
	rows := make([]EventRow, 0, len(evs))
	for _, e := range evs {
		meta := clockIn(e.At, o.Location, "15:04")
		if e.Type != "" {
			meta += " · " + e.Type
		}
		if e.Sent {
			meta += " · отправлено"
		}
		rows = append(rows, EventRow{Tone: eventTone(e), Text: redact.String(e.Text), Meta: meta})
	}
	return rows
}
