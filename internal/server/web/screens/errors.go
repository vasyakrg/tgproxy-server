package screens

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// ErrorSource — журнал ошибок (реализует *history.Query).
type ErrorSource interface {
	Errors(ctx context.Context, cursor string, f history.Filters) (history.Page, error)
}

// ErrorsDeps — зависимости экрана «Ошибки».
type ErrorsDeps struct {
	Shell    Shell
	Source   ErrorSource
	Agents   AgentLister // nil — список агентов в фильтре строится только из выбранного значения
	Location *time.Location
	Now      func() time.Time
	Log      *slog.Logger
}

const (
	errorsPath    = "/errors"
	kpiWindow     = 24 * time.Hour
	kpiPageLimit  = 200
	kpiMaxPages   = 10
	noAgentsPhase = tgapi.PhaseNoAgents
)

type errorsScreen struct{ ErrorsDeps }

// NewErrors возвращает хендлер «GET /errors»: целая страница, либо (htmx) фрагмент:
// список с курсором («Показать ещё») или карточку результатов при смене фильтров.
func NewErrors(d ErrorsDeps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Location == nil {
		d.Location = time.Local
	}
	return &errorsScreen{d}
}

// ---------- модель представления ----------

// PhaseKPI — карточка сводки по фазам.
type PhaseKPI struct {
	Label, Value, Hint string
	Tone               string // ok | warn | err | tg | muted
}

// ErrorRow — строка таблицы.
type ErrorRow struct {
	Time, RequestID, RequestIDFull, BotID, Method, Agent string
	Phase, PhaseTone                                     string
	Code                                                 string
	OutcomeText                                          string
	OutcomeTone                                          views.Tone
	Description                                          string
}

// ErrorsFilter — выбранные фильтры (значения форм).
type ErrorsFilter struct {
	Agent, BotID, Phase, Code, RequestID string
}

// ErrorsVM — модель страницы «Ошибки».
type ErrorsVM struct {
	KPIs       []PhaseKPI
	KPIsCapped bool
	Filter     ErrorsFilter
	AgentOpts  []string
	PhaseOpts  []string
	CodeOpts   []string
	Rows       []ErrorRow
	MoreURL    string // пусто — страниц больше нет
	Filtered   bool
}

var (
	phaseOptions = []string{tgapi.PhaseDial, tgapi.PhaseTLS, tgapi.PhasePreSend, tgapi.PhaseWrite, tgapi.PhaseRead, tgapi.PhaseTimeout, "telegram", "server"}
	codeOptions  = []string{"200", "429", "502", "503", "504"}
)

func (s *errorsScreen) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ErrorsFilter{
		Agent: q.Get("agent"), BotID: strings.TrimSpace(q.Get("bot_id")), Phase: q.Get("phase"),
		Code: q.Get("code"), RequestID: strings.TrimSpace(q.Get("request_id")),
	}
	hf := history.Filters{AgentID: f.Agent, BotID: f.BotID, Phase: f.Phase, RequestID: f.RequestID}
	if f.Code != "" {
		n, err := strconv.Atoi(f.Code)
		if err != nil || n < 0 || n > 999 {
			f.Code = "" // мусор в коде игнорируем, а не ломаем страницу
		} else {
			hf.Code = n
		}
	}
	cursor := q.Get("cursor")
	page, err := s.Source.Errors(r.Context(), cursor, hf)
	if err != nil {
		if errors.Is(err, history.ErrBadCursor) {
			http.Error(w, "некорректный cursor", http.StatusBadRequest)
			return
		}
		s.Log.ErrorContext(r.Context(), "errors screen: list", "err", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	rows := s.rows(page.Items)
	more := ""
	if page.NextCursor != "" {
		more = moreURL(f, page.NextCursor)
	}

	// Подгрузка следующей страницы: только строки + новая строка «Показать ещё».
	if cursor != "" && isFragment(r) {
		renderFragment(w, r, http.StatusOK, ErrorRows(rows, more)) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}

	vm := ErrorsVM{
		Filter: f, Rows: rows, MoreURL: more, Filtered: hf != (history.Filters{}),
		PhaseOpts: withCurrent(phaseOptions, f.Phase), CodeOpts: withCurrent(codeOptions, f.Code),
		AgentOpts: s.agentOptions(f.Agent),
	}
	if isFragment(r) {
		renderFragment(w, r, http.StatusOK, ErrorsResults(vm)) //nolint:contextcheck // templ
		return
	}
	vm.KPIs, vm.KPIsCapped = s.phaseKPIs(r.Context())
	renderPage(s.Shell, w, r, http.StatusOK, "Ошибки", views.NavErrors, ErrorsPage(vm)) //nolint:contextcheck // templ
}

func moreURL(f ErrorsFilter, cursor string) string {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("agent", f.Agent)
	set("bot_id", f.BotID)
	set("phase", f.Phase)
	set("code", f.Code)
	set("request_id", f.RequestID)
	v.Set("cursor", cursor)
	return errorsPath + "?" + v.Encode()
}

func withCurrent(opts []string, cur string) []string {
	if cur == "" || slices.Contains(opts, cur) {
		return opts
	}
	return append(slices.Clone(opts), cur)
}

func (s *errorsScreen) agentOptions(cur string) []string {
	var ids []string
	if s.Agents != nil {
		for _, st := range s.Agents.List() {
			ids = append(ids, st.Agent.ID)
		}
	}
	slices.Sort(ids)
	return withCurrent(ids, cur)
}

func (s *errorsScreen) rows(items []store.ErrorEvent) []ErrorRow {
	out := make([]ErrorRow, 0, len(items))
	for _, e := range items {
		r := ErrorRow{
			Time: clockIn(e.At, s.Location, "15:04:05"), RequestID: shortID(e.RequestID), RequestIDFull: e.RequestID,
			BotID: dash(e.BotID), Method: dash(e.Method), Agent: dash(e.AgentID),
			Phase: dash(e.Phase), PhaseTone: phaseTone(e.Phase),
			Code: "—", Description: redact.String(e.Description),
		}
		if e.Code > 0 {
			r.Code = strconv.Itoa(e.Code)
		}
		r.OutcomeText, r.OutcomeTone = outcomeView(e.Outcome)
		out = append(out, r)
	}
	return out
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// shortID: «01JBX4…Q2» — длинный ULID сокращается, полное значение — в title.
func shortID(id string) string {
	r := []rune(id)
	if len(r) <= 12 {
		return id
	}
	return string(r[:6]) + "…" + string(r[len(r)-2:])
}

func outcomeView(o store.ErrorOutcome) (string, views.Tone) {
	switch o {
	case store.OutcomeRetried:
		return "переотправлен", views.ToneOK
	case store.OutcomeFailedToBot:
		return "отказ боту", views.ToneErr
	case store.OutcomePassedToBot:
		return "передан боту", views.ToneTG
	}
	return dash(string(o)), views.ToneNeutral
}

func phaseTone(p string) string {
	switch p {
	case tgapi.PhaseDial, tgapi.PhaseTLS, tgapi.PhasePreSend:
		return "warn"
	case tgapi.PhaseWrite, tgapi.PhaseRead, tgapi.PhaseTimeout:
		return "err"
	case "telegram", "server":
		return "tg"
	}
	return ""
}

// ---------- сводка по фазам ----------

type phaseCounts struct {
	dialTLS, dialTLSRetried    int
	preSend, preSendRetried    int
	timeoutRead, timeoutFailed int
	r429                       int
	noAgents                   int
}

// phaseKPIs считает карточки по записям журнала за 24 часа (до kpiMaxPages страниц).
func (s *errorsScreen) phaseKPIs(ctx context.Context) ([]PhaseKPI, bool) {
	var c phaseCounts
	cutoff := s.Now().Add(-kpiWindow)
	cursor, capped := "", false
loop:
	for page := 0; ; page++ {
		if page == kpiMaxPages {
			capped = true
			break
		}
		p, err := s.Source.Errors(ctx, cursor, history.Filters{Limit: kpiPageLimit})
		if err != nil {
			s.Log.WarnContext(ctx, "errors screen: kpi", "err", err)
			break
		}
		for _, e := range p.Items {
			if e.At.Before(cutoff) {
				break loop
			}
			c.add(e)
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	return c.kpis(capped), capped
}

func (c *phaseCounts) add(e store.ErrorEvent) {
	retried := e.Outcome == store.OutcomeRetried
	switch {
	case e.Code == 429:
		c.r429++
	case e.Phase == noAgentsPhase || (e.Code == 503 && e.AgentID == ""):
		c.noAgents++
	case e.Phase == tgapi.PhaseDial || e.Phase == tgapi.PhaseTLS:
		c.dialTLS++
		if retried {
			c.dialTLSRetried++
		}
	case e.Phase == tgapi.PhasePreSend:
		c.preSend++
		if retried {
			c.preSendRetried++
		}
	case e.Phase == tgapi.PhaseTimeout || e.Phase == tgapi.PhaseRead || e.Phase == tgapi.PhaseWrite:
		c.timeoutRead++
		if e.Outcome == store.OutcomeFailedToBot {
			c.timeoutFailed++
		}
	}
}

func retriedHint(n, retried int) string {
	if n == 0 {
		return "за 24 часа"
	}
	if n == retried {
		return "все переотправлены"
	}
	return "переотправлено " + strconv.Itoa(retried) + " из " + strconv.Itoa(n)
}

func (c *phaseCounts) kpis(capped bool) []PhaseKPI {
	cnt := func(n int) string {
		if capped {
			return strconv.Itoa(n) + "+"
		}
		return strconv.Itoa(n)
	}
	timeoutHint := "send* — без повтора"
	if c.timeoutRead == 0 {
		timeoutHint = "за 24 часа"
	} else if c.timeoutFailed > 0 {
		timeoutHint = "отказ боту: " + strconv.Itoa(c.timeoutFailed)
	}
	r429Hint := "за 24 часа"
	if c.r429 > 0 {
		r429Hint = "переданы ботам"
	}
	return []PhaseKPI{
		{"dial / tls", cnt(c.dialTLS), retriedHint(c.dialTLS, c.dialTLSRetried), toneIf(c.dialTLS > 0, "ok")},
		{"pre-send", cnt(c.preSend), retriedHint(c.preSend, c.preSendRetried), toneIf(c.preSend > 0, "ok")},
		{"timeout / read", cnt(c.timeoutRead), timeoutHint, toneIf(c.timeoutRead > 0, "err")},
		{"429 Telegram", cnt(c.r429), r429Hint, toneIf(c.r429 > 0, "tg")},
		{"нет агентов", cnt(c.noAgents), "за 24 часа", toneIf(c.noAgents > 0, "err")},
	}
}

func toneIf(cond bool, tone string) string {
	if cond {
		return tone
	}
	return "muted"
}
