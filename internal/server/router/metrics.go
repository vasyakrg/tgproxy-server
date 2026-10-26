package router

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// NoAgent — условная метка агента для запросов, не дошедших до агента
// (нет здоровых агентов, 429-окно): нужна только для истории.
const NoAgent = "none"

// Значения метки result в upstream_attempts_total.
const (
	AttemptOK       = "ok"
	AttemptTGError  = "tg_error"
	AttemptError    = "error"
	AttemptTimeout  = "timeout"
	attemptReasonTG = "5xx"
)

// Recorder — приёмник метрик роутера (реализует *metrics.Server). Служебные
// (internal) запросы в него не попадают, кроме SetAgentInflight.
type Recorder interface {
	UpstreamAttempt(agent, result string)
	Retry(class, reason string)
	NoHealthyAgents()
	RequestDuration(methodClass, agent string, d time.Duration, longPoll bool)
	SetAgentInflight(agent string, n int)
	LongPollActive(delta int)
}

// HistoryObserver — приёмник истории (реализует *history.Collector).
type HistoryObserver interface {
	ObserveRequest(agent string, outcome history.Outcome, latency time.Duration, longPoll bool)
	SetInflight(agent string, n int)
}

// ErrorSink — журнал ошибок (реализует *history.ErrorLog).
type ErrorSink interface {
	Record(ctx context.Context, e store.ErrorEvent)
}

type noopRecorder struct{}

func (noopRecorder) UpstreamAttempt(string, string)                      {}
func (noopRecorder) Retry(string, string)                                {}
func (noopRecorder) NoHealthyAgents()                                    {}
func (noopRecorder) RequestDuration(string, string, time.Duration, bool) {}
func (noopRecorder) SetAgentInflight(string, int)                        {}
func (noopRecorder) LongPollActive(int)                                  {}

// WithRecorder подключает метрики Prometheus.
func WithRecorder(rec Recorder) Opt {
	return func(r *Router) {
		if rec != nil {
			r.rec = rec
		}
	}
}

// WithInflight задаёт общий счётчик inflight (по умолчанию у каждого роутера свой).
func WithInflight(t *Inflight) Opt {
	return func(r *Router) {
		if t != nil {
			r.inflight = t
		}
	}
}

// WithHistory подключает сборщик истории (samples_10s).
func WithHistory(h HistoryObserver) Opt { return func(r *Router) { r.hist = h } }

// WithErrorLog подключает журнал ошибок.
func WithErrorLog(s ErrorSink) Opt { return func(r *Router) { r.errs = s } }

// Inflight считает запросы в полёте по агентам. Мьютекс удерживается и на
// публикации значения, поэтому метрики не получают устаревшие числа. Один
// экземпляр можно делить между роутерами (WithInflight): при reload конфига
// запросы старого роутера дорабатывают на тех же счётчиках.
type Inflight struct {
	mu sync.Mutex
	n  map[string]int
}

func (t *Inflight) add(r *Router, agent string, delta int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.n == nil {
		t.n = map[string]int{}
	}
	v := max(t.n[agent]+delta, 0)
	t.n[agent] = v
	r.rec.SetAgentInflight(agent, v)
	if r.hist != nil {
		r.hist.SetInflight(agent, v)
	}
}

// Total — суммарное число запросов в полёте по всем агентам прямо сейчас.
func (t *Inflight) Total() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, v := range t.n {
		n += v
	}
	return n
}

// reqObs накапливает данные одного вызова Do для метрик и истории.
type reqObs struct {
	r        *Router
	internal bool
	route    tgapi.Route
	class    tgapi.Class
	longPoll bool
	start    time.Time
	agent    string
	lpOnce   sync.Once
	lpOn     bool
}

func (r *Router) newObs(ctx context.Context, route tgapi.Route) *reqObs {
	return &reqObs{r: r, internal: notify.IsInternal(ctx), route: route, class: classOf(route),
		longPoll: tgapi.IsLongPoll(route.Method), start: r.clock()}
}

// startLongPoll увеличивает gauge активных long-poll; releaseLongPoll
// уменьшает ровно один раз (при закрытии тела ответа или ошибке).
func (o *reqObs) startLongPoll() {
	if o.internal || !o.longPoll {
		return
	}
	o.lpOn = true
	o.r.rec.LongPollActive(1)
}

func (o *reqObs) releaseLongPoll() {
	if !o.lpOn {
		return
	}
	o.lpOnce.Do(func() { o.r.rec.LongPollActive(-1) })
}

// done фиксирует итог запроса: история и длительность по агенту.
func (o *reqObs) done(resp *http.Response, err error) {
	if o.internal {
		return
	}
	var out history.Outcome
	switch {
	case err != nil:
		var re *Error
		if !errors.As(err, &re) || re.Status < http.StatusInternalServerError {
			return // отмена клиента, превышение тела, плохое тело — не ошибка прокси
		}
		out = history.OutcomeProxyErr
	case resp.StatusCode == http.StatusTooManyRequests:
		out = history.OutcomeTG429
	case resp.StatusCode >= http.StatusBadRequest:
		out = history.OutcomeTGErr
	default:
		out = history.OutcomeOK
	}
	d := o.r.clock().Sub(o.start)
	agent := o.agent
	if agent == "" {
		agent = NoAgent
	} else {
		o.r.rec.RequestDuration(o.class.String(), agent, d, o.longPoll)
	}
	if o.r.hist != nil {
		o.r.hist.ObserveRequest(agent, out, d, o.longPoll)
	}
}

// attempt учитывает попытку к агенту (не для internal).
func (c *call) attempt(agent string, o transport.Outcome) {
	if c.obs.internal {
		return
	}
	res := AttemptOK
	switch {
	case o.Canceled:
		return
	case o.Kind == transport.KindTransport && (o.Phase == tgapi.PhaseTimeout):
		res = AttemptTimeout
	case o.Kind == transport.KindTransport:
		res = AttemptError
	case o.Kind == transport.KindTelegramError:
		res = AttemptTGError
	}
	c.r.rec.UpstreamAttempt(agent, res)
}

// retried учитывает ретрай (не для internal).
func (c *call) retried(o transport.Outcome) {
	if c.obs.internal {
		return
	}
	reason := attemptReasonTG
	if o.Kind == transport.KindTransport {
		reason = o.Phase
		if reason == "" {
			reason = "unknown"
		}
	}
	c.r.rec.Retry(c.class.String(), reason)
}

// logErr пишет проблемную попытку в журнал ошибок. Журнал не получает
// internal-запросы, отмены клиента и обычные ответы Telegram 4xx (кроме 429).
func (c *call) logErr(agent string, o transport.Outcome, status int, env *tgapi.Envelope, outcome store.ErrorOutcome) {
	if c.obs.internal || c.r.errs == nil || o.Canceled {
		return
	}
	ev := store.ErrorEvent{
		At: c.r.clock(), RequestID: c.req.Header.Get(tgapi.HeaderRequestID), BotID: strconv.FormatInt(c.route.BotID, 10),
		AgentID: agent, Method: tgapi.MethodLabel(c.route.Method), Code: status, Outcome: outcome,
	}
	switch o.Kind {
	case transport.KindTransport:
		ev.Phase = o.Phase
		if o.Err != nil {
			ev.Description = redact.String(o.Err.Error())
		} else {
			ev.Description = "agent reported transport failure"
		}
	case transport.KindTelegramError:
		ev.Phase = "telegram"
		if env != nil {
			ev.Description = redact.String(env.Description)
		}
	default:
		return
	}
	c.r.errs.Record(c.parent, ev)
}

// logNoAgents пишет в журнал отказ «нет здоровых агентов»: phase=no_agents, агента нет
// (экран «Ошибки» считает такие записи в KPI «нет агентов»).
func (c *call) logNoAgents() {
	if c.r.errs == nil {
		return
	}
	c.r.errs.Record(c.parent, store.ErrorEvent{
		At: c.r.clock(), RequestID: c.req.Header.Get(tgapi.HeaderRequestID), BotID: strconv.FormatInt(c.route.BotID, 10),
		Method: tgapi.MethodLabel(c.route.Method), Phase: tgapi.PhaseNoAgents, Code: http.StatusBadGateway,
		Outcome: store.OutcomeFailedToBot, Description: DescNoAgents,
	})
}

func isLoggable(o transport.Outcome, status int) bool {
	switch o.Kind {
	case transport.KindTransport:
		return true
	case transport.KindTelegramError:
		return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
	}
	return false
}

func errOutcome(d Decision) store.ErrorOutcome {
	switch {
	case d.Final != nil:
		return store.OutcomeFailedToBot
	case d.Retry:
		return store.OutcomeRetried
	}
	return store.OutcomePassedToBot
}
