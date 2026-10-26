// Package router выбирает агента и отправляет ему запрос с синхронными
// ретраями по политике architecture §6: буферизация тела, бюджет попыток,
// окна 429 по (bot_id, chat_id), ожидание появления агентов.
package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Upstream — транспорт до агента (адаптер к internal/transport делает wiring).
// req несёт только путь и query (URL.Path/RawQuery), заголовки и тело;
// схему и адрес выбирает реализация по agentID.
type Upstream interface {
	RoundTrip(ctx context.Context, agentID string, req *http.Request) (*http.Response, error)
}

// Описания ошибок, отдаваемых ботам.
const (
	DescNoAgents = "tgproxy: no healthy agents"
	DescTimeout  = "tgproxy: upstream timeout"
	DescBadBody  = "tgproxy: bad request body"
)

// Error — ошибка маршрутизации с готовым HTTP-статусом для бота.
type Error struct {
	Status int
	Desc   string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Desc + ": " + redact.String(e.Err.Error())
	}
	return e.Desc
}

// Unwrap возвращает причину.
func (e *Error) Unwrap() error { return e.Err }

// HTTPStatus — код ответа боту.
func (e *Error) HTTPStatus() int { return e.Status }

// Description — описание в формате Telegram.
func (e *Error) Description() string { return e.Desc }

// Picker выбирает агента (реализует *balancer.Balancer). release нужно
// вызвать ровно один раз с исходом попытки.
type Picker interface {
	Pick(ctx context.Context, exclude []string) (string, func(balancer.Result), error)
}

// Opt настраивает Router.
type Opt func(*Router)

// WithBalancer включает выбор агента балансировщиком, ретраи на других
// агентах и ожидание появления агентов (cfg.Router.NoAgentWait).
func WithBalancer(p Picker) Opt {
	return func(r *Router) {
		if p != nil {
			r.picker, r.balanced = p, true
		}
	}
}

// WithWindows включает 429-окна (bot_id, chat_id).
func WithWindows(w *Windows) Opt { return func(r *Router) { r.windows = w } }

// WithBufferConfig переопределяет настройки буфера тела (по умолчанию cfg.Buffer).
func WithBufferConfig(c config.BufferConfig) Opt { return func(r *Router) { r.buf = c } }

// WithBufferGauge задаёт метрику занятого буфера (байты).
func WithBufferGauge(g Gauge) Opt { return func(r *Router) { r.gauge = g } }

// WithPassive задаёт пассивный health-хук: вызывается после каждой попытки
// (кроме отменённых клиентом); transportErr — отказ канала или агента.
func WithPassive(f func(agentID string, transportErr bool)) Opt {
	return func(r *Router) { r.passive = f }
}

// WithClock задаёт источник времени (бюджет, ожидание агентов, окна).
func WithClock(f func() time.Time) Opt {
	return func(r *Router) {
		if f != nil {
			r.clock = f
		}
	}
}

// WithSleep задаёт ожидание (backoff, опрос агентов); для тестов.
func WithSleep(f func(ctx context.Context, d time.Duration) error) Opt {
	return func(r *Router) {
		if f != nil {
			r.sleep = f
		}
	}
}

// Router отправляет запросы агентам.
type Router struct {
	cfg      *config.ServerConfig
	up       Upstream
	log      *slog.Logger
	picker   Picker
	balanced bool
	windows  *Windows
	buf      config.BufferConfig
	gauge    Gauge
	passive  func(string, bool)
	rec      Recorder
	hist     HistoryObserver
	errs     ErrorSink
	inflight *Inflight
	clock    func() time.Time
	sleep    func(context.Context, time.Duration) error
}

// New создаёт Router. Без WithBalancer агент — первый из cfg.Agents
// (ожидание агентов отключено).
func New(cfg *config.ServerConfig, up Upstream, log *slog.Logger, opts ...Opt) *Router {
	r := &Router{cfg: cfg, up: up, log: log, buf: cfg.Buffer, clock: time.Now, sleep: sleepCtx, rec: noopRecorder{}, inflight: &Inflight{}}
	r.picker = cfgPicker{r}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Do отправляет req агенту с ретраями (architecture §6).
//
// Алгоритм: окно 429 (ответ 429 без вызова агента) → Wrap тела → цикл
// попыток в пределах MaxAttempts и бюджета; агенты прошлых попыток в exclude →
// Classify → Decide. Контракт: Do возвращает ответ, как только получены
// заголовки допустимого ответа; тело ответа (в т.ч. /file/*) стримит вызывающий
// уже после возврата, поэтому ретраи /file/* возможны лишь пока клиенту не
// отдано ни байта. Дедлайн и буфер тела запроса живут до Close тела ответа.
// Ошибки: *Error (502/504), *http.MaxBytesError, отмена клиента (ctx.Err()).
func (r *Router) Do(parent context.Context, req *http.Request, route tgapi.Route) (*http.Response, error) {
	obs := r.newObs(parent, route)
	var chatID string
	if r.windows != nil {
		chatID = ExtractChatID(req, nil, 0) // chat_id из query: окно проверяется до буферизации
		if resp := r.blocked(route, chatID); resp != nil {
			obs.done(resp, nil)
			return resp, nil
		}
	}
	body, err := Wrap(req, r.buf, WithGauge(r.gauge))
	if err != nil {
		return nil, r.bodyErr(parent, err)
	}
	if r.windows != nil && chatID == "" {
		if chatID = ExtractChatID(req, body, r.buf.RAMMax); chatID != "" {
			if resp := r.blocked(route, chatID); resp != nil {
				_ = body.Close()
				obs.done(resp, nil)
				return resp, nil
			}
		}
	}

	budget := r.timeout(req, body, route)
	ctx, cancel := context.WithTimeout(parent, budget)
	c := &call{r: r, parent: parent, ctx: ctx, req: req, route: route, body: body, obs: obs,
		class: classOf(route), budget: budget, start: r.clock(), chatID: chatID,
		maxAttempts: max(r.cfg.Router.MaxAttempts, 1)}
	obs.startLongPoll()
	resp, err := c.run()
	obs.done(resp, err)
	if err != nil {
		obs.releaseLongPoll()
		cancel()
		_ = body.Close()
		return nil, err
	}
	resp.Body = &ownedBody{ReadCloser: resp.Body, fns: []func(){cancel, func() { _ = body.Close() }, obs.releaseLongPoll}}
	return resp, nil
}

func classOf(route tgapi.Route) tgapi.Class {
	if route.IsFile {
		return tgapi.Safe
	}
	return tgapi.Classify(route.Method)
}

func (r *Router) bodyErr(parent context.Context, err error) error {
	var mb *http.MaxBytesError
	switch {
	case errors.As(err, &mb):
		return err
	case parent.Err() != nil:
		return parent.Err()
	}
	return &Error{Status: http.StatusBadRequest, Desc: DescBadBody, Err: err}
}

// blocked возвращает готовый 429, если окно (bot, chat) открыто.
func (r *Router) blocked(route tgapi.Route, chatID string) *http.Response {
	if chatID == "" {
		return nil
	}
	left, ok := r.windows.Check(route.BotID, chatID)
	if !ok {
		return nil
	}
	secs := max(int(math.Ceil(left.Seconds())), 1)
	r.log.Debug("429 window active", "bot_id", route.BotID, "retry_after", secs)
	env := tgapi.Envelope{OK: false, ErrorCode: http.StatusTooManyRequests,
		Description: "Too Many Requests: retry after " + strconv.Itoa(secs),
		Parameters:  &tgapi.ResponseParameters{RetryAfter: secs}}
	data, _ := json.Marshal(env) // простая структура: ошибки нет
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	h.Set("Retry-After", strconv.Itoa(secs))
	return &http.Response{StatusCode: http.StatusTooManyRequests, Header: h,
		Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data))}
}

// call — состояние одного вызова Do.
type call struct {
	r           *Router
	parent, ctx context.Context
	req         *http.Request
	route       tgapi.Route
	class       tgapi.Class
	body        Replayable
	rd          io.ReadCloser // единственный читатель non-replayable тела
	budget      time.Duration
	start       time.Time
	chatID      string
	maxAttempts int
	obs         *reqObs

	exclude     []string
	pending     *http.Response // ответ Telegram с 5xx, ожидающий ретрая
	lastFinal   *Final
	lastTimeout bool
}

func (c *call) run() (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		remaining := c.remaining()
		if attempt > 1 && (remaining <= 0 || c.ctx.Err() != nil) {
			return c.exhausted()
		}
		agent, release, err := c.pick(attempt)
		if err != nil {
			return c.pickFailed(attempt, err)
		}
		c.closePending()
		resp, retry, err := c.try(agent, release, attempt, max(remaining, minAttemptTimeout))
		if err != nil || !retry {
			return resp, err
		}
	}
}

func (c *call) pick(attempt int) (string, func(balancer.Result), error) {
	var wait time.Duration
	if attempt == 1 && c.r.balanced {
		wait = c.r.cfg.Router.NoAgentWait
	}
	agent, release, err := c.r.pickWait(c.ctx, c.exclude, wait)
	if err != nil {
		return agent, release, err
	}
	c.obs.agent = agent
	c.r.inflight.add(c.r, agent, 1)
	var once sync.Once
	return agent, func(res balancer.Result) {
		release(res)
		once.Do(func() { c.r.inflight.add(c.r, agent, -1) })
	}, nil
}

func (c *call) pickFailed(attempt int, err error) (*http.Response, error) {
	if c.parent.Err() != nil {
		return nil, c.parent.Err()
	}
	if attempt > 1 {
		return c.exhausted()
	}
	if errors.Is(err, balancer.ErrNoHealthyAgents) {
		if !c.obs.internal {
			c.r.rec.NoHealthyAgents()
			c.logNoAgents()
		}
	} else if c.ctx.Err() == nil {
		c.r.log.Warn("pick failed", "error", redact.Error(err))
	}
	return nil, &Error{Status: http.StatusBadGateway, Desc: DescNoAgents, Err: err}
}

// try выполняет одну попытку. retry=true — нужен следующий круг.
func (c *call) try(agent string, release func(balancer.Result), attempt int, left time.Duration) (*http.Response, bool, error) {
	before := c.body.BytesConsumed()
	t0 := c.r.clock()
	resp, err := c.send(agent, attempt, left)
	var mb *http.MaxBytesError
	if errors.As(err, &mb) { // клиент превысил лимит тела при стриминге
		release(balancer.Result{Canceled: true})
		return nil, false, err
	}
	o := transport.Classify(resp, err, c.body.BytesConsumed() > before)
	if o.Kind == transport.KindTransport && !o.Canceled && c.parent.Err() != nil {
		o.Canceled = true
	}
	var env *tgapi.Envelope
	if o.Kind == transport.KindTelegramError {
		var rerr error
		if resp, env, rerr = readEnvelope(resp); rerr != nil {
			o = transport.Classify(resp, rerr, true)
		}
	}
	res := balancer.Result{Latency: c.r.clock().Sub(t0), LongPoll: tgapi.IsLongPoll(c.route.Method),
		TransportError: o.Kind == transport.KindTransport && !o.Canceled, Canceled: o.Canceled}
	if c.r.passive != nil && !o.Canceled {
		c.r.passive(agent, res.TransportError)
	}
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	if o.Kind == transport.KindTelegramError && status == http.StatusTooManyRequests &&
		c.r.windows != nil && c.chatID != "" {
		c.r.windows.Observe(c.route.BotID, c.chatID, env)
	}

	d := Decide(c.class, FromTransport(o, status, env), attempt, c.maxAttempts)
	c.attempt(agent, o)
	if isLoggable(o, status) {
		c.logErr(agent, o, status, env, errOutcome(d))
	}
	c.r.log.Debug("attempt", "attempt", attempt, "agent", agent, "kind", o.Kind.String(), "phase", o.Phase, "status", status)
	switch {
	case o.Canceled:
		release(res)
		closeResp(resp)
		return nil, false, c.canceledErr(o.Err)
	case d.Final != nil:
		release(res)
		closeResp(resp)
		return nil, false, c.finalErr(d.Final, o)
	case d.Retry:
		release(res)
		return c.retry(agent, resp, o, d)
	}
	if resp == nil || resp.Body == nil {
		release(res)
	} else {
		// inflight агента держится, пока клиент читает тело (в т.ч. стрим /file/*).
		resp.Body = &releaseBody{ReadCloser: resp.Body, release: release, res: res}
	}
	if d.TreatAsSuccess {
		c.r.log.Debug("telegram error after retry treated as success", "attempt", attempt)
	}
	return resp, false, nil
}

// retry готовит следующий круг. Ретрай невозможен, если тело запроса уже
// (частично) уйдёт — для non-replayable допустим лишь not-sent и 0 прочитанных байт.
func (c *call) retry(agent string, resp *http.Response, o transport.Outcome, d Decision) (*http.Response, bool, error) {
	if !c.body.Replayable() && (!o.NotSent || c.body.BytesConsumed() != 0) {
		if o.Kind == transport.KindTelegramError {
			return resp, false, nil
		}
		closeResp(resp)
		desc := DescUpstreamUnavailable
		if !o.NotSent && c.class != tgapi.Safe {
			desc = DescDeliveryUnknown
		}
		return nil, false, c.finalErr(&Final{Status: http.StatusBadGateway, Desc: desc}, o)
	}
	c.retried(o)
	c.exclude = append(c.exclude, agent)
	c.lastTimeout = o.Phase == tgapi.PhaseTimeout || errors.Is(o.Err, context.DeadlineExceeded)
	if o.Kind == transport.KindTelegramError {
		c.pending = resp
	} else {
		closeResp(resp)
		po := FromTransport(o, 0, nil)
		c.lastFinal = Decide(c.class, po, c.maxAttempts, c.maxAttempts).Final
	}
	if d.Backoff > 0 {
		if c.remaining() <= d.Backoff {
			resp, err := c.exhausted()
			return resp, false, err
		}
		if err := c.r.sleep(c.ctx, d.Backoff); err != nil {
			if c.parent.Err() != nil {
				c.closePending()
				return nil, false, c.parent.Err()
			}
			resp, err := c.exhausted()
			return resp, false, err
		}
	}
	return nil, true, nil
}

// exhausted завершает вызов, когда ретраить больше нельзя (бюджет, агенты).
func (c *call) exhausted() (*http.Response, error) {
	if c.pending != nil {
		resp := c.pending
		c.pending = nil
		return resp, nil
	}
	if c.parent.Err() != nil {
		return nil, c.parent.Err()
	}
	f := c.lastFinal
	if f == nil {
		f = &Final{Status: http.StatusBadGateway, Desc: DescUpstreamUnavailable}
	}
	return nil, c.finalErr(f, transport.Outcome{})
}

func (c *call) closePending() {
	if c.pending != nil {
		closeResp(c.pending)
		c.pending = nil
	}
}

func (c *call) canceledErr(err error) error {
	if c.parent.Err() != nil {
		return c.parent.Err()
	}
	if err != nil {
		return err
	}
	return context.Canceled
}

// finalErr превращает финальное решение в *Error; исчерпанный бюджет при
// «upstream unavailable» — это 504.
func (c *call) finalErr(f *Final, o transport.Outcome) error {
	timedOut := c.lastTimeout || o.Phase == tgapi.PhaseTimeout || errors.Is(o.Err, context.DeadlineExceeded) ||
		errors.Is(c.ctx.Err(), context.DeadlineExceeded) || c.remaining() <= 0
	if f.Desc == DescUpstreamUnavailable && timedOut {
		return &Error{Status: http.StatusGatewayTimeout, Desc: DescTimeout, Err: o.Err}
	}
	if o.Err != nil {
		c.r.log.Warn("upstream failed", "error", redact.Error(o.Err), "desc", f.Desc)
	}
	return &Error{Status: f.Status, Desc: f.Desc, Err: o.Err}
}

// send строит запрос к агенту и вызывает Upstream.
func (c *call) send(agent string, n int, left time.Duration) (*http.Response, error) {
	u := &url.URL{Path: tgapi.AgentTGPrefix + strings.TrimPrefix(c.route.UpstreamPath(), "/"), RawQuery: c.req.URL.RawQuery}
	// UpstreamPath возвращает экранированный путь; сохраняем его как есть.
	u.RawPath = u.Path
	if p, err := url.PathUnescape(u.Path); err == nil {
		u.Path = p
	}
	rd, err := c.bodyReader()
	if err != nil {
		return nil, err
	}
	out, err := http.NewRequestWithContext(c.ctx, c.req.Method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	out.URL = u
	out.Header = c.req.Header.Clone()
	if rd != nil {
		out.ContentLength = c.body.Size()
		if out.ContentLength <= 0 {
			out.ContentLength = -1
		}
	}
	out.Header.Set(tgapi.HeaderTimeoutMs, strconv.FormatInt(left.Milliseconds(), 10))
	out.Header.Set(tgapi.HeaderAttempt, strconv.Itoa(n))
	return c.r.up.RoundTrip(c.ctx, agent, out)
}

func (c *call) bodyReader() (io.ReadCloser, error) {
	switch {
	case c.body.Replayable() && c.body.Size() == 0:
		return nil, nil //nolint:nilnil // пустое тело
	case c.body.Replayable():
		return c.body.NewReader()
	case c.rd == nil:
		rd, err := c.body.NewReader()
		if err != nil {
			return nil, err
		}
		c.rd = rd
	}
	return c.rd, nil
}

// envelopeLimit — максимум байт тела ошибки Telegram, читаемого ради конверта.
const envelopeLimit = 64 << 10

// readEnvelope читает тело ошибочного ответа Telegram и подменяет его
// буфером, чтобы тело можно было отдать клиенту. env=nil — тело не разобрано.
func readEnvelope(resp *http.Response) (*http.Response, *tgapi.Envelope, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, envelopeLimit+1))
	if err != nil {
		_ = resp.Body.Close()
		return resp, nil, err
	}
	orig := resp.Body
	if len(data) > envelopeLimit {
		resp.Body = &multiBody{Reader: io.MultiReader(bytes.NewReader(data), orig), Closer: orig}
		return resp, nil, nil
	}
	_ = orig.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	env, perr := tgapi.ParseEnvelope(bytes.NewReader(data), envelopeLimit)
	if perr != nil {
		env = nil
	}
	return resp, env, nil
}

type multiBody struct {
	io.Reader
	io.Closer
}

func closeResp(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

// releaseBody отпускает слот балансировщика при закрытии тела ответа.
// Латентность зафиксирована по заголовкам; ошибка чтения тела — не отказ
// агента, а Canceled-подобный исход (не влияет ни на EWMA, ни на breaker).
type releaseBody struct {
	io.ReadCloser
	release func(balancer.Result)
	res     balancer.Result
	failed  atomic.Bool
	once    sync.Once
}

func (b *releaseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		b.failed.Store(true)
	}
	return n, err
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		res := b.res
		if b.failed.Load() {
			res = balancer.Result{Canceled: true}
		}
		b.release(res)
	})
	return err
}

// ownedBody закрывает вместе с телом ответа дедлайн и буфер запроса.
type ownedBody struct {
	io.ReadCloser
	once sync.Once
	fns  []func()
}

func (b *ownedBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		for _, f := range b.fns {
			f()
		}
	})
	return err
}
