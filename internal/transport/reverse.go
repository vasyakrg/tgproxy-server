package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// ALPNReverse — ALPN reverse-канала агента (architecture §4.1). Агент
// предлагает только его; обычные HTTP-запросы к agent_gateway идут по
// h2/http/1.1. Агентская сторона импортирует эту константу.
const ALPNReverse = "tgproxy-reverse/1"

// ErrNoReverseConn — у агента нет живых reverse-соединений.
var ErrNoReverseConn = errors.New("transport: no reverse connection")

// reverseHost — фиктивный authority для h2-запросов поверх reverse-соединения.
const reverseHostSuffix = ".reverse"

type reverseOpts struct {
	maxConns     int
	pingEvery    time.Duration
	pingTimeout  time.Duration
	maxMisses    int
	statusTO     time.Duration
	drainTimeout time.Duration
	onAttach     func(agentID string, conns int)
	onDetach     func(agentID string, conns int)
	onDown       func(agentID string)
}

// ReverseOption настраивает ReversePool.
type ReverseOption func(*reverseOpts)

// WithMaxConns — максимум соединений на агента (по умолчанию 2).
func WithMaxConns(n int) ReverseOption { return func(o *reverseOpts) { o.maxConns = n } }

// WithReversePing — период, таймаут ответа и число пропусков PING.
func WithReversePing(every, timeout time.Duration, maxMisses int) ReverseOption {
	return func(o *reverseOpts) { o.pingEvery, o.pingTimeout, o.maxMisses = every, timeout, maxMisses }
}

// WithReverseStatusTimeout — таймаут Status (5s).
func WithReverseStatusTimeout(d time.Duration) ReverseOption {
	return func(o *reverseOpts) { o.statusTO = d }
}

// WithDrainTimeout — сколько вытесненному соединению дают дозавершить
// запросы до принудительного закрытия (30s).
func WithDrainTimeout(d time.Duration) ReverseOption {
	return func(o *reverseOpts) { o.drainTimeout = d }
}

// WithOnAttach — колбэк после появления соединения (conns — число после).
func WithOnAttach(f func(agentID string, conns int)) ReverseOption {
	return func(o *reverseOpts) { o.onAttach = f }
}

// WithOnDetach — колбэк после исчезновения соединения (обрыв, PING,
// вытеснение); conns — число оставшихся. Не вызывается из Close.
func WithOnDetach(f func(agentID string, conns int)) ReverseOption {
	return func(o *reverseOpts) { o.onDetach = f }
}

// WithOnDown — колбэк, когда у агента не осталось ни одного соединения.
func WithOnDown(f func(agentID string)) ReverseOption {
	return func(o *reverseOpts) { o.onDown = f }
}

type revConn struct {
	cc     *http2.ClientConn //nolint:staticcheck // SA1019: см. NewReversePool
	raw    net.Conn
	cancel context.CancelFunc
}

// ReversePool — AgentTransport режима reverse: агент сам дозвонился до
// сервера, поверх этого соединения роли h2 развёрнуты (сервер — h2-клиент).
// До maxConns соединений на агента; колбэки вызываются вне блокировок.
type ReversePool struct {
	opts reverseOpts
	h2   *http2.Transport //nolint:staticcheck // SA1019: см. NewReversePool

	mu     sync.Mutex
	conns  map[string][]*revConn // от старого к новому
	closed bool
}

// NewReversePool создаёт пул.
func NewReversePool(opts ...ReverseOption) *ReversePool {
	o := reverseOpts{
		maxConns:     2,
		pingEvery:    DefaultPingEvery,
		pingTimeout:  DefaultPingTimeout,
		maxMisses:    DefaultMaxMisses,
		statusTO:     5 * time.Second,
		drainTimeout: 30 * time.Second,
	}
	for _, f := range opts {
		f(&o)
	}
	if o.maxConns < 1 {
		o.maxConns = 1
	}
	return &ReversePool{
		opts: o,
		//nolint:staticcheck // SA1019: net/http.Transport.NewClientConn не принимает готовый net.Conn
		h2:    &http2.Transport{DisableCompression: true},
		conns: make(map[string][]*revConn),
	}
}

// watchedConn сообщает о первой ошибке чтения/закрытии соединения.
type watchedConn struct {
	net.Conn
	once   sync.Once
	onDead func()
}

// dead срабатывает асинхронно: вызов из readLoop h2 (Read) не должен
// дожидаться ClientConn.Close, который ждёт завершения этого же readLoop.
func (w *watchedConn) dead() { go w.once.Do(w.onDead) }

func (w *watchedConn) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if err != nil {
		w.dead()
	}
	return n, err
}

func (w *watchedConn) Close() error {
	w.dead()
	return w.Conn.Close()
}

// Attach принимает уже аутентифицированное соединение агента agentID
// (проверка сертификата — на стороне gateway). Владение conn переходит пулу.
// При превышении лимита самое старое соединение вытесняется (graceful).
func (p *ReversePool) Attach(agentID string, conn net.Conn) error {
	if agentID == "" {
		_ = conn.Close()
		return fmt.Errorf("%w: empty id", ErrBadAgent)
	}
	rc := &revConn{}
	wc := &watchedConn{Conn: conn, onDead: func() { p.detach(agentID, rc) }}
	//nolint:staticcheck // SA1019: см. NewReversePool
	cc, err := p.h2.NewClientConn(wc)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("transport: reverse h2 client conn: %w", err)
	}
	pctx, cancel := context.WithCancel(context.Background())
	rc.cc, rc.raw, rc.cancel = cc, wc, cancel

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		cancel()
		_ = conn.Close()
		return ErrClosed
	}
	list := append(p.conns[agentID], rc)
	var evicted []*revConn
	for len(list) > p.opts.maxConns {
		evicted = append(evicted, list[0])
		list = list[1:]
	}
	p.conns[agentID] = list
	n := len(list)
	p.mu.Unlock()

	go pingLoop(pctx, cc, p.opts.pingEvery, p.opts.pingTimeout, p.opts.maxMisses, func() { p.detach(agentID, rc) })
	for _, e := range evicted {
		p.retire(agentID, e, n)
	}
	if p.opts.onAttach != nil {
		p.opts.onAttach(agentID, n)
	}
	return nil
}

// retire — вытеснение: останавливаем PING, закрываем graceful.
func (p *ReversePool) retire(agentID string, rc *revConn, remaining int) {
	rc.cancel()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), p.opts.drainTimeout)
		defer cancel()
		if err := rc.cc.Shutdown(ctx); err != nil {
			_ = rc.cc.Close()
		}
		_ = rc.raw.Close()
	}()
	if p.opts.onDetach != nil {
		p.opts.onDetach(agentID, remaining)
	}
}

// detach убирает соединение (если оно ещё в пуле) и закрывает его.
func (p *ReversePool) detach(agentID string, rc *revConn) {
	p.mu.Lock()
	list := p.conns[agentID]
	i := slices.Index(list, rc)
	if i < 0 {
		p.mu.Unlock()
		return
	}
	list = slices.Delete(slices.Clone(list), i, i+1)
	if len(list) == 0 {
		delete(p.conns, agentID)
	} else {
		p.conns[agentID] = list
	}
	closed := p.closed
	p.mu.Unlock()

	rc.cancel()
	_ = rc.cc.Close()
	_ = rc.raw.Close()
	if closed {
		return
	}
	if p.opts.onDetach != nil {
		p.opts.onDetach(agentID, len(list))
	}
	if len(list) == 0 && p.opts.onDown != nil {
		p.opts.onDown(agentID)
	}
}

// Conns — число соединений агента (для метрики agent_reverse_conns).
func (p *ReversePool) Conns(agentID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns[agentID])
}

// candidates — живые соединения агента: менее загруженные, при равенстве
// более новые — первыми.
func (p *ReversePool) candidates(agentID string) []*revConn {
	p.mu.Lock()
	list := slices.Clone(p.conns[agentID])
	p.mu.Unlock()
	list = slices.DeleteFunc(list, func(rc *revConn) bool { return !rc.cc.CanTakeNewRequest() })
	slices.Reverse(list)
	slices.SortStableFunc(list, func(a, b *revConn) int {
		return a.cc.State().StreamsActive - b.cc.State().StreamsActive
	})
	return list
}

// RoundTrip реализует AgentTransport. Нет живых соединений -> dial/NotSent.
// Если выбранное соединение оказалось мёртвым до записи запроса, пробуется
// следующее: до записи в агента ничего не ушло, повтор безопасен.
func (p *ReversePool) RoundTrip(ctx context.Context, agent AgentRef, req *http.Request) (*http.Response, error) {
	if agent.ID == "" {
		return nil, fmt.Errorf("%w: empty id", ErrBadAgent)
	}
	cands := p.candidates(agent.ID)
	if len(cands) == 0 {
		return nil, &PhaseError{Phase: tgapi.PhaseDial, Source: SourceServerAgent,
			Err: fmt.Errorf("%w: agent %s", ErrNoReverseConn, agent.ID)}
	}
	u := &url.URL{Scheme: "https", Host: agent.ID + reverseHostSuffix,
		Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery}
	var lastErr error
	for i, rc := range cands {
		r := req
		if i > 0 && req.GetBody != nil {
			body, berr := req.GetBody()
			if berr != nil {
				break
			}
			r = req.Clone(ctx)
			r.Body = body
		}
		resp, err := trip(ctx, rc.cc.RoundTrip, r, u, true)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		var pe *PhaseError
		if !errors.As(err, &pe) || pe.Phase != tgapi.PhasePreSend || ctx.Err() != nil ||
			i == len(cands)-1 || !replayable(req) {
			break
		}
	}
	return nil, lastErr
}

// replayable: тело не читалось (GetBody есть или тела нет) — запрос можно
// повторить на другом соединении.
func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// Status запрашивает GET /_agent/status через reverse-канал.
func (p *ReversePool) Status(ctx context.Context, agent AgentRef) (*AgentStatus, error) {
	return fetchStatus(ctx, p.opts.statusTO, p, agent)
}

// Close закрывает все соединения; колбэки не вызываются.
func (p *ReversePool) Close() error {
	p.mu.Lock()
	p.closed = true
	all := p.conns
	p.conns = make(map[string][]*revConn)
	p.mu.Unlock()
	for _, list := range all {
		for _, rc := range list {
			rc.cancel()
			_ = rc.cc.Close()
			_ = rc.raw.Close()
		}
	}
	return nil
}
