package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"
	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// MTProtoPoolPath — служебный эндпоинт агента: PUT {"conns": N} задаёт желаемое
// число MTProto-соединений (агент ограничивает его своими min/max, ответ 204).
const MTProtoPoolPath = "/_agent/mtproto/pool"

// PoolRequest — тело PUT MTProtoPoolPath.
type PoolRequest struct {
	Conns int `json:"conns"`
}

type reverseStreamOpts struct {
	maxConns       int
	streamsPerConn int
	pingEvery      time.Duration
	pingTimeout    time.Duration
	maxMisses      int
	drainTimeout   time.Duration
	signalEvery    time.Duration
	shrinkAfter    time.Duration
	signalTimeout  time.Duration
	onSignal       func(agentID string, conns int)
	onAttach       func(agentID string, conns int)
	onDetach       func(agentID string, conns int)
}

// ReverseStreamOption настраивает ReverseStream.
type ReverseStreamOption func(*reverseStreamOpts)

// WithMTProtoMaxConns — максимум MTProto-соединений на агента (4); отдельно от
// лимита Bot API-пула. Сверх лимита самое старое вытесняется gracefully.
func WithMTProtoMaxConns(n int) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.maxConns = n }
}

// WithMTProtoStreamsPerConn — порог загрузки соединения (max_streams_per_conn, 500).
func WithMTProtoStreamsPerConn(n int) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.streamsPerConn = n }
}

// WithMTProtoPing — период, таймаут и число пропусков PING.
func WithMTProtoPing(every, timeout time.Duration, maxMisses int) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.pingEvery, o.pingTimeout, o.maxMisses = every, timeout, maxMisses }
}

// WithMTProtoDrainTimeout — сколько вытесненному соединению дают дозавершить стримы (30s).
func WithMTProtoDrainTimeout(d time.Duration) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.drainTimeout = d }
}

// WithMTProtoSignalInterval — дебаунс сигналов PUT /pool на агента (5s).
func WithMTProtoSignalInterval(d time.Duration) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.signalEvery = d }
}

// WithMTProtoShrinkAfter — гистерезис уменьшения: не раньше чем через d после
// последнего роста (60s).
func WithMTProtoShrinkAfter(d time.Duration) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.shrinkAfter = d }
}

// WithMTProtoOnSignal — колбэк при отправке сигнала размера пула (conns — запрошено).
func WithMTProtoOnSignal(f func(agentID string, conns int)) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.onSignal = f }
}

// WithMTProtoOnAttach — колбэк после появления соединения (conns — число после).
func WithMTProtoOnAttach(f func(agentID string, conns int)) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.onAttach = f }
}

// WithMTProtoOnDetach — колбэк после исчезновения соединения; не вызывается из Close.
func WithMTProtoOnDetach(f func(agentID string, conns int)) ReverseStreamOption {
	return func(o *reverseStreamOpts) { o.onDetach = f }
}

type mtConn struct {
	cc     *http2.ClientConn //nolint:staticcheck // SA1019: см. NewReverseStream
	raw    net.Conn
	cancel context.CancelFunc
	active atomic.Int64 // открытые стримы (учёт сервера: точнее и детерминированнее h2)
}

type mtAgent struct {
	conns      []*mtConn // от старого к новому
	lastSignal time.Time
	lastGrow   time.Time // рост пула или появление соединения: старт окна гистерезиса
	signalling bool
}

// ReverseStream — StreamTransport режима reverse: отдельный пул h2-соединений
// MTProto-класса (ALPN ALPNMTProto), независимый от ReversePool Bot API. Стрим
// идёт по наименее загруженному соединению; при нехватке емкости серверу
// шлётся сигнал агенту открыть ещё соединение. Разрыв соединения рвёт только
// его стримы.
type ReverseStream struct {
	opts reverseStreamOpts
	h2   *http2.Transport //nolint:staticcheck // SA1019: см. NewReverseStream

	rootCtx context.Context
	stop    context.CancelFunc
	wg      sync.WaitGroup

	mu     sync.Mutex
	agents map[string]*mtAgent
	closed bool
}

var _ StreamTransport = (*ReverseStream)(nil)

// NewReverseStream создаёт пул.
func NewReverseStream(opts ...ReverseStreamOption) *ReverseStream {
	o := reverseStreamOpts{
		maxConns:       4,
		streamsPerConn: 500,
		pingEvery:      DefaultPingEvery,
		pingTimeout:    DefaultPingTimeout,
		maxMisses:      DefaultMaxMisses,
		drainTimeout:   30 * time.Second,
		signalEvery:    5 * time.Second,
		shrinkAfter:    60 * time.Second,
		signalTimeout:  5 * time.Second,
	}
	for _, f := range opts {
		f(&o)
	}
	o.maxConns = max(o.maxConns, 1)
	o.streamsPerConn = max(o.streamsPerConn, 1)
	ctx, cancel := context.WithCancel(context.Background())
	return &ReverseStream{
		opts: o,
		//nolint:staticcheck // SA1019: net/http.Transport.NewClientConn не принимает готовый net.Conn
		h2:      &http2.Transport{DisableCompression: true, MaxReadFrameSize: streamMaxFrameSize},
		rootCtx: ctx, stop: cancel,
		agents: make(map[string]*mtAgent),
	}
}

// Attach принимает аутентифицированное соединение MTProto-класса агента
// (сертификат проверил gateway). Владение conn переходит пулу.
func (s *ReverseStream) Attach(agentID string, conn net.Conn) error {
	if agentID == "" {
		_ = conn.Close()
		return fmt.Errorf("%w: empty id", ErrBadAgent)
	}
	mc := &mtConn{}
	wc := &watchedConn{Conn: conn, onDead: func() { s.detach(agentID, mc) }}
	//nolint:staticcheck // SA1019: см. NewReverseStream
	cc, err := s.h2.NewClientConn(wc)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("transport: mtproto h2 client conn: %w", err)
	}
	pctx, cancel := context.WithCancel(s.rootCtx)
	mc.cc, mc.raw, mc.cancel = cc, wc, cancel

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		_ = conn.Close()
		return ErrClosed
	}
	a := s.agents[agentID]
	if a == nil {
		a = &mtAgent{}
		s.agents[agentID] = a
	}
	a.conns = append(a.conns, mc)
	a.lastGrow = time.Now()
	var evicted []*mtConn
	for len(a.conns) > s.opts.maxConns {
		evicted = append(evicted, a.conns[0])
		a.conns = a.conns[1:]
	}
	n := len(a.conns)
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wg.Done()
		pingLoop(pctx, cc, s.opts.pingEvery, s.opts.pingTimeout, s.opts.maxMisses, func() { s.detach(agentID, mc) })
	}()
	for _, e := range evicted {
		s.retire(agentID, e, n)
	}
	if s.opts.onAttach != nil {
		s.opts.onAttach(agentID, n)
	}
	return nil
}

// retire — вытеснение: останавливаем PING, закрываем graceful (стримы дозавершаются).
func (s *ReverseStream) retire(agentID string, mc *mtConn, remaining int) {
	mc.cancel()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(s.rootCtx, s.opts.drainTimeout)
		defer cancel()
		if err := mc.cc.Shutdown(ctx); err != nil {
			_ = mc.cc.Close()
		}
		_ = mc.raw.Close()
	}()
	if s.opts.onDetach != nil {
		s.opts.onDetach(agentID, remaining)
	}
}

func (s *ReverseStream) detach(agentID string, mc *mtConn) {
	s.mu.Lock()
	a := s.agents[agentID]
	var i = -1
	if a != nil {
		i = slices.Index(a.conns, mc)
	}
	if i < 0 {
		s.mu.Unlock()
		return
	}
	a.conns = slices.Delete(slices.Clone(a.conns), i, i+1)
	left := len(a.conns)
	if left == 0 {
		delete(s.agents, agentID)
	}
	closed := s.closed
	s.mu.Unlock()

	mc.cancel()
	_ = mc.cc.Close()
	_ = mc.raw.Close()
	if !closed && s.opts.onDetach != nil {
		s.opts.onDetach(agentID, left)
	}
}

// Conns — число MTProto-соединений агента.
func (s *ReverseStream) Conns(agentID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.agents[agentID]; a != nil {
		return len(a.conns)
	}
	return 0
}

// Streams — число открытых MTProto-стримов агента.
func (s *ReverseStream) Streams(agentID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalLocked(s.agents[agentID])
}

func (*ReverseStream) totalLocked(a *mtAgent) int {
	if a == nil {
		return 0
	}
	var t int64
	for _, c := range a.conns {
		t += c.active.Load()
	}
	return int(t)
}

// pick выбирает наименее загруженное живое соединение и резервирует стрим.
func (s *ReverseStream) pick(agentID string, skip []*mtConn) *mtConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.agents[agentID]
	if a == nil {
		return nil
	}
	var best *mtConn
	for i := len(a.conns) - 1; i >= 0; i-- { // при равенстве — более новое
		c := a.conns[i]
		if slices.Contains(skip, c) || !c.cc.CanTakeNewRequest() {
			continue
		}
		if best == nil || c.active.Load() < best.active.Load() {
			best = c
		}
	}
	if best != nil {
		best.active.Add(1)
	}
	return best
}

// OpenMTProto реализует StreamTransport.
func (s *ReverseStream) OpenMTProto(ctx context.Context, agent AgentRef, dc int) (net.Conn, error) {
	if agent.ID == "" {
		return nil, fmt.Errorf("%w: empty id", ErrBadAgent)
	}
	if err := ctx.Err(); err != nil {
		return nil, setupErr(ctx, err)
	}
	var tried []*mtConn
	var lastErr error
	for {
		mc := s.pick(agent.ID, tried)
		if mc == nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, &PhaseError{Phase: tgapi.PhaseDial, Source: SourceServerAgent,
				Err: fmt.Errorf("%w: agent %s", ErrNoReverseConn, agent.ID)}
		}
		tried = append(tried, mc)
		conn, err := s.openOn(ctx, agent, mc, dc)
		if err == nil {
			s.rebalance(agent.ID)
			return conn, nil
		}
		mc.active.Add(-1)
		lastErr = err
		var pe *PhaseError
		// До записи в агента ничего не ушло (соединение умерло) — пробуем следующее.
		if ctx.Err() != nil || !errors.As(err, &pe) || pe.Phase != tgapi.PhasePreSend {
			return nil, err
		}
	}
}

func (s *ReverseStream) openOn(ctx context.Context, agent AgentRef, mc *mtConn, dc int) (net.Conn, error) {
	sctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopWatch := context.AfterFunc(ctx, cancel)

	wp := newBodyPipe()
	req, err := http.NewRequestWithContext(sctx, http.MethodPost, MTProtoPath+strconv.Itoa(dc), wp)
	if err != nil {
		stopWatch()
		cancel()
		return nil, err
	}
	req.Header.Set(tgapi.HeaderRequestID, ulid.Make().String())
	req.Header.Set(HeaderDC, strconv.Itoa(dc))
	req.Header.Set("Content-Type", "application/octet-stream")

	u := &url.URL{Scheme: "https", Host: agent.ID + reverseHostSuffix, Path: req.URL.Path}
	resp, err := trip(sctx, mc.cc.RoundTrip, req, u, true)
	if err != nil {
		stopWatch()
		cancel()
		return nil, setupErr(ctx, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		stopWatch()
		cancel()
		return nil, statusErr(agent.ID, resp)
	}
	if !stopWatch() { // ctx отменён в момент ответа: стрим уже сброшен
		_ = resp.Body.Close()
		cancel()
		return nil, setupErr(ctx, context.Cause(ctx))
	}
	var once sync.Once
	release := func() {
		cancel()
		once.Do(func() {
			mc.active.Add(-1)
			s.rebalance(agent.ID)
		})
	}
	return newStreamConn(resp.Body, wp, release, tcpAddr(mc.raw.LocalAddr()), tcpAddr(mc.raw.RemoteAddr())), nil
}

// rebalance оценивает загрузку и при необходимости просит агента изменить
// число соединений (с дебаунсом и гистерезисом на уменьшение).
func (s *ReverseStream) rebalance(agentID string) {
	now := time.Now()
	s.mu.Lock()
	a := s.agents[agentID]
	if s.closed || a == nil || a.signalling || now.Sub(a.lastSignal) < s.opts.signalEvery {
		s.mu.Unlock()
		return
	}
	n, total := len(a.conns), s.totalLocked(a)
	per := s.opts.streamsPerConn
	want := n
	switch {
	case total >= per*n && n < s.opts.maxConns:
		want = n + 1
	case n > 1 && total <= per*(n-1)/2 && now.Sub(a.lastGrow) >= s.opts.shrinkAfter:
		want = n - 1
	}
	if want == n {
		s.mu.Unlock()
		return
	}
	var best *mtConn
	for _, c := range a.conns {
		if c.cc.CanTakeNewRequest() && (best == nil || c.active.Load() < best.active.Load()) {
			best = c
		}
	}
	if best == nil {
		s.mu.Unlock()
		return
	}
	a.signalling, a.lastSignal = true, now
	if want > n {
		a.lastGrow = now
	}
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wg.Done()
		s.sendPool(s.rootCtx, agentID, best, want)
		s.mu.Lock()
		if cur := s.agents[agentID]; cur != nil {
			cur.signalling = false
		}
		s.mu.Unlock()
	}()
}

func (s *ReverseStream) sendPool(parent context.Context, agentID string, mc *mtConn, conns int) {
	body, _ := json.Marshal(PoolRequest{Conns: conns})
	ctx, cancel := context.WithTimeout(parent, s.opts.signalTimeout)
	defer cancel()
	u := &url.URL{Scheme: "https", Host: agentID + reverseHostSuffix, Path: MTProtoPoolPath}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := mc.cc.RoundTrip(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	if s.opts.onSignal != nil {
		s.opts.onSignal(agentID, conns)
	}
}

// setupErr приводит ошибку установки к принятому виду: отмена вызывающего —
// как есть, истёкший дедлайн ctx — timeout, остальное — как вернул транспорт.
func setupErr(ctx context.Context, err error) error {
	ce := ctx.Err()
	switch {
	case ce == nil:
		return err
	case errors.Is(ce, context.DeadlineExceeded):
		return &PhaseError{Phase: tgapi.PhaseTimeout, Source: SourceServerAgent, Err: ce}
	default:
		return ce
	}
}

// Close закрывает все соединения и ждёт фоновые горутины; колбэки не вызываются.
func (s *ReverseStream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	all := s.agents
	s.agents = make(map[string]*mtAgent)
	s.mu.Unlock()
	s.stop()
	for _, a := range all {
		for _, c := range a.conns {
			c.cancel()
			_ = c.cc.Close()
			_ = c.raw.Close()
		}
	}
	s.wg.Wait()
	return nil
}
