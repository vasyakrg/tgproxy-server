package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Параметры h2 стримового пула (docs/mtproto.md §6).
const (
	// DefaultStreamWindow — начальные окна потока и соединения: медиа-стрим не
	// упирается в 64 КБ по умолчанию.
	DefaultStreamWindow = 4 << 20
	streamMaxFrameSize  = 1 << 20
	maxIdleStreamConns  = 4
	// HeaderDC — заголовок с номером DC (со знаком), дублирует путь.
	HeaderDC = "X-TGP-DC"
)

// WithStreamWindow задаёт размер h2-окон потока и соединения стримового пула
// (по умолчанию 4 МиБ).
func WithStreamWindow(n int) Option { return func(o *dialOpts) { o.streamWindow = n } }

// DialStream — StreamTransport режима dial: отдельный http.Transport на агента
// (отдельные TCP-соединения, не пересекающиеся с пулом Bot API в Dial).
//
// Строгий лимит параллельных стримов (StrictMaxConcurrentRequests) не включён
// намеренно: при достижении SETTINGS_MAX_CONCURRENT_STREAMS агента
// (max_streams_per_conn) транспорт открывает новое соединение, а не блокирует
// вызывающего (docs/mtproto.md §6).
type DialStream struct {
	cert tls.Certificate
	ca   *x509.CertPool
	opts dialOpts

	mu     sync.Mutex
	conns  map[string]*agentConn
	closed bool
}

var _ StreamTransport = (*DialStream)(nil)

// NewDialStream создаёт транспорт стримов: cert — клиентский сертификат
// сервера, ca — пул доверия проекта. Принимает те же Option, что NewDial.
func NewDialStream(cert tls.Certificate, ca *x509.CertPool, opts ...Option) *DialStream {
	o := defaultDialOpts()
	for _, f := range opts {
		f(&o)
	}
	return &DialStream{cert: cert, ca: ca, opts: o, conns: make(map[string]*agentConn)}
}

func (d *DialStream) transportFor(a AgentRef) (*http.Transport, error) {
	if a.ID == "" || a.URL == nil || a.URL.Scheme != "https" || a.URL.Host == "" {
		return nil, fmt.Errorf("%w: id=%q url=%s", ErrBadAgent, a.ID, redact.URL(a.URL))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, ErrClosed
	}
	if c, ok := d.conns[a.ID]; ok {
		if c.host == a.URL.Host {
			return c.tr, nil
		}
		c.tr.CloseIdleConnections()
	}
	cfg, err := agentTLSConfig(d.cert, d.ca, &d.opts, a.ID)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: d.opts.dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     cfg,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: d.opts.handshakeTimeout,
		IdleConnTimeout:     d.opts.idleConnTimeout,
		MaxIdleConnsPerHost: maxIdleStreamConns,
		HTTP2: &http.HTTP2Config{
			MaxReadFrameSize:              streamMaxFrameSize,
			MaxReceiveBufferPerConnection: d.opts.streamWindow,
			MaxReceiveBufferPerStream:     d.opts.streamWindow,
			SendPingTimeout:               d.opts.pingEvery,
			PingTimeout:                   d.opts.pingTimeout,
		},
	}
	d.conns[a.ID] = &agentConn{host: a.URL.Host, tr: tr}
	return tr, nil
}

// Close закрывает простаивающие соединения пула и запрещает новые стримы.
// Уже открытые стримы закрывает их владелец.
func (d *DialStream) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for id, c := range d.conns {
		c.tr.CloseIdleConnections()
		delete(d.conns, id)
	}
	return nil
}

// OpenMTProto реализует StreamTransport.
func (d *DialStream) OpenMTProto(ctx context.Context, agent AgentRef, dc int) (net.Conn, error) {
	tr, err := d.transportFor(agent)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, d.setupErr(ctx, err)
	}
	// Жизнь стрима не привязана к ctx вызова: ctx ограничивает только установку.
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

	var local, remote atomic.Pointer[net.TCPAddr]
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		local.Store(tcpAddr(i.Conn.LocalAddr()))
		remote.Store(tcpAddr(i.Conn.RemoteAddr()))
	}}
	resp, err := trip(httptrace.WithClientTrace(sctx, trace), tr.RoundTrip, req, agentURL(agent.URL, req.URL), false)
	if err != nil {
		stopWatch()
		cancel()
		return nil, d.setupErr(ctx, err)
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
		return nil, d.setupErr(ctx, context.Cause(ctx))
	}
	l, r := local.Load(), remote.Load()
	if l == nil || r == nil {
		l, r = &net.TCPAddr{}, &net.TCPAddr{}
	}
	return newStreamConn(resp.Body, wp, cancel, l, r), nil
}

// setupErr приводит ошибку установки к принятому виду: отмена вызывающего —
// как есть, истёкший дедлайн ctx — timeout, остальное — как вернул транспорт.
func (*DialStream) setupErr(ctx context.Context, err error) error {
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

// statusErr превращает не-200 агента в *PhaseError: фаза — из X-TGP-Error-Phase
// (неизвестная или отсутствующая — pre-send: стрим не открыт, в DC ничего не ушло).
func statusErr(agentID string, resp *http.Response) error {
	phase := resp.Header.Get(tgapi.HeaderErrorPhase)
	if !knownPhase(phase) {
		phase = tgapi.PhasePreSend
	}
	return &PhaseError{
		Phase: phase, Source: tgapi.SourceAgent,
		Err: &StreamStatusError{AgentID: agentID, Status: resp.StatusCode},
	}
}
