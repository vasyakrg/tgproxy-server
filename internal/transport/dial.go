package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Ошибки конфигурации/состояния Dial.
var (
	ErrClosed   = errors.New("transport: closed")
	ErrBadAgent = errors.New("transport: bad agent ref")
)

const maxStatusBody = 1 << 20

type dialOpts struct {
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	idleConnTimeout  time.Duration
	statusTimeout    time.Duration
	pingEvery        time.Duration
	pingTimeout      time.Duration
	clientCert       func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	peerChecks       []pki.Check
}

// Option настраивает Dial.
type Option func(*dialOpts)

// WithDialTimeout — таймаут TCP-соединения (по умолчанию 5s).
func WithDialTimeout(d time.Duration) Option { return func(o *dialOpts) { o.dialTimeout = d } }

// WithTLSHandshakeTimeout — таймаут рукопожатия (по умолчанию 5s).
func WithTLSHandshakeTimeout(d time.Duration) Option {
	return func(o *dialOpts) { o.handshakeTimeout = d }
}

// WithIdleConnTimeout — время жизни простаивающего соединения (90s).
func WithIdleConnTimeout(d time.Duration) Option { return func(o *dialOpts) { o.idleConnTimeout = d } }

// WithStatusTimeout — таймаут Status (5s).
func WithStatusTimeout(d time.Duration) Option { return func(o *dialOpts) { o.statusTimeout = d } }

// WithHTTP2Ping — период h2 PING простаивающего соединения и таймаут ответа.
func WithHTTP2Ping(every, timeout time.Duration) Option {
	return func(o *dialOpts) { o.pingEvery, o.pingTimeout = every, timeout }
}

// WithClientCertFunc заменяет статический клиентский сертификат динамическим
// (pki.Authority.ServerCert перевыпускает его по сроку): сертификат берётся
// при каждом новом рукопожатии.
func WithClientCertFunc(f func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) Option {
	return func(o *dialOpts) { o.clientCert = f }
}

// WithPeerChecks добавляет проверки листа агента (denylist: pki.Denylist.Check).
func WithPeerChecks(c ...pki.Check) Option {
	return func(o *dialOpts) { o.peerChecks = append(o.peerChecks, c...) }
}

type agentConn struct {
	host string
	tr   *http.Transport
}

// Dial — AgentTransport режима dial: сервер открывает mTLS-соединение к
// агенту; отдельный http.Transport (пул h2-соединений) на каждого агента.
type Dial struct {
	cert tls.Certificate
	ca   *x509.CertPool
	opts dialOpts

	mu     sync.Mutex
	conns  map[string]*agentConn
	closed bool
}

// NewDial создаёт транспорт: cert — клиентский сертификат сервера, ca — пул
// доверия проекта.
func NewDial(cert tls.Certificate, ca *x509.CertPool, opts ...Option) *Dial {
	o := dialOpts{
		dialTimeout:      5 * time.Second,
		handshakeTimeout: 5 * time.Second,
		idleConnTimeout:  90 * time.Second,
		statusTimeout:    5 * time.Second,
		pingEvery:        15 * time.Second,
		pingTimeout:      10 * time.Second,
	}
	for _, f := range opts {
		f(&o)
	}
	return &Dial{cert: cert, ca: ca, opts: o, conns: make(map[string]*agentConn)}
}

func (d *Dial) transportFor(a AgentRef) (*http.Transport, error) {
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
		c.tr.CloseIdleConnections() // агент переехал на другой адрес
	}
	cfg, err := pki.ClientTLSConfig(d.cert, d.ca, pki.VerifyAgentPeer(d.ca, a.ID, d.opts.peerChecks...))
	if err != nil {
		return nil, err
	}
	if d.opts.clientCert != nil {
		cfg.Certificates = nil
		cfg.GetClientCertificate = d.opts.clientCert
	}
	tr := &http.Transport{
		// Прокси не используем: канал server → agent прямой.
		DialContext:         (&net.Dialer{Timeout: d.opts.dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     cfg,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: d.opts.handshakeTimeout,
		// ResponseHeaderTimeout не задаём: getUpdates — long-poll до 65s,
		// дедлайн задаёт ctx вызывающего.
		IdleConnTimeout:     d.opts.idleConnTimeout,
		MaxIdleConnsPerHost: 8,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: d.opts.pingEvery,
			PingTimeout:     d.opts.pingTimeout,
		},
	}
	d.conns[a.ID] = &agentConn{host: a.URL.Host, tr: tr}
	return tr, nil
}

// Close закрывает простаивающие соединения и запрещает новые запросы.
func (d *Dial) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for id, c := range d.conns {
		c.tr.CloseIdleConnections()
		delete(d.conns, id)
	}
	return nil
}

// stage фиксирует, как далеко продвинулась попытка (httptrace).
type stage struct {
	tlsStarted   atomic.Bool
	gotConn      atomic.Bool
	wroteHeaders atomic.Bool
}

func (s *stage) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		TLSHandshakeStart: func() { s.tlsStarted.Store(true) },
		GotConn:           func(httptrace.GotConnInfo) { s.gotConn.Store(true) },
		WroteHeaders:      func() { s.wroteHeaders.Store(true) },
	}
}

// countingBody считает байты, прочитанные транспортом из тела запроса.
type countingBody struct {
	rc io.ReadCloser
	n  atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.n.Add(int64(n))
	return n, err
}

func (b *countingBody) Close() error { return b.rc.Close() }

// RoundTrip реализует AgentTransport.
//
// Понимание «запрос ушёл в агента» (-> write, а не pre-send): сработал
// httptrace.WroteHeaders ИЛИ транспорт прочитал хотя бы байт тела
// (обёртка countingBody). Это консервативнее одного WroteRequest: при RST
// посреди тела агент уже мог начать стримить в Telegram, а WroteRequest в
// таком случае не срабатывает. Ошибка до этого момента (в т.ч. устаревшее
// keep-alive соединение) -> NotSent.
func (d *Dial) RoundTrip(ctx context.Context, agent AgentRef, req *http.Request) (*http.Response, error) {
	tr, err := d.transportFor(agent)
	if err != nil {
		return nil, err
	}
	return trip(ctx, tr.RoundTrip, req, agentURL(agent.URL, req.URL), false)
}

// trip — общая часть RoundTrip для Dial и ReversePool: подмена URL,
// трассировка стадии и классификация ошибки по фазам. connected=true, если
// соединение с агентом уже есть (reverse): «нет соединения» тогда невозможно.
func trip(ctx context.Context, rt func(*http.Request) (*http.Response, error), req *http.Request, u *url.URL, connected bool) (*http.Response, error) {
	out := req.Clone(ctx)
	out.URL = u
	out.Host = ""
	out.RequestURI = ""
	var cb *countingBody
	if req.Body != nil && req.Body != http.NoBody {
		cb = &countingBody{rc: req.Body}
		out.Body = cb
	}
	st := &stage{}
	st.gotConn.Store(connected)
	out = out.WithContext(httptrace.WithClientTrace(ctx, st.trace()))

	resp, err := rt(out)
	if err == nil {
		return resp, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return nil, err
	}
	wrote := st.wroteHeaders.Load() || (cb != nil && cb.n.Load() > 0)
	return nil, &PhaseError{Phase: phaseFromStage(err, st, wrote), Source: SourceServerAgent, Err: err}
}

func phaseFromStage(err error, st *stage, wrote bool) string {
	if isTLSErr(err) {
		return tgapi.PhaseTLS
	}
	if !st.gotConn.Load() && !wrote {
		if st.tlsStarted.Load() {
			return tgapi.PhaseTLS
		}
		return tgapi.PhaseDial
	}
	switch {
	case !wrote && strings.Contains(err.Error(), "client conn could not be established"):
		// TLS 1.3: клиент «завершил» рукопожатие, а сервер сразу закрыл
		// соединение, отвергнув клиентский сертификат; h2 теряет причину.
		return tgapi.PhaseTLS
	case !wrote:
		return tgapi.PhasePreSend
	case isTimeout(err):
		return tgapi.PhaseTimeout
	default:
		return tgapi.PhaseWrite
	}
}

// agentURL: схема/хост агента + путь и query запроса как есть (путь агента
// из конфигурации, если он не корневой, выступает префиксом).
func agentURL(base, in *url.URL) *url.URL {
	u := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: in.Path, RawPath: in.RawPath, RawQuery: in.RawQuery}
	if p := strings.TrimRight(base.Path, "/"); p != "" {
		u.Path = p + in.Path
		if in.RawPath != "" {
			u.RawPath = p + in.RawPath
		}
	}
	return u
}

// Status запрашивает GET /_agent/status. Транспортные ошибки возвращаются как
// *PhaseError; не-200 — обычной ошибкой.
func (d *Dial) Status(ctx context.Context, agent AgentRef) (*AgentStatus, error) {
	return fetchStatus(ctx, d.opts.statusTimeout, d, agent)
}

func fetchStatus(ctx context.Context, timeout time.Duration, t AgentTransport, agent AgentRef) (*AgentStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, StatusPath, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := t.RoundTrip(ctx, agent, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("transport: agent %s status: HTTP %d", agent.ID, resp.StatusCode)
	}
	var st AgentStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxStatusBody)).Decode(&st); err != nil {
		return nil, fmt.Errorf("transport: agent %s status: decode: %w", agent.ID, redact.Error(err))
	}
	return &st, nil
}
