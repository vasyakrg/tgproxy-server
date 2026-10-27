package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// ALPNReverse — ALPN-протокол reverse-канала агент → server. Должна совпадать
// с transport.ALPNReverse (internal/transport; агент серверный код не импортирует).
const ALPNReverse = "tgproxy-reverse/1"

// ALPNMTProto — ALPN отдельного класса reverse-соединений для MTProto-стримов
// (docs/mtproto.md §6). Должна совпадать с серверной константой gateway.
const ALPNMTProto = "tgproxy-mtproto/1"

// Классы соединений.
const (
	classBot     = "bot"
	classMTProto = "mtproto"
)

// defaultUnsupportedRetry — период повторов MTProto-класса, если сервер не
// согласовал ALPN (старый сервер).
const defaultUnsupportedRetry = 10 * time.Minute

// errALPNRefused — сервер не согласовал ALPN класса.
type errALPNRefused struct{ want, got string }

func (e *errALPNRefused) Error() string {
	return fmt.Sprintf("agent: server did not negotiate %q (got %q)", e.want, e.got)
}

// Состояния коннектора.
const (
	StateConnecting = "connecting"
	StateConnected  = "connected"
)

const (
	defaultConns       = 2
	defaultMinBackoff  = time.Second
	defaultMaxBackoff  = 60 * time.Second
	defaultStableAfter = 30 * time.Second
	dialTimeout        = 10 * time.Second
	handshakeTimeout   = 10 * time.Second
	tcpKeepAlive       = 30 * time.Second
	// gracefulRetryInterval — период повторного graceful shutdown в serve.
	gracefulRetryInterval = 50 * time.Millisecond
)

// ConnectorOption настраивает Connector (в основном для тестов).
type ConnectorOption func(*Connector)

// WithBackoff задаёт границы экспоненциального backoff (по умолчанию 1s…60s).
func WithBackoff(minD, maxD time.Duration) ConnectorOption {
	return func(c *Connector) { c.backoffMin, c.backoffMax = minD, maxD }
}

// WithConns задаёт число параллельных соединений (по умолчанию 2).
func WithConns(n int) ConnectorOption {
	return func(c *Connector) {
		if n > 0 {
			c.n = n
		}
	}
}

// WithUnsupportedRetry задаёт период повторов MTProto-класса при отказе сервера
// от ALPN (по умолчанию 10m).
func WithUnsupportedRetry(d time.Duration) ConnectorOption {
	return func(c *Connector) {
		if d > 0 {
			c.unsupportedRetry = d
		}
	}
}

// WithStableAfter задаёт длительность сессии, после которой backoff сбрасывается (по умолчанию 30s).
func WithStableAfter(d time.Duration) ConnectorOption {
	return func(c *Connector) { c.stableAfter = d }
}

// Connector держит N исходящих TLS-соединений к agent_gateway сервера и на
// каждом обслуживает HTTP/2 в роли сервера (роли h2 развёрнуты, §4.1).
type Connector struct {
	a       *Agent
	addr    string
	tlsCfg  *tls.Config
	handler http.Handler

	class string // classBot | classMTProto
	n     int    // начальное/целевое число соединений
	minN  int    // границы динамического пула (для bot-класса minN == maxN == n)
	maxN  int

	backoffMin       time.Duration
	backoffMax       time.Duration
	stableAfter      time.Duration
	unsupportedRetry time.Duration

	active atomic.Int32

	mu     sync.Mutex
	slots  map[*slot]struct{}
	nextID int
	target int
	resize chan struct{}
}

// slot — один постоянный исходящий канал; retire закрывается при сжатии пула.
type slot struct {
	id      int
	retire  chan struct{}
	retired atomic.Bool
	streams atomic.Int32 // активные запросы на текущем соединении
}

// NewConnector готовит коннектор к serverURL (https://host[:port]).
func (a *Agent) NewConnector(serverURL string, opts ...ConnectorOption) (*Connector, error) {
	return a.newConnector(serverURL, classBot, ALPNReverse, opts...)
}

// NewMTProtoConnector готовит коннектор MTProto-класса: ALPN tgproxy-mtproto/1,
// динамический пул [reverse_conns_min, reverse_conns_max], обработчик только
// для /_agent/mtproto/*.
func (a *Agent) NewMTProtoConnector(serverURL string, opts ...ConnectorOption) (*Connector, error) {
	return a.newConnector(serverURL, classMTProto, ALPNMTProto, opts...)
}

func (a *Agent) newConnector(serverURL, class, alpn string, opts ...ConnectorOption) (*Connector, error) {
	u, err := parseServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	verify := pki.VerifyServerPeer(a.caPool)
	cfg, err := pki.ClientTLSConfig(tls.Certificate{}, a.caPool, func(cs tls.ConnectionState) error {
		if cs.NegotiatedProtocol != alpn {
			return &errALPNRefused{want: alpn, got: cs.NegotiatedProtocol}
		}
		return verify(cs)
	})
	if err != nil {
		return nil, fmt.Errorf("agent: reverse tls config: %w", err)
	}
	cfg.Certificates = nil
	cfg.GetClientCertificate = a.certs.clientCert // горячая подмена при ротации
	cfg.NextProtos = []string{alpn}
	if net.ParseIP(u.Hostname()) == nil {
		cfg.ServerName = u.Hostname()
	}
	c := &Connector{
		a:           a,
		addr:        net.JoinHostPort(u.Hostname(), port),
		tlsCfg:      cfg,
		handler:     a.Handler(),
		class:       class,
		n:           defaultConns,
		backoffMin:  defaultMinBackoff,
		backoffMax:  defaultMaxBackoff,
		stableAfter: defaultStableAfter,

		unsupportedRetry: defaultUnsupportedRetry,
		slots:            map[*slot]struct{}{},
		resize:           make(chan struct{}, 1),
	}
	for _, o := range a.connOpts {
		o(c)
	}
	for _, o := range opts {
		o(c)
	}
	if class == classMTProto {
		c.handler = a.mtprotoClassHandler(c)
		c.minN, c.maxN = a.cfg.MTProto.ReverseConnsMin, a.cfg.MTProto.ReverseConnsMax
		if c.minN <= 0 {
			c.minN = config.DefaultReverseConnsMin
		}
		if c.maxN < c.minN {
			c.maxN = max(c.minN, config.DefaultReverseConnsMax)
		}
		c.n = c.minN
	} else {
		c.minN, c.maxN = c.n, c.n
	}
	c.target = c.n
	if c.backoffMin <= 0 || c.backoffMax < c.backoffMin {
		return nil, errors.New("agent: bad backoff bounds")
	}
	return c, nil
}

// parseServerURL: https://host[:port] без userinfo/query; путь допускается пустой или "/".
func parseServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("server_url: want https://host[:port]")
	}
	return u, nil
}

// Conns — число соединений, по которым сервер уже прислал данные.
func (c *Connector) Conns() int { return int(c.active.Load()) }

// State возвращает connected, если есть живое соединение, иначе connecting.
func (c *Connector) State() string {
	if c.Conns() > 0 {
		return StateConnected
	}
	return StateConnecting
}

// Run блокируется до отмены ctx; при отмене h2-соединения завершаются
// gracefully (GOAWAY, in-flight дорабатывают до shutdownTimeout).
func (c *Connector) Run(ctx context.Context) {
	var wg sync.WaitGroup
	c.reconcile(ctx, &wg)
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-c.resize:
			c.reconcile(ctx, &wg)
		}
	}
}

// Target — текущее целевое число соединений.
func (c *Connector) Target() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.target
}

// Resize задаёт целевое число соединений (clamp в [min, max]) и возвращает
// применённое значение. Сжатие отпускает сначала соединения с наименьшим числом
// активных стримов; соединение со стримами дорабатывает их (GOAWAY) и не
// переподключается.
func (c *Connector) Resize(n int) int {
	n = min(max(n, c.minN), c.maxN)
	c.mu.Lock()
	c.target = n
	c.mu.Unlock()
	select {
	case c.resize <- struct{}{}:
	default:
	}
	return n
}

// reconcile приводит число живых слотов к target.
func (c *Connector) reconcile(ctx context.Context, wg *sync.WaitGroup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := make([]*slot, 0, len(c.slots))
	for s := range c.slots {
		if !s.retired.Load() {
			live = append(live, s)
		}
	}
	for len(live) < c.target {
		s := &slot{id: c.nextID, retire: make(chan struct{})}
		c.nextID++
		c.slots[s] = struct{}{}
		live = append(live, s)
		wg.Go(func() {
			defer func() {
				c.mu.Lock()
				delete(c.slots, s)
				c.mu.Unlock()
			}()
			c.slot(ctx, s)
		})
	}
	if extra := len(live) - c.target; extra > 0 {
		sort.Slice(live, func(i, j int) bool { return live[i].streams.Load() < live[j].streams.Load() })
		for _, s := range live[:extra] {
			if s.retired.CompareAndSwap(false, true) {
				close(s.retire)
			}
		}
	}
}

func (c *Connector) slot(ctx context.Context, s *slot) {
	attempt := 0
	lg := c.a.logger.With("slot", s.id, "server", c.addr, "class", c.class)
	for ctx.Err() == nil && !s.retired.Load() {
		start := time.Now()
		served, err := c.session(ctx, s)
		if ctx.Err() != nil || s.retired.Load() {
			return
		}
		if served && time.Since(start) >= c.stableAfter {
			attempt = 0
		}
		d := c.backoff(attempt)
		attempt++
		var refused *errALPNRefused
		switch {
		case c.class == classMTProto && alpnRefused(err, &refused):
			// Старый сервер без MTProto-класса: тихо, редкие повторы.
			d = c.unsupportedRetry
			lg.Debug("mtproto class not supported by server", "retry_in", d)
		case err != nil:
			lg.Warn("reverse connect failed", "err", err, "retry_in", d)
		default:
			lg.Info("reverse connection closed", "retry_in", d)
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.retire:
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// alpnRefused: сервер не согласовал ALPN (отказ уровня TLS-алерта либо пустой
// результат согласования).
func alpnRefused(err error, target **errALPNRefused) bool {
	if err == nil {
		return false
	}
	if errors.As(err, target) {
		return true
	}
	return strings.Contains(err.Error(), "no application protocol")
}

// backoff: min·2^attempt, не больше max; «equal jitter» (половина фиксирована,
// половина случайна), чтобы не было нулевых пауз и штурма сервера.
func (c *Connector) backoff(attempt int) time.Duration {
	d := c.backoffMin
	for i := 0; i < attempt && d < c.backoffMax; i++ {
		d *= 2
	}
	d = min(d, c.backoffMax)
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + rand.N(half+1) // #nosec G404 -- jitter, не криптография
}

// session устанавливает одно соединение и обслуживает его; served — handshake
// прошёл (включая проверку идентичности сервера).
func (c *Connector) session(ctx context.Context, s *slot) (served bool, err error) {
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout, KeepAlive: tcpKeepAlive}, Config: c.tlsCfg}
	raw, err := d.DialContext(hctx, "tcp", c.addr)
	cancel()
	if err != nil {
		return false, err
	}
	tc, ok := raw.(*tls.Conn)
	if !ok {
		_ = raw.Close()
		return false, errors.New("agent: unexpected non-TLS connection")
	}
	conn := &reverseConn{Conn: tc, counter: &c.active}
	defer conn.markClosed()
	c.serve(ctx, conn, s)
	_ = conn.Close()
	return true, nil
}

// serve обслуживает h2 на соединении до его закрытия.
func (c *Connector) serve(ctx context.Context, conn net.Conn, s *slot) {
	handler := countStreams(c.handler, &s.streams)
	base := &http.Server{Handler: handler, ErrorLog: slogErrorLog(c.a), ReadHeaderTimeout: readHeaderTimeout}
	//nolint:staticcheck // reverse-канал требует http2.Server.ServeConn поверх готового соединения (§4.1)
	h2s := &http2.Server{}
	if c.class == classMTProto {
		// Меньший размер фрейма уменьшает scratch-буфер каждого потока сервера (память на соединение).
		h2s.MaxReadFrameSize = transport.StreamMaxFrameSize //nolint:staticcheck // SA1019: http.HTTP2Config не применяется к ServeConn поверх готового соединения
	}
	//nolint:staticcheck // нужен для graceful shutdown через base.Shutdown
	if err := http2.ConfigureServer(base, h2s); err != nil {
		c.a.logger.Error("reverse: configure h2", "err", err)
		return
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		// Graceful: GOAWAY всем h2-соединениям base. Хук http2 видит только уже
		// зарегистрированные в ServeConn соединения, а base своих соединений не
		// держит, поэтому Shutdown возвращается сразу. Если сигнал пришёл до
		// регистрации, один вызов соединение пропустит — повторяем (GOAWAY
		// идемпотентен), пока serve не завершится. Отмена ctx ограничивает
		// ожидание shutdownTimeout; retire (сжатие пула) — без предела: живые
		// стримы дорабатывают.
		cd := ctx.Done()
		var hard <-chan time.Time
		select {
		case <-done:
			return
		case <-cd:
			cd = nil
			tm := time.NewTimer(shutdownTimeout)
			defer tm.Stop()
			hard = tm.C
		case <-s.retire:
		}
		t := time.NewTicker(gracefulRetryInterval)
		defer t.Stop()
		for {
			_ = base.Shutdown(context.WithoutCancel(ctx))
			select {
			case <-done:
				return
			case <-hard:
				_ = conn.Close()
				return
			case <-cd:
				cd = nil
				tm := time.NewTimer(shutdownTimeout)
				defer tm.Stop()
				hard = tm.C
			case <-t.C:
			}
		}
	}()
	// BaseConfig намеренно не задан: с ним ServeConn копирует http.Server и
	// base.Shutdown до соединения не дотянется (graceful через ConfigureServer).
	//nolint:staticcheck // см. выше
	h2s.ServeConn(conn, &http2.ServeConnOpts{
		Context: context.WithoutCancel(ctx),
		Handler: handler,
	})
}

// reverseConn считает соединение живым после первых полученных от сервера
// байт (server — h2-клиент и сразу шлёт preface+SETTINGS): соединение,
// закрытое сервером при отказе по сертификату, живым не считается.
type reverseConn struct {
	*tls.Conn
	counter *atomic.Int32
	once    sync.Once
	counted atomic.Bool
}

func (c *reverseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() {
			c.counted.Store(true)
			c.counter.Add(1)
		})
	}
	return n, err
}

func (c *reverseConn) markClosed() {
	if c.counted.CompareAndSwap(true, false) {
		c.counter.Add(-1)
	}
}

// countStreams считает активные запросы соединения (для выбора жертвы при сжатии).
func countStreams(h http.Handler, n *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		defer n.Add(-1)
		h.ServeHTTP(w, r)
	})
}
