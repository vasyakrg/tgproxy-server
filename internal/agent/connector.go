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
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

// ALPNReverse — ALPN-протокол reverse-канала агент → server. Должна совпадать
// с transport.ALPNReverse (internal/transport; агент серверный код не импортирует).
const ALPNReverse = "tgproxy-reverse/1"

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

	n           int
	backoffMin  time.Duration
	backoffMax  time.Duration
	stableAfter time.Duration

	active atomic.Int32
}

// NewConnector готовит коннектор к serverURL (https://host[:port]).
func (a *Agent) NewConnector(serverURL string, opts ...ConnectorOption) (*Connector, error) {
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
		if cs.NegotiatedProtocol != ALPNReverse {
			return fmt.Errorf("agent: server did not negotiate %q (got %q)", ALPNReverse, cs.NegotiatedProtocol)
		}
		return verify(cs)
	})
	if err != nil {
		return nil, fmt.Errorf("agent: reverse tls config: %w", err)
	}
	cfg.Certificates = nil
	cfg.GetClientCertificate = a.certs.clientCert // горячая подмена при ротации
	cfg.NextProtos = []string{ALPNReverse}
	if net.ParseIP(u.Hostname()) == nil {
		cfg.ServerName = u.Hostname()
	}
	c := &Connector{
		a:           a,
		addr:        net.JoinHostPort(u.Hostname(), port),
		tlsCfg:      cfg,
		handler:     a.Handler(),
		n:           defaultConns,
		backoffMin:  defaultMinBackoff,
		backoffMax:  defaultMaxBackoff,
		stableAfter: defaultStableAfter,
	}
	for _, o := range a.connOpts {
		o(c)
	}
	for _, o := range opts {
		o(c)
	}
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
	for i := range c.n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.slot(ctx, i)
		}()
	}
	wg.Wait()
}

func (c *Connector) slot(ctx context.Context, id int) {
	attempt := 0
	lg := c.a.logger.With("slot", id, "server", c.addr)
	for ctx.Err() == nil {
		start := time.Now()
		served, err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if served && time.Since(start) >= c.stableAfter {
			attempt = 0
		}
		d := c.backoff(attempt)
		attempt++
		if err != nil {
			lg.Warn("reverse connect failed", "err", err, "retry_in", d)
		} else {
			lg.Info("reverse connection closed", "retry_in", d)
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
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
func (c *Connector) session(ctx context.Context) (served bool, err error) {
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
	c.serve(ctx, conn)
	_ = conn.Close()
	return true, nil
}

// serve обслуживает h2 на соединении до его закрытия.
func (c *Connector) serve(ctx context.Context, conn net.Conn) {
	base := &http.Server{Handler: c.handler, ErrorLog: slogErrorLog(c.a), ReadHeaderTimeout: readHeaderTimeout}
	//nolint:staticcheck // reverse-канал требует http2.Server.ServeConn поверх готового соединения (§4.1)
	h2s := &http2.Server{}
	//nolint:staticcheck // нужен для graceful shutdown через base.Shutdown
	if err := http2.ConfigureServer(base, h2s); err != nil {
		c.a.logger.Error("reverse: configure h2", "err", err)
		return
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			// Graceful: GOAWAY всем h2-соединениям base, затем жёсткий предел.
			// Хук http2 видит только уже зарегистрированные в ServeConn
			// соединения, а base своих соединений не держит, поэтому Shutdown
			// возвращается сразу. Если ctx отменён до регистрации, один вызов
			// соединение пропустит — повторяем (хуки срабатывают на каждый
			// вызов, GOAWAY идемпотентен), пока serve не завершится.
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
			defer cancel()
			t := time.NewTicker(gracefulRetryInterval)
			defer t.Stop()
			for {
				_ = base.Shutdown(sctx)
				select {
				case <-done:
					return
				case <-sctx.Done():
					_ = conn.Close()
					return
				case <-t.C:
				}
			}
		}
	}()
	// BaseConfig намеренно не задан: с ним ServeConn копирует http.Server и
	// base.Shutdown до соединения не дотянется (graceful через ConfigureServer).
	//nolint:staticcheck // см. выше
	h2s.ServeConn(conn, &http2.ServeConnOpts{
		Context: context.WithoutCancel(ctx),
		Handler: c.handler,
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
