// Package gateway — листенер agent_gateway (:8444): reverse-каналы агентов за
// NAT, enrollment и раздача пакетов (architecture §4.1, plan M5-T8/T9).
//
// TLS 1.3, ClientAuth=VerifyClientCertIfGiven. Сертификат клиента (если есть)
// проверяется цепочкой к CA, затем SAN агента, членством в реестре и
// denylist; при отказе соединение закрывается до первого запроса. Дальше:
//   - ALPN transport.ALPNReverse (обязателен клиентский сертификат) -> соединение
//     передаётся ReversePool;
//   - иначе — обычный HTTP/1.1+h2 сервер: POST /enroll, GET /enroll/package/<deb>
//     (оба без клиентского сертификата, по enrollment-токену) и /_agent_gw/packages/.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Пути, обслуживаемые обычным HTTP.
const (
	EnrollPath = "/enroll"
	// EnrollPackagePath — префикс GET /enroll/package/<deb>: пакет для установки агента
	// без клиентского сертификата (авторизация — enrollment-токен, не расходуется).
	EnrollPackagePath = "/enroll/package/"
	PackagesPath      = "/_agent_gw/packages/"
)

// AgentLookup — реестр агентов (consumer-интерфейс).
type AgentLookup interface {
	// Known возвращает режим связи агента, если он зарегистрирован.
	Known(id string) (mode string, ok bool)
}

// Attacher принимает аутентифицированное reverse-соединение
// (*transport.ReversePool).
type Attacher interface {
	Attach(agentID string, conn net.Conn) error
}

var _ Attacher = (*transport.ReversePool)(nil)

// Config — параметры Gateway.
type Config struct {
	Cert tls.Certificate // серверный сертификат agent_gateway
	// GetCertificate — динамический серверный сертификат (перевыпуск по сроку без
	// рестарта); если задан, Cert игнорируется.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	CA             *x509.CertPool // CA проекта (проверка клиентских сертификатов)
	Lookup         AgentLookup
	Pool           Attacher
}

type ctxKey struct{}

// AgentIDFromContext возвращает id агента, предъявившего клиентский сертификат
// в обычном HTTP-запросе (для /_agent_gw/packages/).
func AgentIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ctxKey{}).(string)
	return id, ok && id != ""
}

// Option настраивает Gateway.
type Option func(*Gateway)

// WithEnrollHandler задаёт обработчик POST /enroll (по умолчанию 404).
func WithEnrollHandler(h http.Handler) Option { return func(g *Gateway) { g.enroll = h } }

// WithEnrollPackageHandler задаёт обработчик GET /enroll/package/ (по умолчанию 404).
func WithEnrollPackageHandler(h http.Handler) Option {
	return func(g *Gateway) { g.enrollPkg = h }
}

// WithPackagesHandler задаёт обработчик /_agent_gw/packages/ (по умолчанию 404).
func WithPackagesHandler(h http.Handler) Option { return func(g *Gateway) { g.packages = h } }

// WithChecks добавляет проверки листа (denylist: pki.Denylist.Check).
func WithChecks(c ...pki.Check) Option { return func(g *Gateway) { g.checks = append(g.checks, c...) } }

// WithLogger задаёт логгер.
func WithLogger(l *slog.Logger) Option { return func(g *Gateway) { g.log = l } }

// WithHandshakeTimeout — таймаут TLS-рукопожатия (10s).
func WithHandshakeTimeout(d time.Duration) Option { return func(g *Gateway) { g.hsTimeout = d } }

// Gateway — листенер agent_gateway.
type Gateway struct {
	tlsCfg    *tls.Config
	lookup    AgentLookup
	pool      Attacher
	checks    []pki.Check
	enroll    http.Handler
	enrollPkg http.Handler
	packages  http.Handler
	log       *slog.Logger
	hsTimeout time.Duration

	http *http.Server
	feed chan net.Conn

	done     chan struct{}
	doneOnce sync.Once
	idents   sync.Map // *tls.Conn -> id агента (только для обычного HTTP)

	mu       sync.Mutex
	ln       net.Listener
	pending  map[net.Conn]struct{}
	shutdown bool
	wg       sync.WaitGroup
}

// New создаёт Gateway.
func New(cfg Config, opts ...Option) (*Gateway, error) {
	if cfg.CA == nil || cfg.Lookup == nil || cfg.Pool == nil {
		return nil, errors.New("gateway: CA, Lookup and Pool are required")
	}
	g := &Gateway{
		lookup:    cfg.Lookup,
		pool:      cfg.Pool,
		hsTimeout: 10 * time.Second,
		log:       slog.Default(),
		pending:   make(map[net.Conn]struct{}),
		feed:      make(chan net.Conn),
		done:      make(chan struct{}),
	}
	for _, o := range opts {
		o(g)
	}
	g.tlsCfg = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cfg.Cert},
		ClientCAs:    cfg.CA,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		NextProtos:   []string{transport.ALPNReverse, "h2", "http/1.1"},
	}
	if cfg.GetCertificate != nil {
		g.tlsCfg.Certificates = nil
		g.tlsCfg.GetCertificate = cfg.GetCertificate
	}
	g.http = &http.Server{
		Handler:           g.mux(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(g.log.Handler(), slog.LevelDebug),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if id, ok := g.idents.Load(c); ok {
				return context.WithValue(ctx, ctxKey{}, id)
			}
			return ctx
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				g.idents.Delete(c)
			}
		},
	}
	return g, nil
}

func (g *Gateway) mux() http.Handler {
	notFound := http.NotFoundHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == EnrollPath:
			if g.enroll == nil {
				notFound.ServeHTTP(w, r)
				return
			}
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			g.enroll.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, EnrollPackagePath):
			if g.enrollPkg == nil {
				notFound.ServeHTTP(w, r)
				return
			}
			g.enrollPkg.ServeHTTP(w, r)
		case len(r.URL.Path) >= len(PackagesPath) && r.URL.Path[:len(PackagesPath)] == PackagesPath:
			if g.packages == nil {
				notFound.ServeHTTP(w, r)
				return
			}
			g.packages.ServeHTTP(w, r)
		default:
			notFound.ServeHTTP(w, r)
		}
	})
}

// Addr возвращает адрес слушателя (после Serve), иначе nil.
func (g *Gateway) Addr() net.Addr {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ln == nil {
		return nil
	}
	return g.ln.Addr()
}

// ListenAndServe слушает addr и обслуживает соединения до Shutdown.
func (g *Gateway) ListenAndServe(addr string) error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	return g.Serve(ln)
}

// Serve принимает соединения с ln (TCP; TLS поверх добавляет Gateway) до
// Shutdown. После Shutdown возвращает http.ErrServerClosed.
func (g *Gateway) Serve(ln net.Listener) error {
	g.mu.Lock()
	if g.shutdown {
		g.mu.Unlock()
		_ = ln.Close()
		return http.ErrServerClosed
	}
	g.ln = ln
	g.mu.Unlock()

	go func() { _ = g.http.Serve(&feedListener{ch: g.feed, addr: ln.Addr(), done: g.done}) }()

	tl := tls.NewListener(ln, g.tlsCfg)
	for {
		c, err := tl.Accept()
		if err != nil {
			g.mu.Lock()
			sd := g.shutdown
			g.mu.Unlock()
			if sd {
				return http.ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		g.mu.Lock()
		if g.shutdown {
			g.mu.Unlock()
			_ = c.Close()
			return http.ErrServerClosed
		}
		g.pending[c] = struct{}{}
		g.wg.Add(1)
		g.mu.Unlock()
		go g.handle(c.(*tls.Conn))
	}
}

func (g *Gateway) closeDone() { g.doneOnce.Do(func() { close(g.done) }) }

// handle — рукопожатие, проверка идентичности и маршрутизация соединения.
func (g *Gateway) handle(c *tls.Conn) {
	defer g.wg.Done()
	release := func() {
		g.mu.Lock()
		delete(g.pending, c)
		g.mu.Unlock()
	}
	remote := c.RemoteAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), g.hsTimeout)
	err := c.HandshakeContext(ctx)
	cancel()
	if err != nil {
		release()
		g.log.Info("gateway: handshake failed", "remote", remote, "err", err)
		_ = c.Close()
		return
	}
	cs := c.ConnectionState()
	reverse := cs.NegotiatedProtocol == transport.ALPNReverse

	var agentID string
	if len(cs.PeerCertificates) > 0 {
		id, reason := g.authenticate(cs.PeerCertificates[0])
		if reason != "" {
			release()
			g.log.Warn("gateway: peer rejected", "remote", remote, "agent", id, "reason", reason)
			_ = c.Close()
			return
		}
		agentID = id
	} else if reverse {
		release()
		g.log.Warn("gateway: reverse channel without client certificate", "remote", remote)
		_ = c.Close()
		return
	}

	if reverse {
		release()
		if err := g.pool.Attach(agentID, c); err != nil {
			g.log.Warn("gateway: attach failed", "remote", remote, "agent", agentID, "err", err)
			_ = c.Close()
			return
		}
		g.log.Info("gateway: reverse channel attached", "remote", remote, "agent", agentID)
		return
	}

	// Обычный HTTP: передаём соединение http.Server (он владеет им дальше).
	release()
	if agentID != "" {
		g.idents.Store(c, agentID)
	}
	select {
	case g.feed <- c:
	case <-g.done:
		g.idents.Delete(c)
		_ = c.Close()
	}
}

// authenticate проверяет идентичность предъявленного листа (цепочку к CA уже
// проверил TLS). Возвращает причину отказа или "".
func (g *Gateway) authenticate(leaf *x509.Certificate) (id, reason string) {
	id, err := pki.AgentIDFromCert(leaf)
	if err != nil {
		return "", "no valid agent SAN"
	}
	if _, ok := g.lookup.Known(id); !ok {
		return id, "unknown agent"
	}
	for _, c := range g.checks {
		if err := c(leaf); err != nil {
			return id, "denied: " + err.Error()
		}
	}
	return id, ""
}

// Shutdown останавливает приём, закрывает соединения в рукопожатии и
// дожидается обычных HTTP-запросов (до ctx). Принятые reverse-соединения
// принадлежат ReversePool и не закрываются.
func (g *Gateway) Shutdown(ctx context.Context) error {
	g.mu.Lock()
	if g.shutdown {
		g.mu.Unlock()
		return nil
	}
	g.shutdown = true
	ln := g.ln
	for c := range g.pending {
		_ = c.Close()
	}
	g.mu.Unlock()
	g.closeDone()
	if ln != nil {
		_ = ln.Close()
	}
	g.wg.Wait()
	return g.http.Shutdown(ctx)
}

// feedListener отдаёт http.Server уже проверенные соединения.
type feedListener struct {
	ch   <-chan net.Conn
	addr net.Addr
	done <-chan struct{}
}

func (f *feedListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.ch:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}

func (f *feedListener) Close() error   { return nil }
func (f *feedListener) Addr() net.Addr { return f.addr }
