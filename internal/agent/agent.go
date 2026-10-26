// Package agent реализует `tgproxy agent`: mTLS-сервер, прозрачно проксирующий
// /tg/* в Telegram Bot API и отдающий служебные /_agent/* эндпоинты
// (docs/architecture.md §4).
package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Agent — mTLS-прокси до Telegram Bot API.
type Agent struct {
	cfg      *config.AgentConfig
	logger   *slog.Logger
	upstream *url.URL
	tlsCfg   *tls.Config
	upTLS    *tls.Config // TLS до Telegram
	certs    certHolder  // действующий сертификат (горячая подмена)
	pendMu   sync.Mutex
	pending  *ecdsa.PrivateKey // ключ, ожидающий подписанный сертификат (/_agent/csr)
	caPool   *x509.CertPool
	mgr      *manager
	connOpts []ConnectorOption
	saveConn func(path string, mode config.AgentMode, serverURL string) error

	transport *http.Transport
	proxy     *proxy
	stats     *stats
	rec       Recorder
	health    *healthProbe
	draining  atomic.Bool
	started   time.Time
	now       func() time.Time
}

// Option настраивает Agent. Опции предназначены для тестов и не влияют на
// прод-путь.
type Option func(*Agent)

// WithUpstreamRootCAs подменяет корни доверия для TLS до Telegram (только
// тесты: в проде используются системные корни).
func WithUpstreamRootCAs(pool *x509.CertPool) Option {
	return func(a *Agent) { a.upTLS.RootCAs = pool }
}

// WithConnectorOptions задаёт опции reverse-коннектора (backoff и т.п.; тесты).
func WithConnectorOptions(o ...ConnectorOption) Option {
	return func(a *Agent) { a.connOpts = append(a.connOpts, o...) }
}

// New загружает TLS-материалы и собирает агента. Сеть не открывается.
func New(cfg *config.AgentConfig, logger *slog.Logger, opts ...Option) (*Agent, error) {
	if cfg == nil {
		return nil, errors.New("agent: nil config")
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = slog.New(redact.NewHandler(logger.Handler()))

	up, err := url.Parse(cfg.TelegramAPIURL())
	if err != nil || up.Scheme != "https" || up.Host == "" {
		return nil, fmt.Errorf("agent: bad telegram api url %q", redact.String(cfg.TelegramAPIURL()))
	}
	cert, err := loadKeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("agent: load key pair: %w", redact.Error(err))
	}
	caPEM, err := os.ReadFile(cfg.TLS.CAFile)
	if err != nil {
		return nil, fmt.Errorf("agent: read ca: %w", redact.Error(err))
	}
	caPool, err := pki.PoolFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("agent: ca pool: %w", err)
	}
	tlsCfg, err := pki.ServerTLSConfig(cert, caPool, pki.VerifyServerPeer(caPool))
	if err != nil {
		return nil, fmt.Errorf("agent: tls config: %w", err)
	}
	held, err := newHeldCert(cert)
	if err != nil {
		return nil, err
	}
	// Сертификат отдаётся через GetCertificate: ротация без рестарта.
	tlsCfg.Certificates = nil
	// h1 оставлен для curl/диагностики; идентичность клиента проверяется так же.
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}

	a := &Agent{
		cfg:      cfg,
		logger:   logger,
		upstream: up,
		tlsCfg:   tlsCfg,
		caPool:   caPool,
		saveConn: config.SaveAgentConnection,
		upTLS:    &tls.Config{MinVersion: tls.VersionTLS12},
		stats:    newStats(time.Now),
		rec:      noopRecorder{},
		now:      time.Now,
	}
	a.certs.set(held)
	tlsCfg.GetCertificate = a.certs.serverCert
	for _, o := range opts {
		o(a)
	}
	a.mgr = newManager(a)
	a.started = a.now()
	a.transport = newUpstreamTransport(a.upTLS)
	a.proxy = newProxy(a)
	a.health = newHealthProbe(a.probeUpstream, a.now)
	return a, nil
}

// Draining сообщает, что агент не принимает новые /tg/* запросы.
func (a *Agent) Draining() bool { return a.draining.Load() }

// SetDraining включает/выключает drain.
func (a *Agent) SetDraining(v bool) { a.draining.Store(v) }

// writeAgentError пишет ошибку, сформированную самим агентом.
func writeAgentError(w http.ResponseWriter, code int, phase, desc string) {
	w.Header().Set(tgapi.HeaderSource, tgapi.SourceAgent)
	if phase != "" {
		w.Header().Set(tgapi.HeaderErrorPhase, phase)
	}
	tgapi.WriteError(w, code, desc, 0)
}

func closeIdle(a *Agent) { a.transport.CloseIdleConnections() }

// Run работает в режиме cfg.Mode (dial слушает cfg.Listen.API, reverse
// дозванивается до cfg.ServerURL, both — оба) до отмены ctx, затем gracefully
// завершается. Режим меняется на лету через PUT /_agent/config.
func (a *Agent) Run(ctx context.Context) error { return a.Serve(ctx, nil) }

// Serve — как Run, но dial-листенер использует готовый ln (nil — слушать
// cfg.Listen.API).
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	m := a.mgr
	m.mu.Lock()
	m.ctx, m.preset = ctx, ln
	mode, url := m.mode, m.url
	m.mu.Unlock()
	_, err := m.switchTo(mode, url) //nolint:contextcheck // ctx сохранён в менеджере
	if err != nil {
		_ = m.stopAll()
		return err
	}
	select {
	case err := <-m.fatal:
		_ = m.stopAll()
		return err
	case <-ctx.Done():
	}
	a.logger.Info("agent shutting down")
	return m.stopAll()
}
