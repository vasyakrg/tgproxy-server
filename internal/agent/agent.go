// Package agent реализует `tgproxy agent`: mTLS-сервер, прозрачно проксирующий
// /tg/* в Telegram Bot API и отдающий служебные /_agent/* эндпоинты
// (docs/architecture.md §4).
package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
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
	notAfter time.Time

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
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
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
	// h1 оставлен для curl/диагностики; идентичность клиента проверяется так же.
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}

	a := &Agent{
		cfg:      cfg,
		logger:   logger,
		upstream: up,
		tlsCfg:   tlsCfg,
		upTLS:    &tls.Config{MinVersion: tls.VersionTLS12},
		stats:    newStats(time.Now),
		rec:      noopRecorder{},
		now:      time.Now,
	}
	if len(cert.Certificate) > 0 {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
			a.notAfter = leaf.NotAfter
		}
	}
	for _, o := range opts {
		o(a)
	}
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
