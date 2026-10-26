package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/server/proxy"
	"github.com/vasyakrg/tgproxy-server/internal/server/router"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

const (
	shutdownTimeout   = 30 * time.Second
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	readyProbeTimeout = 2 * time.Second
)

// ServerOptions — необязательные параметры RunServer.
type ServerOptions struct {
	// Level — LevelVar логгера; обновляется при reload.
	Level *slog.LevelVar
	// ReloadConfig перечитывает конфиг при SIGHUP (nil — SIGHUP игнорируется).
	ReloadConfig func() (*config.ServerConfig, error)
	// AccessOptions / AgentOptions — дополнительные опции access.Checker и
	// agents.Registry (тесты: быстрые интервалы).
	AccessOptions []access.Option
	AgentOptions  []agents.Option
	// ProxyListener / AdminListener — готовые листенеры вместо cfg.Listen.* (тесты).
	ProxyListener net.Listener
	AdminListener net.Listener
	// MetricsListener — готовый листенер /metrics вместо cfg.Listen.Metrics (тесты).
	MetricsListener net.Listener
	// SamplerTicks подменяет 10-секундный тикер сэмплера истории (тесты).
	SamplerTicks <-chan time.Time
	// NotifyPoll — период опроса outbox (тесты); 0 — по умолчанию.
	NotifyPoll time.Duration
}

// snapshot — неизменяемое состояние, подменяемое атомарно при reload:
// конфиг и собранный из него обработчик прокси.
type snapshot struct {
	cfg     *config.ServerConfig
	router  *router.Router
	handler http.Handler
}

// Server — процесс `tgproxy server`.
type Server struct {
	logger  *slog.Logger
	opts    ServerOptions
	tr      *transport.Registry
	ingTLS  *tls.Config
	st      store.Store
	checker *access.Checker
	bal     *balancer.Balancer
	reg     *agents.Registry
	up      *Upstream
	windows *router.Windows
	obs     *obs
	cur     atomic.Pointer[snapshot]
	closed  sync.Once
}

// NewServer собирает сервер: хранилище, mTLS до агентов, реестр агентов,
// правила доступа, TLS входа, обработчики. Сеть не открывается; фоновые
// горутины реестра стартуют в Serve. После неуспешного Serve (или без него)
// вызывайте Close.
func NewServer(ctx context.Context, cfg *config.ServerConfig, logger *slog.Logger, opts ...ServerOptions) (*Server, error) {
	s := &Server{logger: logger}
	if len(opts) > 0 {
		s.opts = opts[0]
	}
	cert, pool, err := loadAgentTLS(cfg)
	if err != nil {
		return nil, err
	}
	if s.ingTLS, err = ingressTLS(cfg); err != nil {
		return nil, err
	}
	if err := router.CleanupTmpDir(cfg.Buffer.TmpDir); err != nil {
		logger.Warn("cleanup of stale buffers failed", "error", redact.Error(err))
	}
	var distributed bool
	if s.st, distributed, err = openStore(ctx, cfg); err != nil {
		return nil, err
	}
	s.tr = transport.NewRegistry(map[config.AgentMode]transport.AgentTransport{
		config.AgentModeDial: transport.NewDial(cert, pool),
	})
	if err := s.wire(context.WithoutCancel(ctx), cfg, distributed); err != nil {
		s.Close()
		return nil, err
	}
	snap, err := s.build(cfg)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.cur.Store(snap)
	if s.obs.deliv != nil {
		if err := s.obs.deliv.Reload(); err != nil {
			logger.Warn("notify recipients not loaded", "error", redact.Error(err))
		}
	}
	return s, nil
}

// wire засевает БД из конфига (только в пустые таблицы) и собирает
// Checker, балансировщик, реестр агентов и окна 429.
func (s *Server) wire(ctx context.Context, cfg *config.ServerConfig, distributed bool) error {
	nr, err := access.SeedFromConfig(ctx, s.st.AccessRules(), cfg.AccessRules)
	if err != nil {
		return fmt.Errorf("app: seed access rules: %w", err)
	}
	na, err := agents.SeedFromConfig(ctx, s.st.Agents(), cfg.Agents)
	if err != nil {
		return fmt.Errorf("app: seed agents: %w", err)
	}
	if nr > 0 || na > 0 {
		s.logger.Info("database seeded from config", "access_rules", nr, "agents", na)
	}

	aopts := []access.Option{access.WithLogger(s.logger)}
	if distributed {
		aopts = append(aopts, access.WithDistributedLimit(s.st.RateState()))
	}
	aopts = append(aopts, s.opts.AccessOptions...)
	if s.checker, err = access.NewFromStore(ctx, s.st.AccessRules(), cfg.TrustedProxies, aopts...); err != nil {
		return fmt.Errorf("app: access rules: %w", err)
	}

	s.bal = balancer.New()
	s.reg = agents.New(s.st.Agents(), s.tr, s.bal,
		append([]agents.Option{agents.WithLogger(s.logger)}, s.opts.AgentOptions...)...)
	s.up = NewUpstream(s.tr, s.reg)

	var ws router.Store = router.NewMemStore(nil)
	if distributed {
		ws = windowStore{repo: s.st.RateState()}
	}
	s.windows = router.NewWindows(ws, nil)
	return s.wireObs(cfg)
}

func (s *Server) build(cfg *config.ServerConfig) (*snapshot, error) {
	rt := router.New(cfg, s.up, s.logger,
		router.WithBalancer(s.bal),
		router.WithWindows(s.windows),
		router.WithBufferConfig(cfg.Buffer),
		router.WithPassive(s.reg.ReportResult),
		router.WithRecorder(s.obs.m),
		router.WithHistory(s.obs.coll),
		router.WithErrorLog(s.obs.errlog),
		router.WithInflight(s.obs.inflight),
		router.WithBufferGauge(s.obs.m.BufferedBytes()),
	)
	h := proxy.New(s.checker, rt, cfg, s.logger, proxy.WithRecorder(s.obs.m), proxy.WithBots(s.obs.top))
	return &snapshot{cfg: cfg, router: rt, handler: h}, nil
}

// Close освобождает ресурсы (Checker, транспорт, хранилище); идемпотентен.
func (s *Server) Close() {
	s.closed.Do(func() {
		if s.checker != nil {
			s.checker.Close()
		}
		if s.tr != nil {
			_ = s.tr.Close()
		}
		if s.st != nil {
			_ = s.st.Close()
		}
	})
}

// Reload перечитывает конфиг: применяет уровень логов и параметры обработчика,
// просит Checker перечитать правила доступа из БД. При ошибке остаётся прежнее
// состояние. Правила доступа и агенты живут в БД и меняются через CLI/UI.
func (s *Server) Reload(ctx context.Context) error {
	if s.opts.ReloadConfig == nil {
		return errors.New("app: reload not configured")
	}
	cfg, err := s.opts.ReloadConfig()
	if err != nil {
		return fmt.Errorf("app: reload: %w", err)
	}
	var lvl slog.Level
	if s.opts.Level != nil {
		if lvl, err = ParseLevel(cfg.Logging.Level); err != nil {
			return err
		}
	}
	snap, err := s.build(cfg)
	if err != nil {
		return fmt.Errorf("app: reload: %w", err)
	}
	rctx, cancel := context.WithTimeout(ctx, readyProbeTimeout)
	defer cancel()
	if err := s.checker.Refresh(rctx); err != nil {
		return fmt.Errorf("app: reload: refresh access rules: %w", err)
	}
	old := s.cur.Swap(snap)
	if s.opts.Level != nil {
		s.opts.Level.Set(lvl)
	}
	if old != nil && (!reflect.DeepEqual(old.cfg.Listen, cfg.Listen) || !reflect.DeepEqual(old.cfg.TLS, cfg.TLS) ||
		!reflect.DeepEqual(old.cfg.AgentTLS, cfg.AgentTLS) || old.cfg.Metrics.BearerFile != cfg.Metrics.BearerFile ||
		!reflect.DeepEqual(old.cfg.Notify, cfg.Notify) || !reflect.DeepEqual(old.cfg.Store, cfg.Store)) {
		s.logger.Warn("listen/tls/store settings changed: restart required, not applied")
	}
	if s.obs.deliv != nil {
		if err := s.obs.deliv.Reload(); err != nil {
			s.logger.Warn("notify recipients reload failed, keeping previous", "error", redact.Error(err))
		}
	}
	s.logger.Info("config reloaded")
	return nil
}

// proxyHandler делегирует текущему снимку.
func (s *Server) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.cur.Load().handler.ServeHTTP(w, r)
	})
}

func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.anyAgentUp() {
			http.Error(w, "no agent ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// anyAgentUp — хотя бы один агент up в реестре.
func (s *Server) anyAgentUp() bool {
	for _, st := range s.reg.List() {
		if st.Up {
			return true
		}
	}
	return false
}

func newHTTPServer(h http.Handler, tlsCfg *tls.Config, errLog *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      0, // long-poll и большие файлы
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(errLog.Handler(), slog.LevelWarn),
	}
}

// Serve обслуживает листенеры proxy и admin до отмены ctx, затем завершает
// работу: прекращает приём и ждёт inflight до 30s.
func (s *Server) Serve(ctx context.Context, proxyLn, adminLn net.Listener) error {
	srvs := []*http.Server{
		newHTTPServer(s.proxyHandler(), s.ingTLS, s.logger),
		newHTTPServer(s.adminHandler(), s.ingTLS, s.logger),
	}
	lns := []net.Listener{proxyLn, adminLn}
	if ml := s.opts.MetricsListener; ml != nil && s.obs.metricsHandler != nil {
		srvs = append(srvs, newHTTPServer(s.obs.metricsHandler, s.ingTLS, s.logger))
		lns = append(lns, ml)
	}
	errc := make(chan error, len(srvs))
	for i, srv := range srvs {
		go func() {
			var err error
			if s.ingTLS != nil {
				err = srv.ServeTLS(lns[i], "", "")
			} else {
				err = srv.Serve(lns[i])
			}
			errc <- err
		}()
	}
	if s.opts.ReloadConfig != nil {
		onReload(ctx, func() {
			if err := s.Reload(ctx); err != nil {
				s.logger.Error("reload rejected, keeping previous config", "error", redact.Error(err))
			}
		})
	}
	rctx, rcancel := context.WithCancel(context.WithoutCancel(ctx))
	regDone := make(chan struct{})
	events, unsub := s.reg.Subscribe()
	go s.syncAgentMetrics(ctx, events)
	obsWait := s.runObs(rctx)
	go func() {
		defer close(regDone)
		if err := s.reg.Run(rctx); err != nil {
			s.logger.Error("agent registry stopped", "error", redact.Error(err))
		}
	}()
	s.logger.Info("server started", "proxy", proxyLn.Addr().String(), "admin", adminLn.Addr().String(),
		"metrics", len(lns) > 2, "tls", s.ingTLS != nil)

	var first error
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			first = err
		}
	}
	s.logger.Info("shutting down", "timeout", shutdownTimeout)
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	for _, srv := range srvs {
		if err := srv.Shutdown(sctx); err != nil {
			s.logger.Warn("graceful shutdown incomplete, closing", "error", err)
			_ = srv.Close()
		}
	}
	rcancel()
	<-regDone
	obsWait()
	unsub()
	s.Close()
	return first
}

// RunServer запускает сервер и блокируется до отмены ctx.
func RunServer(ctx context.Context, cfg *config.ServerConfig, logger *slog.Logger, opts ...ServerOptions) error {
	s, err := NewServer(ctx, cfg, logger, opts...)
	if err != nil {
		return err
	}
	defer s.Close()
	var lc net.ListenConfig
	proxyLn, adminLn := s.opts.ProxyListener, s.opts.AdminListener
	if proxyLn == nil {
		if proxyLn, err = lc.Listen(ctx, "tcp", cfg.Listen.Proxy); err != nil {
			return fmt.Errorf("app: listen proxy: %w", err)
		}
	}
	if adminLn == nil {
		if adminLn, err = lc.Listen(ctx, "tcp", cfg.Listen.Admin); err != nil {
			_ = proxyLn.Close()
			return fmt.Errorf("app: listen admin: %w", err)
		}
	}
	if s.opts.MetricsListener == nil && cfg.Listen.Metrics != "" {
		ln, lerr := lc.Listen(ctx, "tcp", cfg.Listen.Metrics)
		if lerr != nil {
			_ = proxyLn.Close()
			_ = adminLn.Close()
			return fmt.Errorf("app: listen metrics: %w", lerr)
		}
		s.opts.MetricsListener = ln
	}
	return s.Serve(ctx, proxyLn, adminLn)
}

// loadAgentTLS загружает клиентский сертификат сервера и CA: сначала
// cfg.AgentTLS, иначе файлы dev-PKI из pki.dir.
func loadAgentTLS(cfg *config.ServerConfig) (tls.Certificate, *x509.CertPool, error) {
	certFile, keyFile, caFile := cfg.AgentTLS.CertFile, cfg.AgentTLS.KeyFile, cfg.AgentTLS.CAFile
	if certFile == "" {
		d := cfg.PKI.Dir
		certFile, keyFile, caFile = filepath.Join(d, pki.FileServerCert), filepath.Join(d, pki.FileServerKey), filepath.Join(d, pki.FileCACert)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("app: load agent client cert: %w", redact.Error(err))
	}
	caPEM, err := os.ReadFile(caFile) //nolint:gosec // путь из конфигурации
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("app: read agent ca: %w", redact.Error(err))
	}
	pool, err := pki.PoolFromPEM(caPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("app: agent ca: %w", err)
	}
	return cert, pool, nil
}

// ingressTLS возвращает TLS-конфиг входа (nil для mode=off).
func ingressTLS(cfg *config.ServerConfig) (*tls.Config, error) {
	switch cfg.TLS.Mode {
	case config.TLSModeOff, "":
		return nil, nil //nolint:nilnil // TLS выключен
	case config.TLSModeFiles:
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("app: load ingress cert: %w", redact.Error(err))
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	case config.TLSModeACME:
		return nil, errors.New("app: tls.mode=acme is not implemented yet (M4-T9)")
	default:
		return nil, fmt.Errorf("app: unknown tls.mode %q", cfg.TLS.Mode)
	}
}
