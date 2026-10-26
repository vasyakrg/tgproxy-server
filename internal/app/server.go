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
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/proxy"
	"github.com/vasyakrg/tgproxy-server/internal/server/router"
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
	// ProxyListener / AdminListener — готовые листенеры вместо cfg.Listen.* (тесты).
	ProxyListener net.Listener
	AdminListener net.Listener
}

// snapshot — неизменяемое состояние, подменяемое атомарно при reload:
// Checker правил доступа, роутер и прокси-обработчик, собранные из одного конфига.
type snapshot struct {
	cfg     *config.ServerConfig
	up      *Upstream
	handler http.Handler
}

// Server — процесс `tgproxy server`.
type Server struct {
	logger *slog.Logger
	opts   ServerOptions
	tr     *transport.Registry
	ingTLS *tls.Config
	cur    atomic.Pointer[snapshot]
}

// NewServer собирает сервер: mTLS до агентов, TLS входа, обработчики. Сеть не открывается.
func NewServer(cfg *config.ServerConfig, logger *slog.Logger, opts ...ServerOptions) (*Server, error) {
	s := &Server{logger: logger}
	if len(opts) > 0 {
		s.opts = opts[0]
	}
	cert, pool, err := loadAgentTLS(cfg)
	if err != nil {
		return nil, err
	}
	s.tr = transport.NewRegistry(map[config.AgentMode]transport.AgentTransport{
		config.AgentModeDial: transport.NewDial(cert, pool),
	})
	if s.ingTLS, err = ingressTLS(cfg); err != nil {
		return nil, err
	}
	snap, err := s.build(cfg)
	if err != nil {
		return nil, err
	}
	s.cur.Store(snap)
	return s, nil
}

func (s *Server) build(cfg *config.ServerConfig) (*snapshot, error) {
	checker, err := access.NewStatic(cfg.AccessRules, cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("app: access rules: %w", err)
	}
	up, err := NewUpstream(s.tr, cfg.Agents)
	if err != nil {
		return nil, err
	}
	h := proxy.New(checker, router.New(cfg, up, s.logger), cfg, s.logger)
	return &snapshot{cfg: cfg, up: up, handler: h}, nil
}

// Reload перечитывает конфиг и атомарно подменяет правила доступа (и всё, что
// собрано из них), а также уровень логов. При ошибке остаётся прежнее состояние.
func (s *Server) Reload() error {
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
	old := s.cur.Swap(snap)
	if s.opts.Level != nil {
		s.opts.Level.Set(lvl)
	}
	if old != nil && (!reflect.DeepEqual(old.cfg.Listen, cfg.Listen) || !reflect.DeepEqual(old.cfg.TLS, cfg.TLS) ||
		!reflect.DeepEqual(old.cfg.AgentTLS, cfg.AgentTLS)) {
		s.logger.Warn("listen/tls settings changed: restart required, not applied")
	}
	s.logger.Info("config reloaded", "access_rules", len(cfg.AccessRules), "agents", len(cfg.Agents))
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
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyProbeTimeout)
		defer cancel()
		if !s.cur.Load().up.AnyReady(ctx) {
			http.Error(w, "no agent ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
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
			if err := s.Reload(); err != nil {
				s.logger.Error("reload rejected, keeping previous config", "error", redact.Error(err))
			}
		})
	}
	s.logger.Info("server started", "proxy", proxyLn.Addr().String(), "admin", adminLn.Addr().String(),
		"tls", s.ingTLS != nil)

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
	_ = s.tr.Close()
	return first
}

// RunServer запускает сервер и блокируется до отмены ctx.
func RunServer(ctx context.Context, cfg *config.ServerConfig, logger *slog.Logger, opts ...ServerOptions) error {
	s, err := NewServer(cfg, logger, opts...)
	if err != nil {
		return err
	}
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
