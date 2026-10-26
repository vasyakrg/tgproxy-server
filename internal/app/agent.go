package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/metrics"
)

// AgentOptions — необязательные параметры RunAgent.
type AgentOptions struct {
	// Agent — опции agent.New (тесты).
	Agent []agent.Option
	// Listener — готовый листенер вместо cfg.Listen.API (тесты).
	Listener net.Listener
	// Level — LevelVar логгера; с ReloadConfig обновляется по SIGHUP.
	Level *slog.LevelVar
	// ReloadConfig перечитывает конфиг при SIGHUP (nil — SIGHUP игнорируется).
	ReloadConfig func() (*config.AgentConfig, error)
}

// RunAgent запускает агента и блокируется до отмены ctx (graceful shutdown
// выполняет agent.Run). SIGHUP перечитывает конфиг и применяет уровень логов.
func RunAgent(ctx context.Context, cfg *config.AgentConfig, logger *slog.Logger, opts ...AgentOptions) error {
	var o AgentOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	reg, mrec := metrics.NewAgentRegistry()
	agentOpts := append([]agent.Option{agent.WithRecorder(agentRecorder{mrec})}, o.Agent...)
	a, err := agent.New(cfg, logger, agentOpts...)
	if err != nil {
		return err
	}
	mrec.WatchReverseConns(a.ReverseConns)
	var msrv *agentMetricsServer
	if cfg.Listen.Metrics != "" {
		msrv, err = startAgentMetrics(ctx, cfg.Listen.Metrics, cfg.Metrics.Bearer.Reveal(), reg, logger)
		if err != nil {
			return err
		}
		defer msrv.stop(context.WithoutCancel(ctx))
	}
	if o.ReloadConfig != nil && o.Level != nil {
		onReload(ctx, func() {
			nc, err := o.ReloadConfig()
			if err != nil {
				logger.Error("reload rejected, keeping previous config", "error", err)
				return
			}
			lvl, err := ParseLevel(nc.Logging.Level)
			if err != nil {
				logger.Error("reload rejected, keeping previous config", "error", err)
				return
			}
			o.Level.Set(lvl)
			logger.Info("config reloaded (only log level is applied at runtime)")
		})
	}
	logger.Info("agent starting", "mode", cfg.Mode, "api", cfg.Listen.API, "server_url", cfg.ServerURL)
	if o.Listener != nil {
		return a.Serve(ctx, o.Listener)
	}
	return a.Run(ctx)
}

// agentRecorder адаптирует metrics.Agent к agent.Recorder: пустая фаза
// (ответил Telegram) пишется как "none".
type agentRecorder struct{ *metrics.Agent }

func (r agentRecorder) Request(codeClass, phase string) {
	if phase == "" {
		phase = "none"
	}
	r.Agent.Request(codeClass, phase)
}

type agentMetricsServer struct {
	srv    *http.Server
	logger *slog.Logger
	done   chan struct{}
	addr   string
}

// startAgentMetrics поднимает отдельный листенер /metrics (bearer обязателен для
// не-loopback адреса).
func startAgentMetrics(ctx context.Context, addr, bearer string, reg *prometheus.Registry, logger *slog.Logger) (*agentMetricsServer, error) {
	h, err := metrics.NewHandler(reg, bearer, agentMetricsLoopback(addr))
	if err != nil {
		return nil, fmt.Errorf("agent metrics: %w", err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("agent metrics: listen %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h)
	m := &agentMetricsServer{
		srv:    &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second},
		logger: logger,
		done:   make(chan struct{}),
		addr:   ln.Addr().String(),
	}
	go func() {
		defer close(m.done)
		if err := m.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("agent metrics server failed", "error", err)
		}
	}()
	logger.Info("agent metrics listening", "addr", ln.Addr().String())
	return m, nil
}

func (m *agentMetricsServer) stop(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := m.srv.Shutdown(ctx); err != nil {
		_ = m.srv.Close()
	}
	<-m.done
}

// agentMetricsLoopback: слушает ли адрес только loopback (":9443" — нет).
func agentMetricsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
