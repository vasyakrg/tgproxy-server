package app

import (
	"context"
	"log/slog"
	"net"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/config"
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
	a, err := agent.New(cfg, logger, o.Agent...)
	if err != nil {
		return err
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
	logger.Info("agent starting", "api", cfg.Listen.API)
	if o.Listener != nil {
		return a.Serve(ctx, o.Listener)
	}
	return a.Run(ctx)
}
