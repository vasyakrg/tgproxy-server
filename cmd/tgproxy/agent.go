package main

import (
	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/config"
)

func newAgentCmd() *cobra.Command {
	var cfgPath, tgURL string
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Запустить агента (mTLS-прокси до Telegram)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadAgent(cfgPath)
			if err != nil {
				return err
			}
			if tgURL != "" {
				if err := cfg.OverrideTelegramAPIURL(tgURL); err != nil {
					return err
				}
			}
			logger, level, err := app.NewLogger(cfg.Logging, nil)
			if err != nil {
				return err
			}
			ctx, stop := signalContext(cmd.Context())
			defer stop()
			return app.RunAgent(ctx, cfg, logger, app.AgentOptions{
				Level:        level,
				ReloadConfig: func() (*config.AgentConfig, error) { return config.LoadAgent(cfgPath) },
			})
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к agent.yaml")
	_ = cmd.MarkFlagRequired("config")
	cmd.Flags().StringVar(&tgURL, "telegram-api-url", "", "подмена upstream (только e2e)")
	_ = cmd.Flags().MarkHidden("telegram-api-url")
	return cmd
}
