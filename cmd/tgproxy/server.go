package main

import (
	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/config"
)

func newServerCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Запустить сервер (прокси для ботов)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadServer(cfgPath)
			if err != nil {
				return err
			}
			logger, level, err := app.NewLogger(cfg.Logging, nil)
			if err != nil {
				return err
			}
			ctx, stop := signalContext(cmd.Context())
			defer stop()
			return app.RunServer(ctx, cfg, logger, app.ServerOptions{
				Level:        level,
				ReloadConfig: func() (*config.ServerConfig, error) { return config.LoadServer(cfgPath) },
			})
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}
