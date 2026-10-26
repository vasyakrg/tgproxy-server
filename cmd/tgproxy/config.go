package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

// Каталоги, на которые рассчитаны юниты tgproxy-update-{server,agent}.path (packaging/systemd).
const (
	defaultServerStaging = "/var/lib/tgproxy/updates"
	defaultAgentDataDir  = "/var/lib/tgproxy/agent"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Работа с конфигурацией"}
	cmd.AddCommand(newConfigValidateCmd())
	return cmd
}

func newConfigValidateCmd() *cobra.Command {
	var mode, cfgPath string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Проверить конфигурацию (загрузка, env, секреты, валидация)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			var warns []string
			switch mode {
			case "server":
				var c *config.ServerConfig
				if c, err = config.LoadServer(cfgPath); err == nil && c.Update.Enabled && c.Update.StagingDir != defaultServerStaging {
					warns = append(warns, fmt.Sprintf("update.staging_dir=%q отличается от %q: переопределите tgproxy-update-server.{path,service} drop-in'ом (docs/architecture.md §12), иначе самообновление не запустится",
						c.Update.StagingDir, defaultServerStaging))
				}
			case "agent":
				var c *config.AgentConfig
				if c, err = config.LoadAgent(cfgPath); err == nil && c.DataDir != defaultAgentDataDir {
					warns = append(warns, fmt.Sprintf("data_dir=%q отличается от %q: переопределите tgproxy-update-agent.{path,service} drop-in'ом (docs/architecture.md §12), иначе самообновление агента не запустится",
						c.DataDir, defaultAgentDataDir))
				}
			default:
				return fmt.Errorf("unknown --mode %q (server|agent)", mode)
			}
			if err != nil {
				return err
			}
			for _, w := range warns {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: "+w)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "OK: %s config %s is valid\n", mode, cfgPath)
			return err
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "", "server|agent")
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к конфигу")
	_ = cmd.MarkFlagRequired("mode")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}
