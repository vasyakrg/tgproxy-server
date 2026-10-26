package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/config"
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
			switch mode {
			case "server":
				_, err = config.LoadServer(cfgPath)
			case "agent":
				_, err = config.LoadAgent(cfgPath)
			default:
				return fmt.Errorf("unknown --mode %q (server|agent)", mode)
			}
			if err != nil {
				return err
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
