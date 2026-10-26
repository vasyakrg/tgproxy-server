package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
)

// EnrollTokenEnv — переменная окружения с токеном (предпочтительнее флага:
// флаг виден в ps и истории шелла).
const EnrollTokenEnv = "TGP_ENROLL_TOKEN" //nolint:gosec // G101: имя переменной, не секрет

func newAgentEnrollCmd() *cobra.Command {
	var o agent.EnrollOptions
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Подключить агента за NAT к серверу по одноразовому токену",
		Long: "Проверяет CA сервера по отпечатку (--ca-fingerprint), генерирует ключ P-256 локально,\n" +
			"получает сертификат и записывает mode: reverse и server_url в agent.yaml.\n" +
			"Токен берётся из $" + EnrollTokenEnv + " (или --token).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.Token == "" {
				o.Token = os.Getenv(EnrollTokenEnv)
			}
			if o.Token == "" {
				return errors.New("токен не задан: используйте $" + EnrollTokenEnv + " или --token")
			}
			res, err := agent.Enroll(cmd.Context(), o)
			if err != nil {
				return err
			}
			updHint := enableUpdatePath(cmd.Context())
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "агент %q зарегистрирован; ключ и сертификаты: %s, %s, %s\nконфиг: %s (mode: reverse)\nзапуск: systemctl enable --now tgproxy-agent\n%s",
				res.AgentID, res.KeyFile, res.CertFile, res.CAFile, res.ConfigPath, updHint)
			return nil
		},
	}
	cmd.Flags().StringVar(&o.Server, "server", "", "URL agent_gateway сервера, https://host:8444")
	cmd.Flags().StringVar(&o.Token, "token", "", "одноразовый токен (лучше через $"+EnrollTokenEnv+")")
	cmd.Flags().StringVar(&o.CAFingerprint, "ca-fingerprint", "", "отпечаток CA сервера, SHA256:...")
	cmd.Flags().StringVarP(&o.ConfigPath, "config", "c", agent.DefaultAgentConfigPath, "путь к agent.yaml")
	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("ca-fingerprint")
	return cmd
}

const agentUpdatePath = "tgproxy-update-agent.path"

// enableUpdatePath включает path-юнит самообновления агента (root + systemd) либо возвращает подсказку.
// Юнит рассчитан на data_dir=/var/lib/tgproxy/agent (docs/operations.md).
func enableUpdatePath(ctx context.Context) string {
	hint := "самообновление: systemctl enable --now " + agentUpdatePath + "\n"
	if os.Geteuid() != 0 {
		return hint
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return hint
	}
	if err := exec.CommandContext(ctx, "systemctl", "enable", "--now", agentUpdatePath).Run(); err != nil { // #nosec G204 -- константа
		return "самообновление не включено (" + err.Error() + "): systemctl enable --now " + agentUpdatePath + "\n"
	}
	return "самообновление: " + agentUpdatePath + " включён\n"
}
