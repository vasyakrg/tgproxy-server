package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
)

// EnrollTokenEnv — переменная окружения с токеном (предпочтительнее флага:
// флаг виден в ps и истории шелла).
const EnrollTokenEnv = "TGP_ENROLL_TOKEN" // #nosec G101 -- G101: имя переменной, не секрет

func newAgentEnrollCmd() *cobra.Command {
	var (
		o          agent.EnrollOptions
		tokenStdin bool
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Подключить агента за NAT к серверу по одноразовому токену",
		Long: "Проверяет CA сервера по отпечатку (--ca-fingerprint), генерирует ключ P-256 локально,\n" +
			"получает сертификат и записывает mode: reverse и server_url в agent.yaml.\n" +
			"Токен (в порядке приоритета): --token; $" + EnrollTokenEnv + "; stdin (--token-stdin, он же по умолчанию,\n" +
			"если stdin не терминал). Через stdin токен не виден в `ps`:\n" +
			"  printf %s '<токен>' | sudo tgproxy agent enroll --token-stdin --server ... --ca-fingerprint ...\n" +
			"(printf — встроенная команда bash/sh, отдельного процесса с токеном в argv нет). Без записи в историю:\n" +
			"  read -rs T && printf %s \"$T\" | sudo tgproxy agent enroll --token-stdin ...; unset T",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok, err := resolveEnrollToken(o.Token, os.Getenv(EnrollTokenEnv), tokenStdin, cmd.InOrStdin())
			if err != nil {
				return err
			}
			o.Token = tok
			res, err := agent.Enroll(cmd.Context(), o)
			if err != nil {
				return err
			}
			updHint := enableUpdatePath(cmd.Context())
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "агент %q зарегистрирован; ключ и сертификаты: %s, %s, %s\nконфиг: %s (mode: reverse)\nзапуск: systemctl enable tgproxy-agent && systemctl restart tgproxy-agent\n%s",
				res.AgentID, res.KeyFile, res.CertFile, res.CAFile, res.ConfigPath, updHint)
			return nil
		},
	}
	cmd.Flags().StringVar(&o.Server, "server", "", "URL agent_gateway сервера, https://host:8444")
	cmd.Flags().StringVar(&o.Token, "token", "", "одноразовый токен (виден в ps; лучше --token-stdin)")
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "прочитать токен из stdin (первая строка); по умолчанию, если stdin не терминал")
	cmd.Flags().StringVar(&o.CAFingerprint, "ca-fingerprint", "", "отпечаток CA сервера, SHA256:...")
	cmd.Flags().StringVarP(&o.ConfigPath, "config", "c", agent.DefaultAgentConfigPath, "путь к agent.yaml")
	cmd.Flags().StringVar(&o.ServiceUser, "service-user", agent.DefaultServiceUser, "пользователь юнита tgproxy-agent: от root ему отдаются конфиг (root:группа) и данные")
	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("ca-fingerprint")
	return cmd
}

const maxEnrollTokenLen = 4096

// resolveEnrollToken выбирает источник токена: флаг, окружение, затем stdin
// (явно по --token-stdin или неявно, если stdin не терминал).
func resolveEnrollToken(flagTok, envTok string, stdinFlag bool, in io.Reader) (string, error) {
	if !stdinFlag {
		if flagTok != "" {
			return flagTok, nil
		}
		if envTok != "" {
			return envTok, nil
		}
	}
	f, isFile := in.(*os.File)
	if isFile && term.IsTerminal(int(f.Fd())) { //nolint:gosec // fd влезает в int
		return "", errors.New("токен не задан: передайте через stdin (read -rs T && printf %s \"$T\" | sudo tgproxy agent enroll --token-stdin ...), $" +
			EnrollTokenEnv + " или --token")
	}
	line, err := bufio.NewReader(io.LimitReader(in, maxEnrollTokenLen)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("чтение токена из stdin: %w", err)
	}
	tok := strings.TrimSpace(line)
	if tok == "" {
		return "", errors.New("токен не задан: stdin пуст (используйте --token-stdin, $" + EnrollTokenEnv + " или --token)")
	}
	return tok, nil
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
