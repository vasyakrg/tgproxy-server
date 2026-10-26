package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// newHostKeysCmd — управление закреплёнными SSH host key (TOFU). Только CLI на сервере:
// сброс пина через веб-сессию сделал бы возможной подмену хоста.
func newHostKeysCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "hostkeys", Short: "Закреплённые SSH host key мастера установки (напрямую из БД)"}
	cmd.AddCommand(newHostKeysListCmd(), newHostKeysForgetCmd())
	return cmd
}

func newHostKeysListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Список закреплённых ключей хостов",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			list, err := st.HostKeys().List(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "HOST\tALGO\tFINGERPRINT\tPINNED")
			for _, k := range list {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k.Host, orDash(k.Algo), k.Fingerprint, k.CreatedAt.Local().Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newHostKeysForgetCmd() *cobra.Command {
	var (
		cfgPath string
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "forget <host:port>",
		Short: "Сбросить закреплённый ключ хоста (после легитимной переустановки)",
		Long: "Удаляет пин; при следующей установке отпечаток нужно подтвердить заново.\n" +
			"Без --yes показывает текущий отпечаток и просит подтверждение (y/N); нужен интерактивный терминал,\n" +
			"иначе отказ (для автоматизации — --yes).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			if !yes && !stdinIsTerminal(cmd.InOrStdin()) {
				return errors.New("подтверждение требует интерактивного терминала (stdin не tty): запустите из терминала или передайте --yes")
			}
			_, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			k, err := st.HostKeys().Get(cmd.Context(), host)
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("для %q нет закреплённого ключа (см. tgproxy hostkeys list)", host)
			} else if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if !yes {
				_, _ = fmt.Fprintf(w, "Хост %s: %s %s (закреплён %s)\nСбросить пин? Это снимет защиту от подмены хоста. [y/N]: ",
					k.Host, orDash(k.Algo), k.Fingerprint, k.CreatedAt.Local().Format(time.RFC3339))
				line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
					return errors.New("отменено: подтверждение не получено")
				}
			}
			if err := st.HostKeys().Delete(cmd.Context(), host); err != nil {
				return err
			}
			actor := "cli:" + cliUser()
			if _, err := st.Audit().Append(cmd.Context(), store.AuditEntry{
				At: time.Now(), Actor: actor, Action: auth.AuditHostKeyForget, Target: host, Detail: k.Fingerprint,
			}); err != nil {
				return fmt.Errorf("пин удалён, но запись аудита не сохранена: %w", err)
			}
			_, err = fmt.Fprintf(w, "Пин %s удалён. При следующей установке отпечаток нужно подтвердить заново.\n", host)
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().BoolVar(&yes, "yes", false, "не спрашивать подтверждение")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// stdinIsTerminal — переменная для подмены в тестах.
var stdinIsTerminal = func(in io.Reader) bool {
	f, ok := in.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) //nolint:gosec // fd влезает в int
}

func cliUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}
