package main

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/enroll"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func newAgentsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agents", Short: "Реестр агентов (напрямую из БД)"}
	var cfgPath string
	list := &cobra.Command{
		Use:   "list",
		Short: "Список агентов из БД (состояние up/down — только у запущенного сервера, см. логи)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			list, err := st.Agents().List(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tMODE\tURL\tWEIGHT\tDRAINING")
			for _, a := range list {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%t\n", a.ID, a.Mode, orDash(a.URL), a.Weight, a.Draining)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = list.MarkFlagRequired("config")
	cmd.AddCommand(list, newAgentsEnrollTokenCmd())
	return cmd
}

func newAgentsEnrollTokenCmd() *cobra.Command {
	var (
		cfgPath, name, gatewayURL string
		ttl                       time.Duration
		weight                    int
		installed                 bool
		list                      bool
		revoke                    string
	)
	cmd := &cobra.Command{
		Use:   "enroll-token",
		Short: "Выпустить одноразовый токен подключения агента за NAT и вывести команду для агента",
		Long: "То же, что кнопка «Агент за NAT» в UI. Токен показывается один раз; в БД хранится только SHA-256.\n" +
			"Требуется инициализированный CA (tgproxy pki init). Основная команда ставит пакет с самого сервера (нужен подписанный релиз\n" +
			"версии сервера в кэше загрузок, иначе токен не выдаётся) и подключает агента; --installed — только подключение.\n" +
			"--list показывает неиспользованные токены, --revoke <id|имя> отзывает токен (после отзыва /enroll отвечает 401).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if list || revoke != "" {
				if list && revoke != "" {
					return errors.New("--list и --revoke взаимоисключающие")
				}
				if name != "" || installed || weight != 0 || ttl != 0 {
					return errors.New("--list/--revoke не сочетаются с параметрами выпуска токена")
				}
				return enrollTokenAdmin(cmd, cfgPath, list, revoke)
			}
			if name == "" {
				return errors.New("укажите --name (или --list / --revoke)")
			}
			cfg, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			if cfg.PKI.KEKFile == "" {
				return errors.New("pki.kek_file не задан в конфиге (создать: tgproxy pki kek-init)")
			}
			kek, err := pki.LoadKEK(cfg.PKI.KEKFile)
			if err != nil {
				return fmt.Errorf("загрузка KEK: %w", err)
			}
			if _, err := st.Certs().LoadCA(cmd.Context()); errors.Is(err, store.ErrNotFound) {
				return errors.New("CA не инициализирован (выполните: tgproxy pki init)")
			} else if err != nil {
				return err
			}
			auth, err := pki.LoadOrInit(cmd.Context(), st.Certs(), kek, pki.Options{})
			if err != nil {
				return err
			}
			url, ok := app.GatewayURL(cfg, gatewayURL)
			if !ok {
				return errors.New("не удалось определить публичный URL agent_gateway: задайте --gateway-url или server.public_base_url")
			}
			pkgs, err := app.EnrollPackages(cfg)
			if err != nil {
				return err
			}
			svc, err := enroll.New(enroll.Config{
				Enrollments: st.Enrollments(), Agents: st.Agents(), Audit: st.Audit(), CA: auth, GatewayURL: url,
				Packages: pkgs,
			})
			if err != nil {
				return err
			}
			is, err := svc.IssueFor(cmd.Context(), enroll.IssueRequest{
				Name: name, Weight: weight, CreatedBy: "cli", TTL: ttl, InstalledOnly: installed,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if installed {
				_, err = fmt.Fprintf(out, "Токен действует до %s и показывается один раз. Команда для агента (tgproxy уже установлен):\n%s\n",
					is.ExpiresAt.Local().Format(time.RFC3339), is.CmdlineInstalled)
				return err
			}
			_, err = fmt.Fprintf(out, "Токен действует до %s и показывается один раз.\n\nКоманда для чистого хоста (скачает пакет с сервера, установит и подключит агента):\n%s\n\nЕсли tgproxy уже установлен на хосте:\n%s\n",
				is.ExpiresAt.Local().Format(time.RFC3339), is.Cmdline, is.CmdlineInstalled)
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().StringVar(&name, "name", "", "имя агента (из него строится id)")
	cmd.Flags().IntVar(&weight, "weight", 0, "вес в балансировке (0 — по умолчанию)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "срок токена (по умолчанию 1h, максимум 24h)")
	cmd.Flags().BoolVar(&installed, "installed", false, "tgproxy уже установлен на хосте: вывести только команду подключения (без установки пакета)")
	cmd.Flags().StringVar(&gatewayURL, "gateway-url", "", "публичный https-URL agent_gateway (по умолчанию из конфига)")
	cmd.Flags().BoolVar(&list, "list", false, "показать неиспользованные и непросроченные токены (без самих токенов)")
	cmd.Flags().StringVar(&revoke, "revoke", "", "отозвать неиспользованный токен по id или имени агента")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// enrollTokenAdmin — список и отзыв токенов подключения (только БД; CA и пакеты не нужны).
func enrollTokenAdmin(cmd *cobra.Command, cfgPath string, list bool, revoke string) error {
	_, st, err := openAdminStore(cmd, cfgPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	svc := api.NewEnrollService(api.EnrollConfig{Enrollments: st.Enrollments(), Audit: st.Audit()})
	items, err := svc.List(cmd.Context())
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if list {
		if len(items) == 0 {
			_, err = fmt.Fprintln(out, "ожидающих токенов нет")
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ID\tNAME\tWEIGHT\tCREATED_BY\tCREATED\tEXPIRES")
		for _, e := range items {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n", e.ID, e.Name, e.Weight, orDash(e.CreatedBy),
				e.CreatedAt.Local().Format("2006-01-02 15:04"), e.ExpiresAt.Local().Format("2006-01-02 15:04"))
		}
		return tw.Flush()
	}
	var match []api.EnrollmentItem
	for _, e := range items {
		if e.ID == revoke {
			match = []api.EnrollmentItem{e}
			break
		}
		if e.Name == revoke {
			match = append(match, e)
		}
	}
	switch len(match) {
	case 0:
		return fmt.Errorf("токен %q не найден среди ожидающих (уже использован, истёк или отозван)", revoke)
	case 1:
	default:
		ids := make([]string, 0, len(match))
		for _, e := range match {
			ids = append(ids, e.ID)
		}
		return fmt.Errorf("имя %q есть у нескольких токенов, укажите id: %s", revoke, strings.Join(ids, ", "))
	}
	if err := svc.Revoke(cmd.Context(), cliActor(), match[0].ID, true); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "токен %s (%s) отозван\n", match[0].ID, match[0].Name)
	return err
}
