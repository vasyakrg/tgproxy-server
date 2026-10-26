package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// openAdminStore загружает конфиг сервера и открывает его БД (можно при
// запущенном сервере: SQLite в WAL, сервер увидит изменения по Version).
func openAdminStore(cmd *cobra.Command, cfgPath string) (*config.ServerConfig, store.Store, error) {
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	st, err := app.OpenSQLite(cmd.Context(), cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, st, nil
}

func newAccessCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "access", Short: "Правила доступа (напрямую в БД)"}
	cmd.AddCommand(newAccessAddCmd(), newAccessListCmd(), newAccessDeleteCmd())
	return cmd
}

func newAccessAddCmd() *cobra.Command {
	var (
		cfgPath, name string
		cidrs         []string
		withKey       bool
		rps           float64
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Добавить правило доступа (сети и/или скрытый ключ)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			res, err := app.AccessAdd(cmd.Context(), st.AccessRules(), app.AccessAddParams{
				Name: name, CIDRs: cidrs, WithKey: withKey, RPS: rps,
			})
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(w, "правило %q создано (id=%d)\n", res.Rule.Name, res.Rule.ID)
			if res.Key == "" {
				return nil
			}
			scheme := "http"
			if cfg.TLS.Mode != config.TLSModeOff && cfg.TLS.Mode != "" {
				scheme = "https"
			}
			_, err = fmt.Fprintf(w, "ключ (показывается ОДИН раз, сохраните): %s\nbase URL: %s://%s/k/%s/bot<TOKEN>/<method>\n",
				res.Key, scheme, cfg.Listen.Proxy, res.Key)
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().StringVar(&name, "name", "", "имя правила")
	cmd.Flags().StringArrayVar(&cidrs, "cidr", nil, "сеть (повторяемый флаг)")
	cmd.Flags().BoolVar(&withKey, "with-key", false, "сгенерировать скрытый ключ")
	cmd.Flags().Float64Var(&rps, "rps", 0, "лимит запросов в секунду (0 — без лимита)")
	_ = cmd.MarkFlagRequired("config")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newAccessListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Список правил доступа (ключи не показываются, только префикс)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			rules, err := st.AccessRules().List(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tNAME\tCIDRS\tKEY\tRPS\tENABLED")
			for _, r := range rules {
				nets := make([]string, len(r.CIDRs))
				for i, c := range r.CIDRs {
					nets[i] = c.String()
				}
				key := "-"
				switch {
				case r.KeyPrefix != "":
					key = r.KeyPrefix + "…"
				case len(r.KeyHash) > 0:
					key = "(hash)" // правило из конфига: префикс не хранится
				}
				enabled := r.Enabled && r.RevokedAt == nil
				_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%g\t%t\n", r.ID, r.Name, orDash(strings.Join(nets, ",")), key, r.RPS, enabled)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newAccessDeleteCmd() *cobra.Command {
	var (
		cfgPath, name string
		id            int64
	)
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Удалить правило доступа по --name или --id",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			r, err := app.AccessDelete(cmd.Context(), st.AccessRules(), id, name)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "правило %q (id=%d) удалено\n", r.Name, r.ID)
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().StringVar(&name, "name", "", "имя правила")
	cmd.Flags().Int64Var(&id, "id", 0, "id правила")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
