package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/geoip"
	"github.com/vasyakrg/tgproxy-server/internal/server/ban"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func newBanCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ban", Short: "Баны IP (напрямую в БД; сервер подхватит за пару секунд)"}
	cmd.AddCommand(newBanAddCmd(), newBanListCmd(), newBanDeleteCmd())
	return cmd
}

// banService поднимает менеджер банов поверх БД (без фоновых задач) и сервис с аудитом.
func banService(cmd *cobra.Command, cfgPath string) (*api.BansService, store.Store, error) {
	cfg, st, err := openAdminStore(cmd, cfgPath)
	if err != nil {
		return nil, nil, err
	}
	m, err := ban.New(cmd.Context(), st.Bans(), ban.Options{Config: cfg.Ban, Protect: app.NewBanProtector(cfg, st, nil)})
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	return api.NewBansService(m, st.Audit(), nil, nil), st, nil
}

func cliActor() api.Actor {
	u := os.Getenv("SUDO_USER")
	if u == "" {
		u = os.Getenv("USER")
	}
	if u == "" {
		u = "unknown"
	}
	return api.Actor{User: "cli:" + u}
}

func newBanAddCmd() *cobra.Command {
	var (
		cfgPath, ip, duration, comment string
		permanent                      bool
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Забанить IP (IPv4 целиком, IPv6 — сетью /64) на срок или навсегда",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, st, err := banService(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			b, err := svc.Create(cmd.Context(), cliActor(), api.BanInput{IP: ip, Duration: duration, Permanent: permanent, Comment: comment})
			var ve *api.ValidationError
			if errors.As(err, &ve) {
				return errors.New(ve.Error())
			}
			if err != nil {
				return err
			}
			until := "навсегда"
			if b.ExpiresAt != nil {
				until = "до " + b.ExpiresAt.Local().Format("2006-01-02 15:04:05")
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "забанен %s %s (id=%d)\n", api.DisplayAddr(b.Prefix), until, b.ID)
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().StringVar(&ip, "ip", "", "IP-адрес")
	cmd.Flags().StringVar(&duration, "duration", "", "срок: 30m, 1h, 24h, 7d")
	cmd.Flags().BoolVar(&permanent, "permanent", false, "бессрочно")
	cmd.Flags().StringVar(&comment, "comment", "", "комментарий")
	_ = cmd.MarkFlagRequired("config")
	_ = cmd.MarkFlagRequired("ip")
	return cmd
}

func newBanListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Действующие баны",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			geo, _ := geoip.Open(cfg.GeoIP.File)
			defer func() { _ = geo.Close() }()
			list, err := st.Bans().ListActive(cmd.Context(), time.Now())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tIP\tCOUNTRY\tSOURCE\tBY\tUNTIL\tHITS\tLEVEL\tCOMMENT")
			for _, b := range list {
				until := "permanent"
				if b.ExpiresAt != nil {
					until = b.ExpiresAt.Local().Format("2006-01-02 15:04:05")
				}
				_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n", b.ID, api.DisplayAddr(b.Prefix),
					orDash(geo.Lookup(b.Prefix.Addr())), b.Source, orDash(b.Actor), until, b.Hits, b.Level, orDash(b.Comment))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newBanDeleteCmd() *cobra.Command {
	var (
		cfgPath, ip string
		id          int64
	)
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Снять бан по --id или --ip",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (id == 0) == (ip == "") {
				return errors.New("укажите ровно одно из --id или --ip")
			}
			svc, st, err := banService(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			if ip != "" {
				a, perr := api.ParseBanAddr(ip)
				if perr != nil {
					return fmt.Errorf("--ip: %w", perr)
				}
				p := ban.PrefixOf(a)
				b, gerr := st.Bans().GetByPrefix(cmd.Context(), p)
				if gerr != nil {
					return fmt.Errorf("бан %s не найден", p)
				}
				id = b.ID
			}
			b, err := svc.Delete(cmd.Context(), cliActor(), id)
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("бан id=%d не найден", id)
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "бан %s (id=%d) снят\n", api.DisplayAddr(b.Prefix), b.ID)
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().Int64Var(&id, "id", 0, "id бана")
	cmd.Flags().StringVar(&ip, "ip", "", "IP-адрес")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}
