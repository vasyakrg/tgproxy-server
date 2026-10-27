package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/mtproto/link"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/probe"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const errNeedKEK = "для секретов MTProto нужен pki.kek_file (создать: tgproxy pki kek-init)"

func newMTProtoCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "mtproto", Short: "MTProto-прокси для клиентов Telegram"}
	secret := &cobra.Command{Use: "secret", Short: "Секреты MTProto (напрямую в БД; действия пишутся в аудит)"}
	secret.AddCommand(newMTSecretAddCmd(), newMTSecretListCmd(), newMTSecretDeleteCmd(), newMTSecretPurgeCmd(), newMTSecretRotateCmd(), newMTSecretLinkCmd())
	cmd.AddCommand(secret, newMTProbeCmd())
	return cmd
}

// mtService поднимает сервис секретов поверх БД и KEK из конфига.
func mtService(cmd *cobra.Command, cfgPath string) (*api.MTProtoService, store.Store, error) {
	cfg, st, err := openAdminStore(cmd, cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if cfg.PKI.KEKFile == "" {
		_ = st.Close()
		return nil, nil, errors.New(errNeedKEK)
	}
	kek, err := pki.LoadKEK(cfg.PKI.KEKFile)
	if err != nil {
		_ = st.Close()
		return nil, nil, fmt.Errorf("загрузка KEK: %w", err)
	}
	ep := api.ResolveMTProtoEndpoint(cfg.MTProto, cfg.Server.PublicBaseURL, cfg.Listen.Proxy)
	return api.NewMTProtoService(st.MTProtoSecrets(), st.Audit(), kek, func() api.MTProtoEndpoint { return ep }, nil, nil), st, nil
}

// mtResolve находит секрет по числовому id или имени (действующие приоритетнее отозванных).
func mtResolve(ctx context.Context, svc *api.MTProtoService, ref string) (store.MTProtoSecret, error) {
	list, err := svc.List(ctx)
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	id, idErr := strconv.ParseInt(ref, 10, 64)
	var byName *store.MTProtoSecret
	for i, s := range list {
		if idErr == nil && s.ID == id {
			return s, nil
		}
		if s.Name == ref && (byName == nil || byName.RevokedAt != nil) {
			byName = &list[i]
		}
	}
	if byName != nil {
		return *byName, nil
	}
	return store.MTProtoSecret{}, fmt.Errorf("секрет %q не найден", ref)
}

func mtErr(err error) error {
	var ve *api.ValidationError
	if errors.As(err, &ve) {
		return errors.New(ve.Error())
	}
	return err
}

func printLinks(cmd *cobra.Command, l api.MTProtoLinks, linkErr error) error {
	w := cmd.OutOrStdout()
	if linkErr != nil {
		_, err := fmt.Fprintf(w, "ссылка недоступна: %v (задайте mtproto.public_host и mtproto.fronting_domain)\n", linkErr)
		return err
	}
	_, err := fmt.Fprintf(w, "%s\n%s\n", l.TG, l.HTTPS)
	return err
}

func newMTSecretAddCmd() *cobra.Command {
	var (
		cfgPath, name string
		cidrs         []string
		maxConns      int
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Создать секрет MTProto (ссылка печатается один раз)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, st, err := mtService(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			res, err := svc.Create(cmd.Context(), cliActor(), api.MTProtoCreateInput{Name: name, CIDRs: cidrs, MaxConns: maxConns})
			if err != nil {
				return mtErr(err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "секрет %q создан (id=%d). Ссылка показывается ОДИН раз:\n", res.Secret.Name, res.Secret.ID)
			return printLinks(cmd, res.Links, res.LinkErr)
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().StringVar(&name, "name", "", "имя секрета")
	cmd.Flags().StringArrayVar(&cidrs, "cidr", nil, "разрешённая сеть (повторяемый флаг)")
	cmd.Flags().IntVar(&maxConns, "max-conns", 0, "лимит соединений (0 — без лимита)")
	_ = cmd.MarkFlagRequired("config")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func mtStatus(s store.MTProtoSecret, now time.Time) string {
	switch {
	case s.RevokedAt != nil && s.Active(now):
		return "grace"
	case s.RevokedAt != nil:
		return "revoked"
	case !s.Enabled:
		return "disabled"
	}
	return "active"
}

func newMTSecretListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Список секретов (ключи не показываются, только префикс)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			list, err := st.MTProtoSecrets().List(cmd.Context())
			if err != nil {
				return err
			}
			now := time.Now()
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tNAME\tPREFIX\tSTATUS\tCIDRS\tMAX_CONNS")
			for _, s := range list {
				nets := make([]string, len(s.CIDRs))
				for i, c := range s.CIDRs {
					nets[i] = c.String()
				}
				_, _ = fmt.Fprintf(tw, "%d\t%s\t%s…\t%s\t%s\t%d\n", s.ID, s.Name, s.Prefix, mtStatus(s, now), orDash(strings.Join(nets, ",")), s.MaxConns)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newMTSecretDeleteCmd() *cobra.Command {
	var (
		cfgPath string
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "delete <id|name>",
		Short: "Отозвать секрет немедленно",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, st, err := mtService(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			s, err := mtResolve(cmd.Context(), svc, args[0])
			if err != nil {
				return err
			}
			if !yes && !confirm(cmd, fmt.Sprintf("Отозвать секрет %q (id=%d)? Клиенты потеряют доступ. [y/N] ", s.Name, s.ID)) {
				return errors.New("отменено (используйте --yes)")
			}
			if _, err := svc.Revoke(cmd.Context(), cliActor(), s.ID); err != nil {
				return mtErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "секрет %q (id=%d) отозван\n", s.Name, s.ID)
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().BoolVar(&yes, "yes", false, "без подтверждения")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newMTSecretPurgeCmd() *cobra.Command {
	var (
		cfgPath    string
		yes, allRv bool
	)
	cmd := &cobra.Command{
		Use:   "purge <id|name> | --all-revoked",
		Short: "Удалить отозванный секрет окончательно (активный — отказ: сначала delete)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if allRv == (len(args) == 1) {
				return errors.New("укажите либо <id|name>, либо --all-revoked")
			}
			svc, st, err := mtService(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			if allRv {
				list, err := svc.List(cmd.Context())
				if err != nil {
					return err
				}
				now, n := time.Now(), 0
				for _, s := range list {
					if api.MTProtoPurgeable(s, now) {
						n++
					}
				}
				if n == 0 {
					_, err = fmt.Fprintln(cmd.OutOrStdout(), "отозванных секретов для удаления нет")
					return err
				}
				if !yes && !confirm(cmd, fmt.Sprintf("Удалить окончательно отозванные секреты: %d? Действие необратимо. [y/N] ", n)) {
					return errors.New("отменено (используйте --yes)")
				}
				done, err := svc.PurgeRevoked(cmd.Context(), cliActor())
				if err != nil {
					return mtErr(err)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "удалено отозванных секретов: %d\n", done)
				return err
			}
			s, err := mtResolve(cmd.Context(), svc, args[0])
			if err != nil {
				return err
			}
			if !api.MTProtoPurgeable(s, time.Now()) {
				return fmt.Errorf("секрет %q (id=%d) ещё действует: сначала отзовите его (mtproto secret delete) и дождитесь конца grace", s.Name, s.ID)
			}
			if !yes && !confirm(cmd, fmt.Sprintf("Удалить секрет %q (id=%d) окончательно? Действие необратимо. [y/N] ", s.Name, s.ID)) {
				return errors.New("отменено (используйте --yes)")
			}
			if _, err := svc.Purge(cmd.Context(), cliActor(), s.ID); err != nil {
				if errors.Is(err, api.ErrMTProtoActive) {
					return fmt.Errorf("секрет %q (id=%d) ещё действует: сначала отзовите его", s.Name, s.ID)
				}
				return mtErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "секрет %q (id=%d) удалён\n", s.Name, s.ID)
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().BoolVar(&yes, "yes", false, "без подтверждения")
	cmd.Flags().BoolVar(&allRv, "all-revoked", false, "удалить все отозванные секреты с истёкшим grace")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func confirm(cmd *cobra.Command, prompt string) bool {
	_, _ = fmt.Fprint(cmd.ErrOrStderr(), prompt)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes" || a == "д" || a == "да"
}

func newMTSecretRotateCmd() *cobra.Command {
	var (
		cfgPath string
		grace   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "rotate <id|name>",
		Short: "Заменить ключ секрета; старый действует ещё --grace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, st, err := mtService(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			s, err := mtResolve(cmd.Context(), svc, args[0])
			if err != nil {
				return err
			}
			res, err := svc.Rotate(cmd.Context(), cliActor(), s.ID, grace)
			if err != nil {
				return mtErr(err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "секрет %q ротирован (новый id=%d, старый действует ещё %s). Ссылка показывается ОДИН раз:\n", s.Name, res.Secret.ID, grace)
			return printLinks(cmd, res.Links, res.LinkErr)
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().DurationVar(&grace, "grace", 0, "сколько ещё принимать старый ключ (например 1h)")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newMTSecretLinkCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "link <id|name>",
		Short: "Показать ссылку подключения (пишется в аудит как reveal)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, st, err := mtService(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			s, err := mtResolve(cmd.Context(), svc, args[0])
			if err != nil {
				return err
			}
			l, err := svc.Reveal(cmd.Context(), cliActor(), s.ID)
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("секрет %q отозван", s.Name)
			}
			if err != nil {
				return mtErr(err)
			}
			return printLinks(cmd, l, nil)
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newMTProbeCmd() *cobra.Command {
	var (
		linkArg   string
		fromStdin bool
		dc        int
		timeout   time.Duration
		hsOnly    bool
	)
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Проверить MTProto-прокси: FakeTLS + resPQ от DC (код возврата 0 — успех)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw := linkArg
			if fromStdin {
				if raw != "" {
					return errors.New("укажите одно из --link или --link-stdin")
				}
				b, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 4096))
				if err != nil {
					return errors.New("не удалось прочитать ссылку из stdin")
				}
				raw = strings.TrimSpace(string(b))
			}
			if raw == "" {
				return errors.New("нужна --link или --link-stdin")
			}
			// Ошибки разбора и пробы не содержат ссылку/ключ: печатаем только хост и порт.
			host, port, key, domain, err := link.Parse(raw)
			if err != nil {
				return errors.New("некорректная ссылка MTProto (нужна FakeTLS-ссылка вида ee-секрета)")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			if hsOnly {
				// Только FakeTLS (ServerHello с верным HMAC): DC и агенты не нужны — для smoke без сети к Telegram.
				c, derr := probe.Dial(ctx, addr, key, domain, dc)
				if derr != nil {
					return fmt.Errorf("проба %s не прошла: %w", addr, redact(derr, raw, key[:]))
				}
				_ = c.Close()
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "OK %s: FakeTLS-рукопожатие пройдено (DC не проверялся)\n", addr)
				return err
			}
			res, err := probe.RunDC(ctx, addr, key, domain, dc)
			if err != nil {
				return fmt.Errorf("проба %s не прошла: %w", addr, redact(err, raw, key[:]))
			}
			if !res.DCResponded {
				return fmt.Errorf("проба %s: DC не ответил resPQ", addr)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "OK %s: resPQ от DC%d за %s\n", addr, dc, res.RTT.Round(time.Millisecond))
			return err
		},
	}
	cmd.Flags().StringVar(&linkArg, "link", "", "ссылка tg://proxy?... (лучше --link-stdin: аргументы видны в ps)")
	cmd.Flags().BoolVar(&fromStdin, "link-stdin", false, "читать ссылку из stdin")
	cmd.Flags().IntVar(&dc, "dc", probe.DefaultDC, "номер DC")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "общий таймаут пробы")
	cmd.Flags().BoolVar(&hsOnly, "handshake-only", false, "только FakeTLS-рукопожатие, без обмена с DC (код 0 — ServerHello верен)")
	return cmd
}

// redact убирает из текста ошибки ссылку и hex ключа (на случай, если нижний слой их процитирует).
func redact(err error, raw string, key []byte) error {
	msg := err.Error()
	for _, s := range []string{raw, fmt.Sprintf("%x", key)} {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return errors.New(msg)
}
