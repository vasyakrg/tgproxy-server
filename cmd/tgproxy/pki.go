package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func newPKICmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pki", Short: "Сертификаты"}
	cmd.AddCommand(newPKIDevInitCmd(), newPKIKEKInitCmd(), newPKIInitCmd(), newPKIFingerprintCmd(), newPKIDevAgentsCmd())
	return cmd
}

func newPKIDevInitCmd() *cobra.Command {
	var out string
	var agentIDs []string
	cmd := &cobra.Command{
		Use:   "dev-init",
		Short: "Создать dev-PKI (CA, сертификаты сервера и агента); существующий CA не перезаписывается",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			err := pki.DevInit(out, agentIDs)
			switch {
			case errors.Is(err, pki.ErrExists):
				_, werr := fmt.Fprintf(w, "dev PKI уже существует в %s, пропуск (удалите каталог для пересоздания)\n", out)
				return werr
			case err != nil:
				return err
			}
			_, err = fmt.Fprintf(w, "dev PKI создана в %s (агенты %v)\n", out, agentIDs)
			return err
		},
	}
	cmd.Flags().StringVar(&out, "out", "dev/tls", "каталог для сертификатов")
	cmd.Flags().StringSliceVar(&agentIDs, "agent", []string{"local"}, "id агентов (повторяемый или через запятую)")
	return cmd
}

func newPKIKEKInitCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "kek-init",
		Short: "Создать ключ шифрования секретов (KEK, 32 байта, 0400); существующий файл не перезаписывается",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			err := pki.GenerateKEK(out)
			switch {
			case errors.Is(err, pki.ErrKEKExists):
				_, werr := fmt.Fprintf(w, "KEK уже существует: %s, пропуск\n", out)
				return werr
			case err != nil:
				return err
			}
			_, err = fmt.Fprintf(w, "KEK создан: %s (0400)\n", out)
			return err
		},
	}
	cmd.Flags().StringVar(&out, "out", "/etc/tgproxy/kek", "путь к файлу KEK")
	return cmd
}

// loadAuthority открывает БД и KEK из конфига сервера и загружает (init=true —
// создаёт при отсутствии) CA.
func loadAuthority(ctx context.Context, cfgPath string, init bool) (a *pki.Authority, created bool, err error) {
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return nil, false, err
	}
	if cfg.PKI.KEKFile == "" {
		return nil, false, errors.New("pki.kek_file не задан в конфиге (создать: tgproxy pki kek-init)")
	}
	kek, err := pki.LoadKEK(cfg.PKI.KEKFile)
	if err != nil {
		return nil, false, fmt.Errorf("загрузка KEK (создать: tgproxy pki kek-init --out %s): %w", cfg.PKI.KEKFile, err)
	}
	st, err := app.OpenSQLite(ctx, cfg)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = st.Close() }()
	if !init {
		if _, err := st.Certs().LoadCA(ctx); errors.Is(err, store.ErrNotFound) {
			return nil, false, errors.New("CA не инициализирован (выполните: tgproxy pki init)")
		} else if err != nil {
			return nil, false, err
		}
	} else if _, err := st.Certs().LoadCA(ctx); errors.Is(err, store.ErrNotFound) {
		created = true
	}
	a, err = pki.LoadOrInit(ctx, st.Certs(), kek, pki.Options{})
	return a, created, err
}

func newPKIInitCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Инициализировать CA сервера в БД (ключ CA шифруется KEK); существующий CA не перезаписывается",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, created, err := loadAuthority(cmd.Context(), cfgPath, true)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			state := "уже существует"
			if created {
				state = "создан"
			}
			_, err = fmt.Fprintf(w, "CA %s\nОтпечаток CA: %s\n", state, a.CAFingerprint())
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newPKIFingerprintCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Показать SHA-256 отпечаток CA (для tgproxy agent enroll --ca-fingerprint)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, _, err := loadAuthority(cmd.Context(), cfgPath, false)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), a.CAFingerprint())
			return err
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// devAgentRenewBefore — сертификат dev-агента перевыпускается, если до конца срока меньше.
const devAgentRenewBefore = 24 * time.Hour

func newPKIDevAgentsCmd() *cobra.Command {
	var cfgPath, out string
	var agentIDs []string
	cmd := &cobra.Command{
		Use:   "dev-agents",
		Short: "Выпустить из CA сервера (БД) сертификаты dev-агентов в каталог (идемпотентно; только dev)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPKIDevAgents(cmd, cfgPath, out, agentIDs)
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	cmd.Flags().StringVar(&out, "out", "dev/tls", "каталог для ca.crt и agent-<id>.crt/.key")
	cmd.Flags().StringSliceVar(&agentIDs, "agent", []string{"local"}, "id агентов (повторяемый или через запятую)")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func runPKIDevAgents(cmd *cobra.Command, cfgPath, out string, agentIDs []string) error {
	ctx := cmd.Context()
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return err
	}
	if cfg.PKI.KEKFile == "" {
		return errors.New("pki.kek_file не задан в конфиге (создать: tgproxy pki kek-init)")
	}
	kek, err := pki.LoadKEK(cfg.PKI.KEKFile)
	if err != nil {
		return fmt.Errorf("загрузка KEK: %w", err)
	}
	st, err := app.OpenSQLite(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	auth, err := pki.LoadOrInit(ctx, st.Certs(), kek, pki.Options{})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, pki.FileCACert), auth.CertPEM(), 0o644); err != nil { // #nosec G306 -- CA публичный
		return err
	}
	w := cmd.OutOrStdout()
	for i, id := range agentIDs {
		if !pki.ValidAgentID(id) {
			return fmt.Errorf("недопустимый id агента %q", id)
		}
		crtPath, keyPath := filepath.Join(out, pki.AgentCertFile(id)), filepath.Join(out, pki.AgentKeyFile(id))
		if devAgentFresh(auth.Pool(), crtPath, keyPath) {
			_, _ = fmt.Fprintf(w, "агент %s: сертификат действует, пропуск\n", id)
		} else if err := issueDevAgent(ctx, auth, id, crtPath, keyPath); err != nil {
			return err
		} else {
			_, _ = fmt.Fprintf(w, "агент %s: сертификат выпущен\n", id)
		}
		if i == 0 { // совместимость: agent.crt/agent.key — первый агент
			if err := copyFile(crtPath, filepath.Join(out, pki.FileAgentCert), 0o644); err != nil {
				return err
			}
			if err := copyFile(keyPath, filepath.Join(out, pki.FileAgentKey), 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func issueDevAgent(ctx context.Context, auth *pki.Authority, id, crtPath, keyPath string) error {
	csr, key, err := pki.NewAgentCSR(id)
	if err != nil {
		return err
	}
	crt, _, err := auth.SignAgentCSR(ctx, csr, id, 0)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return err
	}
	return os.WriteFile(crtPath, crt, 0o644) // #nosec G306 -- сертификат публичный
}

// devAgentFresh: пара ключ+сертификат есть, выдана текущим CA и действует ещё devAgentRenewBefore.
func devAgentFresh(roots *x509.CertPool, crtPath, keyPath string) bool {
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	data, err := os.ReadFile(crtPath) // #nosec G304 -- путь dev-каталога
	if err != nil {
		return false
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || time.Until(c.NotAfter) <= devAgentRenewBefore {
		return false
	}
	_, err = c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src) // #nosec G304 -- путь dev-каталога
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode) // #nosec G703 -- dev-каталог из флага --out
}
