package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

func newPKICmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pki", Short: "Сертификаты"}
	cmd.AddCommand(newPKIDevInitCmd(), newPKIKEKInitCmd())
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
