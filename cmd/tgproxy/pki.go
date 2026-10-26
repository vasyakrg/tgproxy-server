package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

func newPKICmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pki", Short: "Сертификаты"}
	cmd.AddCommand(newPKIDevInitCmd())
	return cmd
}

func newPKIDevInitCmd() *cobra.Command {
	var out, agentID string
	cmd := &cobra.Command{
		Use:   "dev-init",
		Short: "Создать dev-PKI (CA, сертификаты сервера и агента); существующий CA не перезаписывается",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			err := pki.DevInit(out, []string{agentID})
			switch {
			case errors.Is(err, pki.ErrExists):
				_, werr := fmt.Fprintf(w, "dev PKI уже существует в %s, пропуск (удалите каталог для пересоздания)\n", out)
				return werr
			case err != nil:
				return err
			}
			_, err = fmt.Fprintf(w, "dev PKI создана в %s (агент %q)\n", out, agentID)
			return err
		},
	}
	cmd.Flags().StringVar(&out, "out", "dev/tls", "каталог для сертификатов")
	cmd.Flags().StringVar(&agentID, "agent", "local", "id агента")
	return cmd
}
