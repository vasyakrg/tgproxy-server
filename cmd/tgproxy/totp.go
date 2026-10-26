package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
)

// loadSealer — точка подключения KEK; по умолчанию pki.LoadKEK (подменяется в тестах).
var loadSealer = func(path string) (auth.Sealer, error) {
	k, err := pki.LoadKEK(path)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func newTOTPCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "totp", Short: "TOTP администраторов"}
	cmd.AddCommand(newTOTPEnrollCmd())
	return cmd
}

func newTOTPEnrollCmd() *cobra.Command {
	var usersFile, kekFile, issuer string
	var noQR bool
	cmd := &cobra.Command{
		Use:   "enroll <user>",
		Short: "Сгенерировать TOTP-секрет: otpauth URI, QR и строка totp_secret_enc",
		Long: "Генерирует секрет, шифрует его KEK (AAD = \"totp:<user>\") и печатает значение totp_secret_enc\n" +
			"для вставки в users-файл. Сам файл не изменяется (он может управляться конфиг-менеджментом).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			user := args[0]
			if usersFile == "" || kekFile == "" {
				return errors.New("нужны --users-file и --kek-file")
			}
			users, err := auth.LoadUsers(usersFile, nil)
			if err != nil {
				return err
			}
			if _, ok := users.Get(user); !ok {
				return fmt.Errorf("пользователь %q не найден в %s", user, usersFile)
			}
			sealer, err := loadSealer(kekFile)
			if err != nil {
				return fmt.Errorf("KEK: %w", err)
			}
			enr, err := auth.NewTOTP(sealer, nil, issuer).Enroll(user)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(w, "otpauth URI:\n%s\n\n", enr.URI)
			if !noQR {
				qr, err := enr.QR()
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(w, "%s\n", qr)
			}
			_, err = fmt.Fprintf(w, "Добавьте пользователю %q в %s:\n  totp_secret_enc: '%s'\n", user, usersFile, enr.Sealed)
			return err
		},
	}
	cmd.Flags().StringVar(&usersFile, "users-file", "/etc/tgproxy/users_database.yml", "users_database.yml")
	cmd.Flags().StringVar(&kekFile, "kek-file", "/etc/tgproxy/kek", "файл KEK")
	cmd.Flags().StringVar(&issuer, "issuer", "tgproxy", "issuer в otpauth URI")
	cmd.Flags().BoolVar(&noQR, "no-qr", false, "не рисовать QR-код")
	return cmd
}
