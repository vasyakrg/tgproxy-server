package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
)

func newHashpwCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hashpw",
		Short: "Хеш пароля argon2id (формат Authelia) для users_database.yml",
		Long: "Читает пароль из терминала (без эха, с подтверждением) или из stdin (одна строка)\n" +
			"и печатает PHC-строку argon2id с параметрами Authelia (m=65536,t=3,p=4).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pw, err := readPassword(cmd.InOrStdin(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			h, err := auth.Hash(pw, auth.DefaultHashParams())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), h)
			return err
		},
	}
}

// readPassword: на TTY — без эха и с повтором; иначе — первая строка stdin.
func readPassword(in io.Reader, prompt io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // fd влезает в int
		fd := int(f.Fd()) //nolint:gosec // fd влезает в int
		_, _ = fmt.Fprint(prompt, "Пароль: ")
		p1, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(prompt)
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprint(prompt, "Повторите: ")
		p2, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(prompt)
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			return "", errors.New("пароли не совпадают")
		}
		return nonEmpty(string(p1))
	}
	line, err := bufio.NewReader(io.LimitReader(in, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return nonEmpty(strings.TrimRight(line, "\r\n"))
}

func nonEmpty(p string) (string, error) {
	if p == "" {
		return "", errors.New("пустой пароль")
	}
	return p, nil
}
