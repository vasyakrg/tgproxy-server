package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/deployhelper"
)

// exitError — завершение с заданным кодом без дополнительного вывода.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// newDeployHelperCmd — привилегированный хелпер для tgproxy-deploy (запуск через sudo).
// Флаги не разбираются: хелпер сам валидирует позиционные аргументы.
func newDeployHelperCmd() *cobra.Command {
	return newDeployHelperCmdWith(func(cmd *cobra.Command) *deployhelper.Helper {
		return deployhelper.New(cmd.OutOrStdout(), cmd.ErrOrStderr())
	})
}

func newDeployHelperCmdWith(mk func(*cobra.Command) *deployhelper.Helper) *cobra.Command {
	return &cobra.Command{
		Use:                "deploy-helper",
		Short:              "Привилегированные операции установки агента (только root, через sudo)",
		Hidden:             true,
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if code := mk(cmd).Main(cmd.Context(), args); code != 0 {
				return exitError{code}
			}
			return nil
		},
	}
}

func exitCode(err error) (int, bool) {
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code, true
	}
	return 0, false
}
