package main

import (
	"errors"

	"github.com/spf13/cobra"
)

var errNotImplemented = errors.New("not implemented")

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "tgproxy",
		Short:         "Telegram Bot API proxy: server и agent",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newStubCmd("server", "Запустить сервер (реализуется в M1)"),
		newStubCmd("agent", "Запустить агент (реализуется в M1)"),
		newVersionCmd(),
	)
	return root
}

func newStubCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(*cobra.Command, []string) error {
			return errNotImplemented
		},
	}
}
