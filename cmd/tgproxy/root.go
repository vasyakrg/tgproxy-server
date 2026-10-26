package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "tgproxy",
		Short:         "Telegram Bot API proxy: server и agent",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newServerCmd(),
		newAgentCmd(),
		newAccessCmd(),
		newAgentsCmd(),
		newConfigCmd(),
		newPKICmd(),
		newVersionCmd(),
	)
	return root
}

// signalContext возвращает контекст, отменяемый по SIGINT/SIGTERM.
func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
