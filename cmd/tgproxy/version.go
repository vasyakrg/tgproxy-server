package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Показать версию сборки",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"tgproxy %s\ncommit: %s\ndate: %s\ngo: %s\nplatform: %s/%s\n",
				buildinfo.Version, buildinfo.Commit, buildinfo.Date,
				runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return err
		},
	}
}
