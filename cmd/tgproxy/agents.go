package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newAgentsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agents", Short: "Реестр агентов (напрямую из БД)"}
	var cfgPath string
	list := &cobra.Command{
		Use:   "list",
		Short: "Список агентов из БД (состояние up/down — только у запущенного сервера, см. логи)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, err := openAdminStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			list, err := st.Agents().List(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tMODE\tURL\tWEIGHT\tDRAINING")
			for _, a := range list {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%t\n", a.ID, a.Mode, orDash(a.URL), a.Weight, a.Draining)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVarP(&cfgPath, "config", "c", "", "путь к server.yaml")
	_ = list.MarkFlagRequired("config")
	cmd.AddCommand(list)
	return cmd
}
