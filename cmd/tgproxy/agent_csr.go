package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

// agentKeyOwner — системный пользователь агента: ключ, созданный от root,
// передаётся ему.
const agentKeyOwner = "tgproxy"

func newAgentCSRCmd() *cobra.Command {
	var keyPath, id, out string
	var force bool
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Создать ключ агента (P-256, 0600) и вывести CSR (первая установка)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !pki.ValidAgentID(id) {
				return fmt.Errorf("invalid --id %q", id)
			}
			key, err := agent.NewKeyFile(keyPath, force, agentKeyOwner)
			if err != nil {
				return err
			}
			csr, err := agent.BuildCSR(key, id)
			if err != nil {
				return err
			}
			if out == "" || out == "-" {
				_, err = cmd.OutOrStdout().Write(csr)
				return err
			}
			if err := os.WriteFile(out, csr, 0o644); err != nil { // #nosec G306 -- CSR не секрет
				return fmt.Errorf("write csr: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "путь к новому приватному ключу")
	cmd.Flags().StringVar(&id, "id", "", "agent_id")
	cmd.Flags().StringVar(&out, "out", "-", "куда писать CSR: - (stdout) или файл")
	cmd.Flags().BoolVar(&force, "force", false, "перезаписать существующий ключ")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}
