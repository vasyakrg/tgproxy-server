package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/selfupdate"
)

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "update", Short: "Самообновление", Hidden: true}
	cmd.AddCommand(newUpdateApplyCmd())
	return cmd
}

func newUpdateApplyCmd() *cobra.Command {
	var dataDir, workDir, component, cfgPath, agentCfgPath string
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Применить подписанное обновление из updates/staged (только root, запускается tgproxy-update-{server,agent}.service)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ex := selfupdate.SystemExecutor{Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr()}
			v, err := newReleaseVerifier()
			if err != nil {
				return err
			}
			// Конфиг сервера читается лениво: на хосте агента server.yaml нет.
			healthURL := func() (string, error) {
				cfg, err := config.LoadServer(cfgPath)
				if err != nil {
					return "", fmt.Errorf("конфиг сервера: %w", err)
				}
				return selfupdate.HealthURL(cfg.Listen.Admin, cfg.TLS.Mode == config.TLSModeOff)
			}
			uid, gid, err := selfupdate.ServiceIDs()
			if err != nil {
				return fmt.Errorf("пользователь tgproxy: %w", err)
			}
			// Агент: /healthz на listen.metrics (loopback) из agent.yaml; нет конфига/адреса — только is-active и стабильность.
			agentURL := func() (string, error) {
				cfg, err := config.LoadAgent(agentCfgPath)
				if err != nil {
					return "", nil //nolint:nilerr // конфиг агента необязателен для проверки
				}
				return selfupdate.AgentHealthURL(cfg.Listen.Metrics), nil
			}
			a := selfupdate.New(selfupdate.Config{
				DataDir: dataDir, WorkDir: workDir, Component: component,
				Arch: runtime.GOARCH, CurrentVersion: buildinfo.Version,
				Verifier: v, Exec: ex, Probe: selfupdate.NewProbeConfig(selfupdate.ProbeConfig{ServerURL: healthURL, AgentURL: agentURL}, ex),
				AllowedUIDs: []uint32{0, uid}, ResultGID: gid, Log: cmd.ErrOrStderr(),
			})
			return a.Apply(cmd.Context())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", "/var/lib/tgproxy", "каталог данных")
	cmd.Flags().StringVar(&workDir, "work-dir", "/run/tgproxy-update", "root-only рабочий каталог")
	cmd.Flags().StringVar(&component, "component", "", "server|agent (по умолчанию из request)")
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/tgproxy/server.yaml", "конфиг сервера (адрес /healthz)")
	cmd.Flags().StringVar(&agentCfgPath, "agent-config", "/etc/tgproxy/agent.yaml", "конфиг агента (listen.metrics для /healthz)")
	return cmd
}
