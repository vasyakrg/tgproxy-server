package selfupdate

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"strconv"
)

// Фиксированные пути команд.
const (
	dpkgPath      = "/usr/bin/dpkg"
	systemctlPath = "/usr/bin/systemctl"
)

// SystemExecutor запускает dpkg и systemctl по абсолютным путям с чистым окружением.
type SystemExecutor struct{ Stdout, Stderr io.Writer }

// Run реализует Executor; допустимы только dpkg и systemctl.
func (e SystemExecutor) Run(ctx context.Context, name string, args ...string) error {
	var path string
	switch name {
	case "dpkg":
		path = dpkgPath
	case "systemctl":
		path = systemctlPath
	default:
		return fmt.Errorf("команда %q не разрешена", name)
	}
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- path — константа, args строит Applier
	cmd.Stdout, cmd.Stderr = e.Stdout, e.Stderr
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	return cmd.Run()
}

// Output запускает systemctl и возвращает stdout (OutputExecutor).
func (e SystemExecutor) Output(ctx context.Context, name string, args ...string) (string, error) {
	if name != "systemctl" {
		return "", fmt.Errorf("команда %q не разрешена", name)
	}
	cmd := exec.CommandContext(ctx, systemctlPath, args...) // #nosec G204 -- путь — константа, args строит Applier
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	b, err := cmd.Output()
	return string(b), err
}

// ServiceIDs возвращает uid/gid системного пользователя tgproxy.
func ServiceIDs() (uid uint32, gid int, err error) {
	u, err := user.Lookup("tgproxy")
	if err != nil {
		return 0, -1, err
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, -1, err
	}
	g, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, -1, err
	}
	return uint32(id), g, nil
}
