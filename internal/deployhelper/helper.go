// Package deployhelper — привилегированный хелпер `tgproxy deploy-helper`
// (architecture §8). Пользователь tgproxy-deploy может через sudo запускать
// только его, а хелпер сам разбирает и жёстко валидирует ввод: ни оболочки, ни
// передачи аргументов дальше, пути строятся здесь по версии и архитектуре dpkg.
//
// Глаголы:
//
//	install <version>            dpkg -i /var/lib/tgproxy/packages/tgproxy_<v>_<arch>.deb после проверки файла и подписи
//	stage <tmpfile> <version>    перенос deb из каталога incoming в packages (sha256 по <tmpfile>.sha256)
//	unit start|stop|restart|status|is-active|enable|disable   только tgproxy-agent (enable/disable = с --now)
//
// Коды выхода: 0 — успех, 1 — ошибка выполнения, 2 — недопустимый ввод.
package deployhelper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Фиксированные пути.
const (
	DefaultPackagesDir = "/var/lib/tgproxy/packages"
	// DefaultIncomingDir лежит вне /var/lib/tgproxy (0750 tgproxy:tgproxy), чтобы
	// пользователь tgproxy-deploy мог в него дойти; родитель /var/lib принадлежит root.
	DefaultIncomingDir = "/var/lib/tgproxy-incoming"
	agentUnit          = "tgproxy-agent"
	dpkgPath           = "/usr/bin/dpkg"
	systemctlPath      = "/usr/bin/systemctl"
	maxDebSize         = 512 << 20
)

var (
	versionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
	archRe    = regexp.MustCompile(`^[a-z0-9]{2,16}$`)
	baseRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// ExitUsage — недопустимый ввод.
const ExitUsage = 2

// usageError — ошибка ввода (код 2).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// Verifier проверяет подлинность deb перед установкой. f открыт на чтение.
//
// TODO(M6): заменить на проверку minisign-подписи (docs/plan.md, M6-T2/M6-T4);
// пока целостность проверяет только sha256 из <deb>.sha256, что не защищает от
// подмены пары файлов. Пропуска проверки («no-op») нет и быть не должно.
type Verifier interface {
	Verify(path string, f *os.File) error
}

// Runner запускает фиксированную внешнюю команду; вывод идёт в stdout/stderr хелпера.
type Runner func(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) error

// Helper — зависимости, подменяемые в тестах.
type Helper struct {
	PackagesDir string
	IncomingDir string
	Verifier    Verifier
	Run         Runner
	EUID        func() int
	// Owner возвращает uid владельца файла.
	Owner  func(os.FileInfo) (uint32, bool)
	Stdout io.Writer
	Stderr io.Writer
}

// New возвращает хелпер с боевыми путями и проверкой sha256.
func New(stdout, stderr io.Writer) *Helper {
	h := &Helper{
		PackagesDir: DefaultPackagesDir, IncomingDir: DefaultIncomingDir,
		Run: execRun, EUID: os.Geteuid, Owner: fileOwner, Stdout: stdout, Stderr: stderr,
	}
	h.Verifier = SHA256Verifier{Owner: h.Owner}
	return h
}

func execRun(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- name — константа пакета, args построены хелпером
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	return cmd.Run()
}

// Main разбирает args (без имени подкоманды) и возвращает код выхода.
func (h *Helper) Main(ctx context.Context, args []string) int {
	if h.EUID() != 0 {
		_, _ = fmt.Fprintln(h.Stderr, "deploy-helper: нужен root (запускается через sudo)")
		return 1
	}
	err := h.dispatch(ctx, args)
	var ue usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		_, _ = fmt.Fprintln(h.Stderr, "deploy-helper:", ue.msg)
		return ExitUsage
	default:
		_, _ = fmt.Fprintln(h.Stderr, "deploy-helper:", err)
		return 1
	}
}

func (h *Helper) dispatch(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("ожидается: install <version> | stage <tmpfile> <version> | unit <verb>")
	}
	switch args[0] {
	case "install":
		if len(args) != 2 {
			return usagef("install <version>")
		}
		return h.install(ctx, args[1])
	case "stage":
		if len(args) != 3 {
			return usagef("stage <tmpfile> <version>")
		}
		return h.stage(ctx, args[1], args[2])
	case "unit":
		if len(args) != 2 {
			return usagef("unit start|stop|restart|status|is-active|enable|disable")
		}
		return h.unit(ctx, args[1])
	}
	return usagef("неизвестный глагол")
}

func (h *Helper) unit(ctx context.Context, verb string) error {
	var argv []string
	switch verb {
	case "start", "stop", "restart", "status", "is-active":
		argv = []string{verb, agentUnit}
	case "enable", "disable":
		argv = []string{verb, "--now", agentUnit}
	default:
		return usagef("недопустимый глагол unit")
	}
	return h.Run(ctx, h.Stdout, h.Stderr, systemctlPath, argv...)
}

func (h *Helper) arch(ctx context.Context) (string, error) {
	var b strings.Builder
	if err := h.Run(ctx, &b, h.Stderr, dpkgPath, "--print-architecture"); err != nil {
		return "", err
	}
	a := strings.TrimSpace(b.String())
	if !archRe.MatchString(a) {
		return "", fmt.Errorf("неожиданная архитектура %q", a)
	}
	return a, nil
}

func (h *Helper) debPath(ctx context.Context, version string) (string, error) {
	if !versionRe.MatchString(version) {
		return "", usagef("версия должна быть semver X.Y.Z[-pre]")
	}
	arch, err := h.arch(ctx)
	if err != nil {
		return "", err
	}
	return h.PackagesDir + "/tgproxy_" + version + "_" + arch + ".deb", nil
}

func (h *Helper) install(ctx context.Context, version string) error {
	path, err := h.debPath(ctx, version)
	if err != nil {
		return err
	}
	if err := h.checkDir(h.PackagesDir); err != nil {
		return err
	}
	f, err := h.openChecked(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := h.Verifier.Verify(path, f); err != nil {
		return fmt.Errorf("проверка пакета: %w", err)
	}
	return h.Run(ctx, h.Stdout, h.Stderr, dpkgPath, "-i", path)
}
