// Package deployhelper — привилегированный хелпер `tgproxy deploy-helper`
// (architecture §8). Пользователь tgproxy-deploy может через sudo запускать
// только его, а хелпер сам разбирает и жёстко валидирует ввод: ни оболочки, ни
// передачи аргументов дальше, пути строятся здесь по версии и архитектуре dpkg.
//
// Глаголы:
//
//	install <version>            dpkg -i /var/cache/tgproxy/packages/<v>/tgproxy_<v>_<arch>.deb после повторной проверки minisign
//	stage <tmpfile> <version>    перенос релиза из каталога incoming в доверенный кэш; рядом с deb лежат
//	                             <tmpfile>.checksums и <tmpfile>.minisig (подпись проверяется встроенными ключами)
//	unit start|stop|restart|status|is-active|enable|disable   только tgproxy-agent (enable/disable = с --now)
//	unit enable-update|is-active-update   только tgproxy-update-agent.path (самообновление агента)
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

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/release"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

// Фиксированные пути.
const (
	DefaultPackagesDir = release.DefaultCacheDir // root:root 0755, пишут только root-процессы
	// DefaultIncomingDir лежит вне /var/lib/tgproxy (0750 tgproxy:tgproxy), чтобы
	// пользователь tgproxy-deploy мог в него дойти; родитель /var/lib принадлежит root.
	DefaultIncomingDir = "/var/lib/tgproxy-incoming"
	agentUnit          = "tgproxy-agent"
	agentUpdateUnit    = "tgproxy-update-agent.path"
	dpkgPath           = "/usr/bin/dpkg"
	systemctlPath      = "/usr/bin/systemctl"
	maxDebSize         = 512 << 20
	maxChecksumsSize   = 1 << 20
	maxSigSize         = 4 << 10

	// Суффиксы сопроводительных файлов stage в incoming.
	ChecksumsSuffix = ".checksums"
	SigSuffix       = ".minisig"
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

// Verifier проверяет подлинность релиза перед стейджем и установкой. В проде это
// minisign по ключам, вшитым в бинарь (release.EmbeddedPubKeys), sha256 из
// подписанного checksums.txt и нижняя граница версии = установленная версия.
// Пропуска проверки («no-op») нет и быть не должно.
type Verifier interface {
	// Verify проверяет minisign-подпись checksums.txt.
	Verify(checksums, sig []byte) error
	// CheckFile сверяет sha256 содержимого r с записью name в checksums.txt.
	CheckFile(checksums []byte, name string, r io.Reader) error
	// CheckVersion отвергает версию ниже установленной / невалидную.
	CheckVersion(version string) error
}

// embeddedVerifier строит боевой Verifier. Ошибка вшитых ключей = отказ всех проверок.
func embeddedVerifier() Verifier {
	keys, err := release.EmbeddedPubKeys()
	if err != nil {
		return failVerifier{fmt.Errorf("встроенные ключи: %w", err)}
	}
	floor := buildinfo.Version
	if _, err := verify.ParseVersion(floor); err != nil {
		floor = "" // dev-сборка: нижней границы нет
	}
	return verify.Verifier{Keys: keys, MinVersion: floor}
}

type failVerifier struct{ err error }

func (f failVerifier) Verify([]byte, []byte) error               { return f.err }
func (f failVerifier) CheckFile([]byte, string, io.Reader) error { return f.err }
func (f failVerifier) CheckVersion(string) error                 { return f.err }

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

// New возвращает хелпер с боевыми путями и проверкой minisign по вшитым ключам.
func New(stdout, stderr io.Writer) *Helper {
	h := &Helper{
		PackagesDir: DefaultPackagesDir, IncomingDir: DefaultIncomingDir,
		Run: execRun, EUID: os.Geteuid, Owner: fileOwner, Stdout: stdout, Stderr: stderr,
	}
	h.Verifier = embeddedVerifier()
	return h
}

func execRun(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- name — константа пакета, args построены хелпером
	cmd.Stdin = nil                                // /dev/null: dpkg не должен ждать ответа на вопросы
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
			return usagef("unit start|stop|restart|status|is-active|enable|disable|enable-update|is-active-update")
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
	case "enable-update": // path-юнит самообновления агента (D1): единственный дополнительный юнит в allowlist
		argv = []string{"enable", "--now", agentUpdateUnit}
	case "is-active-update":
		argv = []string{"is-active", agentUpdateUnit}
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

// relPaths возвращает каталог версии и имена файлов релиза в кэше.
func (h *Helper) relPaths(ctx context.Context, version string) (verDir, debName string, err error) {
	if !versionRe.MatchString(version) {
		return "", "", usagef("версия должна быть semver X.Y.Z[-pre]")
	}
	arch, err := h.arch(ctx)
	if err != nil {
		return "", "", err
	}
	return release.VersionDir(h.PackagesDir, version), release.DebName(version, arch), nil
}

func (h *Helper) install(ctx context.Context, version string) error {
	verDir, debName, err := h.relPaths(ctx, version)
	if err != nil {
		return err
	}
	if err := h.checkDir(h.PackagesDir); err != nil {
		return err
	}
	if err := h.checkDir(verDir); err != nil {
		return err
	}
	debPath := verDir + "/" + debName
	f, err := h.openChecked(debPath, maxDebSize)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	checksums, err := h.readChecked(verDir+"/"+release.ChecksumsName, maxChecksumsSize)
	if err != nil {
		return err
	}
	sig, err := h.readChecked(verDir+"/"+release.SigName, maxSigSize)
	if err != nil {
		return err
	}
	if err := h.verifyRelease(version, debName, checksums, sig, f); err != nil {
		return fmt.Errorf("проверка пакета: %w", err)
	}
	// --force-conf*: конфиг, правленный оператором, сохраняется (новый шаблон ляжет рядом
	// как .dpkg-dist), dpkg не задаёт интерактивных вопросов.
	return h.Run(ctx, h.Stdout, h.Stderr, dpkgPath, "--force-confdef", "--force-confold", "-i", debPath)
}

// verifyRelease: подпись → версия → sha256 deb по подписанному checksums.txt.
func (h *Helper) verifyRelease(version, debName string, checksums, sig []byte, deb io.ReadSeeker) error {
	if err := h.Verifier.Verify(checksums, sig); err != nil {
		return fmt.Errorf("подпись: %w", err)
	}
	if err := h.Verifier.CheckVersion(version); err != nil {
		return fmt.Errorf("версия: %w", err)
	}
	if _, err := deb.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := h.Verifier.CheckFile(checksums, debName, deb); err != nil {
		return fmt.Errorf("sha256: %w", err)
	}
	return nil
}
