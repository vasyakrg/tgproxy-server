package enroll

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/release"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// PackagePathPrefix — префикс GET /enroll/package/<deb> на agent_gateway.
const PackagePathPrefix = "/enroll/package/"

// AgentArch — архитектура пакета, который раздаётся агентам за NAT.
const AgentArch = "amd64"

// maxMetaBytes — предел размера checksums.txt и .minisig.
const maxMetaBytes = 1 << 20

var (
	// ErrPackageUnavailable — в кэше нет проверенного пакета нужной версии.
	ErrPackageUnavailable = errors.New("enroll: package unavailable")
	// ErrBadPackageName — имя пакета не соответствует tgproxy_<semver>_<arch>.deb.
	ErrBadPackageName = errors.New("enroll: bad package name")

	debNameRe = regexp.MustCompile(`^tgproxy_(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?_[a-z0-9]{2,16}\.deb$`)
	versionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
)

// PackageInfo — проверенный пакет: имя файла и sha256 из подписанного checksums.txt.
type PackageInfo struct {
	Name    string
	Version string
	SHA256  string // hex
}

// PackageSource — проверенные пакеты агента (реализует *CachePackages).
type PackageSource interface {
	// Current возвращает проверенный пакет версии сервера либо ошибку,
	// оборачивающую ErrPackageUnavailable.
	Current() (PackageInfo, error)
	// Open открывает проверенный пакет name и позиционирует файл в начало;
	// вызывающий закрывает файл. ErrBadPackageName — имя вне формата,
	// ErrPackageUnavailable — такого проверенного пакета нет.
	Open(name string) (*os.File, PackageInfo, error)
}

// CachePackages раздаёт deb текущей версии сервера из кэша загрузок
// (<Dir>/<Version>/{tgproxy_<v>_<arch>.deb, checksums.txt, checksums.txt.minisig}).
// Перед выдачей каждый раз проверяются minisign-подпись checksums.txt, нижняя граница
// версии и sha256 открытого файла (подмена файла в кэше после загрузки не пройдёт).
type CachePackages struct {
	Dir      string          // updater.Cache.Dir
	Version  string          // версия сервера (buildinfo.Version)
	Arch     string          // AgentArch
	Verifier verify.Verifier // те же ключи, что у updater
}

var _ PackageSource = CachePackages{}

func (c CachePackages) name() string { return release.DebName(c.Version, c.Arch) }

// unavailable формирует понятную администратору ошибку (причина — для журнала/CLI).
func (c CachePackages) unavailable(cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: пакет %s не загружен на сервер; загрузите релиз %s в Система → Обновления",
			ErrPackageUnavailable, c.name(), c.Version)
	}
	return fmt.Errorf("%w: пакет %s не прошёл проверку (%v); загрузите релиз %s в Система → Обновления",
		ErrPackageUnavailable, c.name(), cause, c.Version)
}

// Current см. PackageSource.
func (c CachePackages) Current() (PackageInfo, error) {
	f, info, err := c.open()
	if err != nil {
		return PackageInfo{}, err
	}
	_ = f.Close()
	return info, nil
}

// Open см. PackageSource.
func (c CachePackages) Open(name string) (*os.File, PackageInfo, error) {
	if !debNameRe.MatchString(name) {
		return nil, PackageInfo{}, ErrBadPackageName
	}
	// Отдаётся только пакет версии сервера; другие версии/архитектуры — как «нет».
	if name != c.name() {
		return nil, PackageInfo{}, ErrPackageUnavailable
	}
	f, info, err := c.open()
	if err != nil {
		return nil, PackageInfo{}, err
	}
	return f, info, nil
}

func (c CachePackages) open() (*os.File, PackageInfo, error) {
	if c.Dir == "" || !versionRe.MatchString(c.Version) || !debNameRe.MatchString(c.name()) {
		return nil, PackageInfo{}, c.unavailable(errors.New("версия сервера не является релизной"))
	}
	if err := c.Verifier.CheckVersion(c.Version); err != nil {
		return nil, PackageInfo{}, c.unavailable(err)
	}
	dir := release.VersionDir(c.Dir, c.Version)
	sums, err := readMeta(filepath.Join(dir, release.ChecksumsName))
	if err != nil {
		return nil, PackageInfo{}, c.unavailable(nil)
	}
	sig, err := readMeta(filepath.Join(dir, release.SigName))
	if err != nil {
		return nil, PackageInfo{}, c.unavailable(nil)
	}
	if err := c.Verifier.Verify(sums, sig); err != nil {
		return nil, PackageInfo{}, c.unavailable(err)
	}
	p := filepath.Join(dir, c.name())
	fi, err := os.Lstat(p) // #nosec G304 G703 -- имя собрано из проверенных версии и архитектуры
	if err != nil || !fi.Mode().IsRegular() {
		return nil, PackageInfo{}, c.unavailable(nil)
	}
	file, err := os.Open(p) // #nosec G304 G703 -- см. выше
	if err != nil {
		return nil, PackageInfo{}, c.unavailable(nil)
	}
	fail := func(cause error) (*os.File, PackageInfo, error) {
		_ = file.Close()
		return nil, PackageInfo{}, c.unavailable(cause)
	}
	if ofi, serr := file.Stat(); serr != nil || !os.SameFile(fi, ofi) { // подмена файла между Lstat и Open
		return fail(errors.New("файл изменился во время проверки"))
	}
	// sha256 считается по уже открытому дескриптору: отдаётся ровно проверенное содержимое.
	if err := c.Verifier.CheckFile(sums, c.name(), file); err != nil {
		return fail(err)
	}
	sum, err := verify.Sum(sums, c.name())
	if err != nil {
		return fail(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return file, PackageInfo{Name: c.name(), Version: c.Version, SHA256: sum}, nil
}

func readMeta(p string) ([]byte, error) {
	fi, err := os.Lstat(p) // #nosec G304 G703 -- путь внутри каталога кэша
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxMetaBytes {
		return nil, errors.New("not a regular file")
	}
	return os.ReadFile(p) // #nosec G304 G703 -- см. выше
}

// PackageHandler — GET /enroll/package/<deb> для gateway.WithEnrollPackageHandler.
// Авторизация: Authorization: Bearer <enrollment-токен>; токен должен быть валиден
// (не истёк, не использован), но НЕ расходуется. Причина отказа клиенту не раскрывается.
func (s *Service) PackageHandler() http.Handler {
	return http.HandlerFunc(s.servePackage)
}

func (s *Service) servePackage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !s.pkgLim.allow(ip) {
		s.observe("package_rate_limited")
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	e, ok := s.pending(r)
	if !ok {
		s.observe("package_denied")
		s.audit(r.Context(), "", "enroll.package.denied", "", ip, "")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.cfg.Packages == nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, PackagePathPrefix)
	f, info, err := s.cfg.Packages.Open(name)
	switch {
	case errors.Is(err, ErrBadPackageName):
		http.Error(w, "bad package name", http.StatusBadRequest)
		return
	case errors.Is(err, ErrPackageUnavailable):
		s.log.Warn("enroll: package unavailable", "enrollment", e.ID, "name", name, "err", err)
		http.NotFound(w, r)
		return
	case err != nil:
		s.log.Error("enroll: package open failed", "enrollment", e.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.observe("package_ok")
	s.audit(r.Context(), "", "enroll.package", info.Name, ip, "enrollment="+e.ID)
	s.log.Info("enroll: package served", "enrollment", e.ID, "name", info.Name, "ip", ip)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, info.Name, fi.ModTime(), f)
}

// pending проверяет Bearer-токен запроса, не расходуя его. Сравнение хешей по всем
// ожидающим токенам идёт без раннего выхода.
func (s *Service) pending(r *http.Request) (store.Enrollment, bool) {
	h := r.Header.Get("Authorization")
	const scheme = "bearer "
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return store.Enrollment{}, false
	}
	hash, ok := tokenHash(strings.TrimSpace(h[len(scheme):]))
	if !ok {
		return store.Enrollment{}, false
	}
	list, err := s.cfg.Enrollments.ListPending(r.Context(), s.now())
	if err != nil {
		s.log.Error("enroll: list pending failed", "err", err)
		return store.Enrollment{}, false
	}
	var (
		found store.Enrollment
		hit   bool
	)
	for _, e := range list {
		if subtle.ConstantTimeCompare(e.TokenHash, hash[:]) == 1 {
			found, hit = e, true
		}
	}
	return found, hit
}
