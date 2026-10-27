// Package selfupdate — привилегированное применение подписанного обновления
// (`tgproxy update apply`, docs/architecture.md §12, plan M6-T3).
//
// Запускается root-oneshot'ом tgproxy-update.service, когда менее привилегированный
// процесс (сервер или агент) положил пакет в <data_dir>/updates/staged и создал
// файл request. Процессу-инициатору НЕ доверяем: подпись, sha256 и min_version
// проверяются заново, а проверенный deb копируется в root-каталог (WorkDir)
// и ставится оттуда — подмена файла после проверки невозможна.
package selfupdate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/release"
)

// Ограничения на входные файлы.
const (
	maxRequestSize   = 4 << 10
	maxChecksumsSize = 1 << 20
	maxSigSize       = 4 << 10
	maxDebSize       = 512 << 20

	// ServerHealthTimeout / AgentHealthTimeout — окна ожидания health после рестарта.
	ServerHealthTimeout = 30 * time.Second
	AgentHealthTimeout  = 60 * time.Second
)

// Компоненты обновления.
const (
	ComponentServer = "server"
	ComponentAgent  = "agent"
)

var (
	// ErrNotRoot — применять обновление может только root.
	ErrNotRoot = errors.New("нужен root")
	// ErrLocked — другой `update apply` уже выполняется (request не трогаем).
	ErrLocked = errors.New("обновление уже выполняется (updates/.lock занят)")

	versionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
	archRe    = regexp.MustCompile(`^[a-z0-9]{2,16}$`)
)

// Verifier — проверка подлинности релиза (в проде — internal/release/verify
// со встроенными ключами).
type Verifier interface {
	// Verify проверяет minisign-подпись checksums.txt.
	Verify(checksums, sig []byte) error
	// CheckFile сверяет sha256 содержимого r с записью name в checksums.txt.
	CheckFile(checksums []byte, name string, r io.Reader) error
	// CheckVersion отвергает версию ниже min_version / невалидную.
	CheckVersion(version string) error
}

// Executor запускает фиксированные внешние команды (dpkg, systemctl).
type Executor interface {
	Run(ctx context.Context, name string, args ...string) error
}

// Request — содержимое файла request.
type Request struct {
	Version   string `json:"version"`
	Component string `json:"component"`
}

// Result — содержимое updates/result.json.
type Result struct {
	Version    string `json:"version"`
	OK         bool   `json:"ok"`
	RolledBack bool   `json:"rolled_back"`
	Error      string `json:"error"`
	// Warning — не фатальное предупреждение (например, новый шаблон конфига .dpkg-dist).
	Warning string `json:"warning,omitempty"`
	At      string `json:"at"`
}

// OutputExecutor — Executor, умеющий вернуть stdout (нужен для `systemctl show`: проверка
// стабильности агента). Без него health агента сводится к одиночной Probe.
type OutputExecutor interface {
	Output(ctx context.Context, name string, args ...string) (string, error)
}

// Config — зависимости и параметры Applier.
type Config struct {
	DataDir string // по умолчанию /var/lib/tgproxy
	// PackagesDir — доверенный root-кэш (по умолчанию /var/cache/tgproxy/packages,
	// root:root 0755): сюда после СОБСТВЕННОЙ проверки пишет только root. Раскладка
	// <v>/{tgproxy_<v>_<arch>.deb,checksums.txt,checksums.txt.minisig} + prev.deb.
	PackagesDir string
	// WorkDir — root-only каталог (RuntimeDirectory юнита) для проверенных копий deb.
	WorkDir string
	// Component: "" — брать из request; иначе должен совпасть.
	Component string
	Arch      string // архитектура dpkg: amd64/arm64
	// ConfDir — каталог конфигов пакета, где ищутся *.dpkg-dist (по умолчанию /etc/tgproxy).
	ConfDir        string
	CurrentVersion string // установленная версия (для prev.deb); "" или dev — бэкапа нет

	Verifier Verifier
	Exec     Executor
	// Probe — одна проверка здоровья компонента; nil — ошибка конфигурации.
	Probe         func(ctx context.Context, component string) error
	HealthTimeout time.Duration // 0 — по компоненту (30s/60s)
	// AgentStableFor — сколько непрерывно агент должен быть active при неизменных NRestarts и
	// ActiveEnterTimestampMonotonic (0 — 15s). Действует только если Exec реализует OutputExecutor.
	AgentStableFor time.Duration
	HealthInterval time.Duration // 0 — 1s

	EUID func() int
	// Owner возвращает uid владельца файла.
	Owner func(os.FileInfo) (uint32, bool)
	// AllowedUIDs — допустимые владельцы request/staged-файлов (root и tgproxy).
	AllowedUIDs []uint32
	// ResultGID — группа result.json (tgproxy); <0 — не менять.
	ResultGID int
	Now       func() time.Time
	Log       io.Writer
}

// Applier применяет обновление.
type Applier struct {
	c       Config
	warning string // предупреждение текущего Apply (попадает в result.json)
}

// New возвращает Applier; пустые поля получают боевые значения по умолчанию.
func New(c Config) *Applier {
	if c.DataDir == "" {
		c.DataDir = "/var/lib/tgproxy"
	}
	if c.PackagesDir == "" {
		c.PackagesDir = release.DefaultCacheDir
	}
	if c.ConfDir == "" {
		c.ConfDir = "/etc/tgproxy"
	}
	if c.WorkDir == "" {
		c.WorkDir = "/run/tgproxy-update"
	}
	if c.HealthInterval == 0 {
		c.HealthInterval = time.Second
	}
	if c.EUID == nil {
		c.EUID = os.Geteuid
	}
	if c.Owner == nil {
		c.Owner = fileOwner
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = io.Discard
	}
	return &Applier{c: c}
}

func (a *Applier) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(a.c.Log, "update: "+format+"\n", args...)
}

func (a *Applier) updatesDir() string  { return filepath.Join(a.c.DataDir, "updates") }
func (a *Applier) stagedDir() string   { return filepath.Join(a.updatesDir(), "staged") }
func (a *Applier) packagesDir() string { return a.c.PackagesDir }

// Apply выполняет обновление. Возвращает nil при успешной установке; при любой
// ошибке (кроме ErrNotRoot/ErrLocked) пишет result.json и всегда удаляет request.
func (a *Applier) Apply(ctx context.Context) error {
	if a.c.EUID() != 0 {
		return ErrNotRoot
	}
	if a.c.Verifier == nil || a.c.Exec == nil || a.c.Probe == nil {
		return errors.New("selfupdate: не заданы Verifier/Exec/Probe")
	}
	unlock, err := a.lock()
	if err != nil {
		return err
	}
	defer unlock()
	// request удаляется всегда, иначе path-юнит зациклится; остальное содержимое staged (deb, подпись)
	// тоже не нужно — проверенная копия уже в доверенном кэше. result.json лежит в updates/ и остаётся.
	defer func() {
		_ = os.Remove(filepath.Join(a.stagedDir(), "request"))
		_ = os.RemoveAll(a.stagedDir())
	}()

	res := Result{}
	req, err := a.readRequest()
	if err == nil {
		res.Version = req.Version
		res.RolledBack, err = a.run(ctx, req)
	}
	res.OK = err == nil
	if err == nil {
		res.Warning = a.warning
	}
	if err != nil {
		res.Error = err.Error()
		a.logf("ошибка: %v", err)
	}
	res.At = a.c.Now().UTC().Format(time.RFC3339)
	if werr := a.writeResult(res); werr != nil {
		a.logf("result.json: %v", werr)
		if err == nil {
			err = werr
		}
	}
	return err
}

func (a *Applier) lock() (func(), error) {
	dir := a.updatesDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- путь построен из DataDir
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- fd помещается в int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil // #nosec G115 -- fd процесса помещается в int
}

func (a *Applier) allowedOwner(fi os.FileInfo) bool {
	uid, ok := a.c.Owner(fi)
	if !ok {
		return false
	}
	for _, u := range a.c.AllowedUIDs {
		if u == uid {
			return true
		}
	}
	return false
}

// openStaged открывает обычный файл из staged без следования симлинкам;
// проверяет владельца, права и размер по fstat открытого файла.
func (a *Applier) openStaged(name string, limit int64, rootOnly bool) (*os.File, os.FileInfo, error) {
	path := filepath.Join(a.stagedDir(), name)
	return a.openChecked(path, limit, rootOnly)
}

func (a *Applier) openChecked(path string, limit int64, rootOnly bool) (*os.File, os.FileInfo, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if li.Mode()&os.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: не обычный файл", filepath.Base(path))
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- путь построен из DataDir и фиксированных имён
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s: не обычный файл", filepath.Base(path))
	}
	if fi.Size() > limit {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s: размер %d превышает лимит %d", filepath.Base(path), fi.Size(), limit)
	}
	ok := a.allowedOwner(fi)
	if rootOnly {
		uid, has := a.c.Owner(fi)
		ok = has && uid == 0
	}
	if !ok || fi.Mode().Perm()&0o022 != 0 {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s: недопустимый владелец или права (запись для группы/прочих)", filepath.Base(path))
	}
	return f, fi, nil
}

func (a *Applier) readRequest() (Request, error) {
	f, _, err := a.openStaged("request", maxRequestSize, false)
	if err != nil {
		return Request{}, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = f.Close() }()
	req, err := ParseRequest(f)
	if err != nil {
		return Request{}, err
	}
	if a.c.Component != "" && a.c.Component != req.Component {
		return Request{}, fmt.Errorf("request: component %q не совпадает с --component %q", req.Component, a.c.Component)
	}
	return req, nil
}

// ParseRequest строго разбирает содержимое файла request (не более maxRequestSize
// байт, без неизвестных полей и хвоста), проверяя версию и component.
func ParseRequest(r io.Reader) (Request, error) {
	var req Request
	dec := json.NewDecoder(io.LimitReader(r, maxRequestSize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("request: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("request: лишние данные после JSON")
	}
	if !versionRe.MatchString(req.Version) {
		return Request{}, errors.New("request: недопустимая версия")
	}
	if req.Component != ComponentServer && req.Component != ComponentAgent {
		return Request{}, errors.New("request: component должен быть server или agent")
	}
	return req, nil
}

func readAll(f *os.File, fi os.FileInfo) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, fi.Size()))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (a *Applier) run(ctx context.Context, req Request) (rolledBack bool, err error) {
	if !archRe.MatchString(a.c.Arch) {
		return false, errors.New("недопустимая архитектура")
	}
	if err := a.checkStagedDir(); err != nil {
		return false, err
	}
	// 1. Повторная проверка: подпись, min_version, sha256.
	cf, cfi, err := a.openStaged("checksums.txt", maxChecksumsSize, false)
	if err != nil {
		return false, fmt.Errorf("checksums.txt: %w", err)
	}
	checksums, err := readAll(cf, cfi)
	_ = cf.Close()
	if err != nil {
		return false, err
	}
	sf, sfi, err := a.openStaged("checksums.txt.minisig", maxSigSize, false)
	if err != nil {
		return false, fmt.Errorf("checksums.txt.minisig: %w", err)
	}
	sig, err := readAll(sf, sfi)
	_ = sf.Close()
	if err != nil {
		return false, err
	}
	if err := a.c.Verifier.Verify(checksums, sig); err != nil {
		return false, fmt.Errorf("подпись: %w", err)
	}
	if err := a.c.Verifier.CheckVersion(req.Version); err != nil {
		return false, fmt.Errorf("версия: %w", err)
	}
	debName := fmt.Sprintf("tgproxy_%s_%s.deb", req.Version, a.c.Arch)
	if err := os.MkdirAll(a.c.WorkDir, 0o700); err != nil {
		return false, err
	}
	newDeb := filepath.Join(a.c.WorkDir, debName)
	if err := a.stageVerifiedDeb(debName, checksums, newDeb); err != nil {
		return false, err
	}
	a.logf("пакет %s проверен", debName)

	// 1б. Проверенный релиз — в доверенный кэш (для будущих откатов и раскатки).
	if err := a.cacheRelease(req.Version, debName, checksums, sig, newDeb); err != nil {
		return false, fmt.Errorf("кэш пакетов: %w", err)
	}

	// 2. Бэкап текущей версии.
	prev, err := a.backupCurrent()
	if err != nil {
		return false, fmt.Errorf("бэкап: %w", err)
	}

	// 3. Установка, рестарт, health; при провале — откат.
	unit := "tgproxy-" + req.Component
	err = a.install(ctx, newDeb, unit, req.Component)
	if err == nil {
		return false, nil
	}
	// Неудачный релиз не должен оставаться «доверенным» в кэше (раскатка/установка не возьмёт его снова).
	_ = os.RemoveAll(release.VersionDir(a.packagesDir(), req.Version))
	if prev == "" {
		return false, fmt.Errorf("%w (откат невозможен: нет prev.deb)", err)
	}
	a.logf("откат на prev.deb: %v", err)
	if rerr := a.install(ctx, prev, unit, req.Component); rerr != nil {
		return true, fmt.Errorf("%w; откат не удался: %v", err, rerr)
	}
	return true, err
}

func (a *Applier) checkStagedDir() error {
	fi, err := os.Lstat(a.stagedDir())
	if err != nil {
		return fmt.Errorf("staged: %w", err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !a.allowedOwner(fi) || fi.Mode().Perm()&0o002 != 0 {
		return errors.New("staged: недопустимый каталог")
	}
	return nil
}

// stageVerifiedDeb копирует deb из staged в root-каталог, одновременно проверяя sha256
// по checksums.txt: хэшируется ровно то, что скопировано.
func (a *Applier) stageVerifiedDeb(name string, checksums []byte, dst string) (err error) {
	src, fi, err := a.openStaged(name, maxDebSize, false)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = src.Close() }()
	return writeFileAtomic(filepath.Dir(dst), dst, 0o600, func(w io.Writer) error {
		tee := io.TeeReader(io.LimitReader(src, fi.Size()), w)
		if err := a.c.Verifier.CheckFile(checksums, name, tee); err != nil {
			return fmt.Errorf("sha256 %s: %w", name, err)
		}
		_, err := io.Copy(io.Discard, tee)
		return err
	})
}

// ensurePackagesDir создаёт (при необходимости) и проверяет доверенный кэш:
// настоящий каталог, владелец root, нет записи для прочих.
func (a *Applier) ensurePackagesDir() error {
	pk := a.packagesDir()
	if err := os.MkdirAll(pk, 0o755); err != nil { // #nosec G301 -- кэш читаем всем, пишет root
		return err
	}
	fi, err := os.Lstat(pk)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("packages: недопустимый каталог (режим %v)", fi.Mode())
	}
	if uid, ok := a.c.Owner(fi); !ok || uid != 0 {
		return errors.New("packages: владелец должен быть root")
	}
	return nil
}

// cacheRelease кладёт проверенные deb/checksums/подпись в <packages>/<version>/.
// deb записывается последним: неполный набор не считается кэшированным.
func (a *Applier) cacheRelease(version, debName string, checksums, sig []byte, verifiedDeb string) error {
	if err := a.ensurePackagesDir(); err != nil {
		return err
	}
	vd := release.VersionDir(a.packagesDir(), version)
	if err := os.MkdirAll(vd, 0o755); err != nil { // #nosec G301 -- см. ensurePackagesDir
		return err
	}
	if err := os.Chmod(vd, 0o755); err != nil { // #nosec G302 -- каталог, читаемый всем
		return err
	}
	for name, data := range map[string][]byte{release.ChecksumsName: checksums, release.SigName: sig} {
		if err := writeFileAtomic(vd, filepath.Join(vd, name), 0o644, func(w io.Writer) error {
			_, err := w.Write(data)
			return err
		}); err != nil {
			return err
		}
	}
	in, err := os.Open(verifiedDeb) // #nosec G304 -- root-копия в WorkDir
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	return writeFileAtomic(vd, filepath.Join(vd, debName), 0o644, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	})
}

// backupCurrent копирует установленный deb из кэша в WorkDir/prev.deb и
// packages/prev.deb. Пусто — кэша нет (откат невозможен).
func (a *Applier) backupCurrent() (string, error) {
	cur := a.c.CurrentVersion
	if cur == "" || !versionRe.MatchString(cur) {
		a.logf("текущая версия неизвестна — бэкап пропущен")
		return "", nil
	}
	pk := a.packagesDir()
	fi, err := os.Lstat(pk)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			a.logf("кэш пакетов отсутствует — бэкап пропущен")
			return "", nil
		}
		return "", err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0o002 != 0 {
		return "", fmt.Errorf("packages: недопустимый каталог (режим %v)", fi.Mode())
	}
	if uid, ok := a.c.Owner(fi); !ok || uid != 0 {
		return "", errors.New("packages: владелец должен быть root")
	}
	src, _, err := a.openChecked(filepath.Join(pk, cur, fmt.Sprintf("tgproxy_%s_%s.deb", cur, a.c.Arch)), maxDebSize, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			a.logf("deb текущей версии %s не найден в кэше — бэкап пропущен", cur)
			return "", nil
		}
		return "", err
	}
	defer func() { _ = src.Close() }()
	work := filepath.Join(a.c.WorkDir, "prev.deb")
	if err := writeFileAtomic(a.c.WorkDir, work, 0o600, func(w io.Writer) error {
		_, err := io.Copy(w, src)
		return err
	}); err != nil {
		return "", err
	}
	// Персистентная копия для ручного отката.
	in, err := os.Open(work) // #nosec G304 -- путь в root-каталоге
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	if err := writeFileAtomic(pk, filepath.Join(pk, "prev.deb"), 0o644, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	}); err != nil {
		return "", err
	}
	return work, nil
}

func (a *Applier) install(ctx context.Context, deb, unit, component string) error {
	if err := a.c.Exec.Run(ctx, "dpkg", "--force-confdef", "--force-confold", "-i", deb); err != nil {
		return fmt.Errorf("dpkg -i: %w", err)
	}
	a.checkDpkgDist()
	if err := a.c.Exec.Run(ctx, "systemctl", "restart", unit); err != nil {
		return fmt.Errorf("systemctl restart %s: %w", unit, err)
	}
	return a.waitHealthy(ctx, component)
}

func (a *Applier) waitHealthy(ctx context.Context, component string) error {
	timeout := a.c.HealthTimeout
	if timeout == 0 {
		timeout = ServerHealthTimeout
		if component == ComponentAgent {
			timeout = AgentHealthTimeout
		}
	}
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var track *stability
	if oe, ok := a.c.Exec.(OutputExecutor); ok && component == ComponentAgent {
		stable := a.c.AgentStableFor
		if stable == 0 {
			stable = 15 * time.Second
		}
		track = &stability{oe: oe, unit: "tgproxy-" + component, need: stable, now: time.Now}
	}
	var last error
	for {
		last = a.c.Probe(hctx, component)
		if last == nil && track != nil {
			last = track.check(hctx)
		} else if track != nil {
			track.reset() // любое «не здоров» обнуляет окно стабильности
		}
		if last == nil {
			return nil
		}
		select {
		case <-hctx.Done():
			return fmt.Errorf("health: нет ответа за %s: %v", timeout, last)
		case <-time.After(a.c.HealthInterval):
		}
	}
}

// stability требует непрерывного active при неизменных NRestarts и ActiveEnterTimestampMonotonic:
// агент, который стартует и падает (Restart=on-failure), не считается здоровым.
type stability struct {
	oe     OutputExecutor
	unit   string
	need   time.Duration
	now    func() time.Time
	since  time.Time
	sample string
}

func (s *stability) reset() { s.since, s.sample = time.Time{}, "" }

func (s *stability) check(ctx context.Context) error {
	out, err := s.oe.Output(ctx, "systemctl", "show", "-p", "ActiveState,NRestarts,ActiveEnterTimestampMonotonic", s.unit)
	if err != nil {
		s.reset()
		return fmt.Errorf("systemctl show %s: %w", s.unit, err)
	}
	props := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			props[k] = v
		}
	}
	if props["ActiveState"] != "active" {
		s.reset()
		return fmt.Errorf("%s: ActiveState=%q", s.unit, props["ActiveState"])
	}
	cur := props["NRestarts"] + "/" + props["ActiveEnterTimestampMonotonic"]
	now := s.now()
	if s.since.IsZero() || cur != s.sample {
		s.since, s.sample = now, cur // первый замер или агент перезапускался — отсчёт заново
	}
	if d := now.Sub(s.since); d < s.need {
		return fmt.Errorf("%s: active только %s из %s", s.unit, d.Round(time.Second), s.need)
	}
	return nil
}

// writeResult атомарно пишет updates/result.json (0640 root:tgproxy).
func (a *Applier) writeResult(res Result) error {
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	dir := a.updatesDir()
	dst := filepath.Join(dir, "result.json")
	return writeFileAtomicOpts(dir, dst, 0o640, a.c.ResultGID, func(w io.Writer) error {
		_, err := w.Write(append(b, '\n'))
		return err
	})
}

func writeFileAtomic(dir, dst string, mode os.FileMode, fill func(io.Writer) error) error {
	return writeFileAtomicOpts(dir, dst, mode, -1, fill)
}

// writeFileAtomicOpts пишет во временный файл (O_EXCL) в dir и переименовывает в dst.
func writeFileAtomicOpts(dir, dst string, mode os.FileMode, gid int, fill func(io.Writer) error) (err error) {
	var rnd [8]byte
	if _, err = rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- каталог доверенный
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = fill(f); err != nil {
		return err
	}
	if gid >= 0 {
		if err = f.Chown(-1, gid); err != nil {
			return err
		}
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func fileOwner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// checkDpkgDist ищет *.dpkg-dist в каталоге конфигов: при --force-confold dpkg оставляет
// правленый оператором файл, а новый шаблон кладёт рядом. Находки — в лог и result.json.
func (a *Applier) checkDpkgDist() {
	matches, err := filepath.Glob(filepath.Join(a.c.ConfDir, "*.dpkg-dist"))
	if err != nil || len(matches) == 0 {
		return
	}
	sort.Strings(matches)
	var parts []string
	for _, m := range matches {
		parts = append(parts, fmt.Sprintf("новый шаблон конфига: diff %s %s", strings.TrimSuffix(m, ".dpkg-dist"), m))
	}
	msg := strings.Join(parts, "; ")
	a.logf("предупреждение: %s", msg)
	a.warning = msg
}
