package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

// Config — зависимости Updater.
type Config struct {
	Source       Source
	SourceName   string // github|proxy|agent|upload — для статуса
	StagingDir   string // <data_dir>/updates: staged/ и request
	DownloadsDir string // кэш загрузок; по умолчанию <StagingDir>/downloads
	Arch         string // amd64
	PubKeys      []verify.PublicKey
	MinVersion   string
	Current      string // установленная версия (buildinfo.Version)
	Logger       *slog.Logger
	Now          func() time.Time
}

// Status — состояние для экрана «Система».
type Status struct {
	Current   string
	Available string // пусто, если новее ничего нет
	Notes     string
	CheckedAt time.Time
	Source    string
	Staged    string // версия в staged/request, если есть
	LastError string
}

// Updater выполняет Check → Stage. Check → Stage. Подпись проверяется до записи в кэш и в staged.
type Updater struct {
	cfg    Config
	cache  Cache
	stager Stager
	log    *slog.Logger

	opMu sync.Mutex // сериализует Check/Stage

	mu      sync.Mutex
	src     Source
	srcName string
	status  Status
	latest  *Release
}

// New создаёт Updater и чистит остатки прерванных загрузок.
func New(cfg Config) (*Updater, error) {
	if cfg.Source == nil || cfg.StagingDir == "" || cfg.Arch == "" {
		return nil, errors.New("updater: Source, StagingDir и Arch обязательны")
	}
	if cfg.DownloadsDir == "" {
		cfg.DownloadsDir = filepath.Join(cfg.StagingDir, "downloads")
	}
	if len(cfg.PubKeys) == 0 {
		return nil, verify.ErrNoKeys
	}
	if cfg.MinVersion != "" {
		if _, err := verify.ParseVersion(cfg.MinVersion); err != nil {
			return nil, fmt.Errorf("min_version: %w", err)
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	u := &Updater{
		cfg:     cfg,
		cache:   Cache{Dir: cfg.DownloadsDir, Arch: cfg.Arch},
		stager:  Stager{Dir: cfg.StagingDir},
		log:     cfg.Logger,
		src:     cfg.Source,
		srcName: cfg.SourceName,
	}
	u.cache.CleanTemp()
	u.stager.CleanStaging()
	u.status = Status{Current: cfg.Current, Source: cfg.SourceName}
	return u, nil
}

// SetSource переключает источник (UI «Откуда скачать»).
func (u *Updater) SetSource(s Source, name string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.src, u.srcName, u.latest = s, name, nil
	u.status.Source, u.status.Available, u.status.Notes = name, "", ""
}

func (u *Updater) source() Source {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.src
}

// Status возвращает копию состояния (Staged перечитывается с диска).
func (u *Updater) Status() Status {
	u.mu.Lock()
	st := u.status
	u.mu.Unlock()
	st.Staged = ""
	if p, err := u.stager.Pending(); err == nil && p != nil {
		st.Staged = p.Version
	}
	return st
}

func (u *Updater) fail(err error) error {
	u.mu.Lock()
	u.status.LastError = err.Error()
	u.mu.Unlock()
	return err
}

// Check запрашивает последний релиз у источника и обновляет статус.
func (u *Updater) Check(ctx context.Context) (Release, error) {
	if !u.opMu.TryLock() {
		return Release{}, ErrBusy
	}
	defer u.opMu.Unlock()
	rel, err := u.source().Latest(ctx)
	if err != nil {
		return Release{}, u.fail(err)
	}
	if _, err := verify.ParseVersion(rel.Version); err != nil {
		return Release{}, u.fail(err)
	}
	u.mu.Lock()
	u.latest = &rel
	u.status.CheckedAt = u.cfg.Now()
	u.status.LastError = ""
	u.status.Available, u.status.Notes = "", ""
	if u.newer(rel.Version) {
		u.status.Available, u.status.Notes = rel.Version, rel.Notes
	}
	u.mu.Unlock()
	return rel, nil
}

// newer: версия строго новее установленной. Нераспознаваемая текущая
// ("dev") считается самой старой.
func (u *Updater) newer(v string) bool {
	if _, err := verify.ParseVersion(u.cfg.Current); err != nil {
		return true
	}
	c, err := verify.CompareVersions(v, u.cfg.Current)
	return err == nil && c > 0
}

// Stage скачивает и проверяет версию, кладёт её в кэш и в updates/staged,
// создавая request. Порядок: подпись checksums → скачивание deb со сверкой
// sha256 во временный файл → кэш → staged. Любая ошибка оставляет кэш и
// staged нетронутыми.
func (u *Updater) Stage(ctx context.Context, version string) (err error) {
	if !u.opMu.TryLock() {
		return ErrBusy
	}
	defer u.opMu.Unlock()
	defer func() {
		if err != nil {
			err = u.fail(err)
		}
	}()

	if err = verify.CheckVersion(version, u.cfg.MinVersion); err != nil {
		return err
	}
	if !u.newer(version) {
		return ErrNotNewer
	}
	if p, perr := u.stager.Pending(); perr != nil {
		return perr
	} else if p != nil {
		return ErrPending
	}

	checksums, sig, debName, err := u.verifyAndCache(ctx, version)
	if err != nil {
		return err
	}
	err = u.stager.Stage(StageFiles{
		Req:       Request{Version: version, Component: ComponentServer},
		Deb:       u.cache.DebPath(version),
		DebName:   debName,
		Checksums: checksums,
		Sig:       sig,
	})
	if err == nil {
		u.mu.Lock()
		u.status.LastError = ""
		u.mu.Unlock()
	}
	return err
}

// Cache проверяет версию и кладёт проверенный пакет в кэш загрузок (для установщика
// агентов и раскатки) без проверки «новее» и без постановки в staged: самообновление
// сервера не запрашивается. Подпись проверяется до записи в кэш.
func (u *Updater) Cache(ctx context.Context, version string) (err error) {
	if !u.opMu.TryLock() {
		return ErrBusy
	}
	defer u.opMu.Unlock()
	defer func() {
		if err != nil {
			err = u.fail(err)
		}
	}()
	if err = verify.CheckVersion(version, u.cfg.MinVersion); err != nil {
		return err
	}
	if _, _, _, err = u.verifyAndCache(ctx, version); err != nil {
		return err
	}
	u.mu.Lock()
	u.status.LastError = ""
	u.mu.Unlock()
	return nil
}

// verifyAndCache — общая часть Stage и Cache: подпись checksums → наличие deb в
// checksums → проверенный deb в кэше. Возвращает проверенные checksums, подпись и имя deb.
func (u *Updater) verifyAndCache(ctx context.Context, version string) (checksums, sig []byte, debName string, err error) {
	src := u.source()
	rel, err := u.release(ctx, src, version)
	if err != nil {
		return nil, nil, "", err
	}
	if checksums, err = u.fetchAll(ctx, src, rel, ChecksumsName); err != nil {
		return nil, nil, "", err
	}
	if sig, err = u.fetchAll(ctx, src, rel, SigName); err != nil {
		return nil, nil, "", err
	}
	info, err := verify.Authenticate(checksums, sig, u.cfg.PubKeys)
	if err != nil {
		return nil, nil, "", err
	}
	u.log.Info("updater: подпись checksums принята", "version", version, "key", info.KeyIndex, "comment", info.TrustedComment)

	debName = DebName(version, u.cfg.Arch)
	if _, err = verify.Sum(checksums, debName); err != nil {
		return nil, nil, "", err
	}
	if err = u.ensureCached(ctx, src, rel, version, debName, checksums, sig); err != nil {
		return nil, nil, "", err
	}
	return checksums, sig, debName, nil
}

// release возвращает описание версии: из последнего Check либо у источника.
func (u *Updater) release(ctx context.Context, src Source, version string) (Release, error) {
	u.mu.Lock()
	l := u.latest
	u.mu.Unlock()
	if l != nil && l.Version == version {
		return *l, nil
	}
	rel, err := src.Latest(ctx)
	if err != nil {
		return Release{}, err
	}
	if rel.Version != version {
		return Release{}, fmt.Errorf("%w: %s (источник отдаёт %s)", ErrVersionUnavailable, version, rel.Version)
	}
	return rel, nil
}

func (u *Updater) fetchAll(ctx context.Context, src Source, rel Release, name string) ([]byte, error) {
	a, ok := rel.Asset(name)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAssetMissing, name)
	}
	rc, err := src.Fetch(ctx, a)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, maxMetaSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMetaSize {
		return nil, fmt.Errorf("%w: %s", ErrTooLarge, name)
	}
	return b, nil
}

// ensureCached гарантирует проверенный deb версии в кэше. Уже лежащий в кэше
// файл перепроверяется по подписанным checksums (кэш не доверенный).
func (u *Updater) ensureCached(ctx context.Context, src Source, rel Release, version, debName string, checksums, sig []byte) error {
	if u.cache.Has(version) {
		f, err := os.Open(u.cache.DebPath(version))
		if err == nil {
			cerr := verify.CheckFile(checksums, debName, f)
			_ = f.Close()
			if cerr == nil {
				return nil
			}
			u.log.Warn("updater: кэшированный deb не прошёл проверку, качаем заново", "err", cerr)
		}
	}
	a, ok := rel.Asset(debName)
	if !ok {
		return fmt.Errorf("%w: %s", ErrAssetMissing, debName)
	}
	if a.Size > maxDebSize {
		return fmt.Errorf("%w: %s", ErrTooLarge, debName)
	}
	rc, err := src.Fetch(ctx, a)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	tmp, err := u.cache.CreateTemp()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmp.Name())
		}
	}()
	lim := &limitedReader{r: rc, left: maxDebSize}
	if err = verify.CheckFile(checksums, debName, io.TeeReader(lim, tmp)); err != nil {
		if lim.exceeded {
			return fmt.Errorf("%w: %s", ErrTooLarge, debName)
		}
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = u.cache.Commit(tmp.Name(), version, checksums, sig); err != nil {
		return err
	}
	committed = true
	return nil
}

// limitedReader обрывает чтение при превышении лимита (ошибка, не молчаливый EOF).
type limitedReader struct {
	r        io.Reader
	left     int64
	exceeded bool
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		// Лимит исчерпан: любой дополнительный байт — превышение.
		var b [1]byte
		n, err := l.r.Read(b[:])
		if n > 0 {
			l.exceeded = true
			return 0, ErrTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}
