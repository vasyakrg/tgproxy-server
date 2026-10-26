package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/server/updater"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Лимиты загрузки файла обновления.
const (
	// MaxUploadBytes — потолок размера deb при ручной загрузке.
	MaxUploadBytes int64 = 100 << 20
	// maxUploadMeta — потолок checksums.txt и .minisig.
	maxUploadMeta = 1 << 20
	// uploadSlack — запас на заголовки multipart сверх файлов.
	uploadSlack = 64 << 10
	// maxNotes — сколько байт release notes отдаём в UI/JSON.
	maxNotes = 16 << 10
	// maxResultErr — сколько байт ошибки установки показываем.
	maxResultErr = 1024
)

// Имена полей multipart-формы загрузки.
const (
	FieldDeb       = "deb"
	FieldChecksums = "checksums"
	FieldSignature = "signature"
)

// Ошибки сервиса «Система».
var (
	// ErrUpdatesDisabled — самообновление выключено в конфиге (update.enabled=false).
	ErrUpdatesDisabled = errors.New("api: обновления выключены в конфигурации")
	// ErrTooLargeUpload — загружаемый файл больше лимита.
	ErrTooLargeUpload = errors.New("api: файл больше допустимого размера")

	errInternal = errors.New("api: внутренняя ошибка")
)

// UploadError — загруженный набор файлов не принят (HTTP 422).
type UploadError struct {
	Kind string // missing|bad_name|bad_signature|bad_checksum|bad_version|not_newer|bad_form
	Msg  string
}

func (e *UploadError) Error() string { return "upload: " + e.Kind + ": " + e.Msg }

// UpdateBackend — то, что сервису нужно от *updater.Updater.
type UpdateBackend interface {
	Check(ctx context.Context) (updater.Release, error)
	Stage(ctx context.Context, version string) error
	Status() updater.Status
}

// SourceSwitch — Source для Updater: обычно отдаёт релизы из настроенного источника (Base);
// на время установки загруженного вручную пакета (Use(true)) читает проверенный набор из каталога загрузки.
// Источник из конфига при этом не меняется: проверки продолжают ходить в него.
type SourceSwitch struct {
	Base   updater.Source
	Upload updater.Source
	on     atomic.Bool
}

// Use включает и выключает чтение из каталога загрузки.
func (w *SourceSwitch) Use(upload bool) { w.on.Store(upload) }

func (w *SourceSwitch) cur() updater.Source {
	if w.on.Load() {
		return w.Upload
	}
	return w.Base
}

// Latest реализует updater.Source.
func (w *SourceSwitch) Latest(ctx context.Context) (updater.Release, error) {
	return w.cur().Latest(ctx)
}

// Fetch реализует updater.Source.
func (w *SourceSwitch) Fetch(ctx context.Context, a updater.Asset) (io.ReadCloser, error) {
	return w.cur().Fetch(ctx, a)
}

// SourceInfo — источник обновлений из конфига (для подписи на экране).
type SourceInfo struct {
	Kind   string // github|proxy|agent|upload
	Detail string // репозиторий, host прокси или id агента
}

// SystemConfig — зависимости SystemService.
type SystemConfig struct {
	Updater    UpdateBackend // nil — обновления выключены
	Switch     *SourceSwitch // источник Updater; nil — загруженный пакет поставить нельзя
	Source     SourceInfo
	Version    string             // установленная версия
	UploadDir  string             // каталог источника «Загрузить файл»
	Arch       string             // amd64
	PubKeys    []verify.PublicKey // те же ключи, что у Updater
	MinVersion string
	ResultPath string // updates/result.json от root-oneshot
	MaxUpload  int64  // 0 → MaxUploadBytes
	Audit      store.AuditRepo
	Logger     *slog.Logger
	Now        func() time.Time
}

// SystemService — обновление сервера: версия, проверка, установка, загрузка файла.
type SystemService struct {
	c    SystemConfig
	log  *slog.Logger
	now  func() time.Time
	opMu sync.Mutex // сериализует Refresh, Install и Upload
	mu   sync.Mutex
	last *updater.Release // результат последней успешной проверки

	uploaded     string // версия загруженного и проверенного пакета
	uploadedSize int64
}

// NewSystemService создаёт сервис.
func NewSystemService(c SystemConfig) *SystemService {
	s := &SystemService{c: c, log: c.Logger, now: c.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.c.MaxUpload <= 0 {
		s.c.MaxUpload = MaxUploadBytes
	}
	return s
}

// Enabled сообщает, что самообновление включено.
func (s *SystemService) Enabled() bool { return s.c.Updater != nil }

// MaxUpload — лимит размера deb.
func (s *SystemService) MaxUpload() int64 { return s.c.MaxUpload }

// InstallResult — итог последней установки (updates/result.json).
type InstallResult struct {
	Version    string `json:"version"`
	OK         bool   `json:"ok"`
	RolledBack bool   `json:"rolled_back"`
	Error      string `json:"error,omitempty"`
	At         string `json:"at,omitempty"`
}

// VersionInfo — состояние обновления для UI и GET /api/v1/system/version.
type VersionInfo struct {
	Enabled      bool           `json:"enabled"`
	Current      string         `json:"current"`
	Available    string         `json:"available,omitempty"`
	Notes        string         `json:"notes,omitempty"`
	CheckedAt    string         `json:"checked_at,omitempty"`
	Source       string         `json:"source"`
	SourceDetail string         `json:"source_detail,omitempty"`
	Staged       string         `json:"staged,omitempty"` // версия, ожидающая установки
	LastError    string         `json:"last_error,omitempty"`
	DebName      string         `json:"deb_name,omitempty"`
	DebSize      int64          `json:"deb_size,omitempty"`
	Uploaded     string         `json:"uploaded,omitempty"` // загруженный вручную проверенный пакет, готов к установке
	Target       string         `json:"target,omitempty"`   // что ставит кнопка «Установить»: Uploaded, иначе Available
	Result       *InstallResult `json:"result,omitempty"`
}

// ReleaseInfo — релиз из последней проверки.
type ReleaseInfo struct {
	Version     string `json:"version"`
	Tag         string `json:"tag,omitempty"`
	Notes       string `json:"notes,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
	Newer       bool   `json:"newer"` // новее установленной
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Version возвращает текущее состояние обновления.
func (s *SystemService) Version() VersionInfo {
	v := VersionInfo{Current: s.c.Version, Source: s.c.Source.Kind, SourceDetail: s.c.Source.Detail}
	if s.c.Updater == nil {
		return v
	}
	v.Enabled = true
	st := s.c.Updater.Status()
	if st.Current != "" {
		v.Current = st.Current
	}
	if st.Source != "" {
		v.Source = st.Source
		if st.Source != s.c.Source.Kind {
			v.SourceDetail = ""
		}
	}
	v.Available = st.Available
	v.Notes = truncate(st.Notes, maxNotes)
	v.CheckedAt = rfc3339(st.CheckedAt)
	v.Staged = st.Staged
	v.LastError = truncate(redact.String(st.LastError), maxResultErr)
	s.mu.Lock()
	if s.uploaded != "" {
		if c, err := verify.CompareVersions(s.uploaded, v.Current); (err == nil && c <= 0) || s.uploaded == v.Staged {
			s.uploaded = ""
		}
	}
	v.Uploaded = s.uploaded
	switch {
	case s.uploaded != "":
		v.Target, v.DebName, v.DebSize = s.uploaded, updater.DebName(s.uploaded, s.c.Arch), s.uploadedSize
	case st.Available != "":
		v.Target, v.DebName = st.Available, updater.DebName(st.Available, s.c.Arch)
		if s.last != nil && s.last.Version == st.Available {
			if a, ok := s.last.Asset(v.DebName); ok {
				v.DebSize = a.Size
			}
		}
	}
	s.mu.Unlock()
	v.Result = s.result()
	return v
}

// result читает итог последней установки; нечитаемый файл — «итога нет».
func (s *SystemService) result() *InstallResult {
	if s.c.ResultPath == "" {
		return nil
	}
	fi, err := os.Stat(s.c.ResultPath)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 64<<10 {
		return nil
	}
	b, err := os.ReadFile(s.c.ResultPath)
	if err != nil {
		return nil
	}
	var r InstallResult
	if err := json.Unmarshal(b, &r); err != nil || r.Version == "" {
		return nil
	}
	r.Error = truncate(redact.String(r.Error), maxResultErr)
	return &r
}

// Releases возвращает релизы из последней проверки (до первой проверки — пусто).
func (s *SystemService) Releases() []ReleaseInfo {
	s.mu.Lock()
	l := s.last
	s.mu.Unlock()
	if l == nil {
		return []ReleaseInfo{}
	}
	cur := s.c.Version
	if s.c.Updater != nil {
		cur = s.c.Updater.Status().Current
	}
	newer := true
	if c, err := verify.CompareVersions(l.Version, cur); err == nil {
		newer = c > 0
	}
	return []ReleaseInfo{{
		Version: l.Version, Tag: l.Tag, Notes: truncate(l.Notes, maxNotes),
		PublishedAt: rfc3339(l.PublishedAt), Newer: newer,
	}}
}

func (s *SystemService) record(ctx context.Context, act Actor, action, target, detail string) {
	if s.c.Audit == nil {
		return
	}
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	if _, err := s.c.Audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: action, Target: target, IP: act.IP, Detail: truncate(detail, 128),
	}); err != nil {
		s.log.ErrorContext(ctx, "system audit failed", "action", action, "err", err)
	}
}

// Refresh запрашивает последний релиз у источника без записи в аудит (периодическая проверка).
func (s *SystemService) Refresh(ctx context.Context) (VersionInfo, error) {
	if s.c.Updater == nil {
		return VersionInfo{}, ErrUpdatesDisabled
	}
	s.opMu.Lock()
	rel, err := s.c.Updater.Check(ctx)
	s.opMu.Unlock()
	if err != nil {
		return s.Version(), err
	}
	s.mu.Lock()
	s.last = &rel
	s.mu.Unlock()
	return s.Version(), nil
}

// Check — Refresh по запросу администратора, с записью в аудит.
func (s *SystemService) Check(ctx context.Context, act Actor) (VersionInfo, error) {
	v, err := s.Refresh(ctx)
	switch {
	case errors.Is(err, ErrUpdatesDisabled):
	case err != nil:
		s.record(ctx, act, "system.check", "", "failed")
	default:
		s.record(ctx, act, "system.check", v.Available, "")
	}
	return v, err
}

// Install ставит версию в очередь на установку (staged/request). Без confirm — ErrConfirmRequired.
// Повторный вызов при уже стоящем в очереди запросе — updater.ErrPending, второй request не создаётся.
func (s *SystemService) Install(ctx context.Context, act Actor, version string, confirm bool) (VersionInfo, error) {
	if s.c.Updater == nil {
		return VersionInfo{}, ErrUpdatesDisabled
	}
	if !confirm {
		return VersionInfo{}, ErrConfirmRequired
	}
	if _, err := verify.ParseVersion(version); err != nil {
		return VersionInfo{}, &ValidationError{Fields: FieldErrors{"version": "укажите версию в формате 1.2.3"}}
	}
	if s.c.Updater.Status().Staged != "" {
		return s.Version(), updater.ErrPending
	}
	s.opMu.Lock()
	s.mu.Lock()
	fromUpload := s.c.Switch != nil && s.uploaded == version
	s.mu.Unlock()
	if fromUpload {
		s.c.Switch.Use(true)
	}
	err := s.c.Updater.Stage(ctx, version)
	if fromUpload {
		s.c.Switch.Use(false)
	}
	s.opMu.Unlock()
	if err != nil {
		s.record(ctx, act, "system.update", version, "failed")
		return s.Version(), err
	}
	s.record(ctx, act, "system.update", version, "staged")
	return s.Version(), nil
}

var debNameRe = regexp.MustCompile(`^tgproxy_([0-9A-Za-z.+~-]{1,64})_([a-z0-9]{1,16})\.deb$`)

type uploaded struct {
	tmp       string
	name      string
	version   string
	sum       string
	size      int64
	checksums []byte
	sig       []byte
}

// Upload принимает три файла (deb, checksums.txt, checksums.txt.minisig) из multipart-формы.
// deb стримится на диск во временный файл; подпись и sha256 проверяются ДО помещения в каталог
// источника, при любой ошибке не остаётся ничего. После успеха источник переключается на
// загруженные файлы (до рестарта сервера) и выполняется проверка.
func (s *SystemService) Upload(ctx context.Context, act Actor, mr *multipart.Reader) (VersionInfo, error) {
	if s.c.Updater == nil {
		return VersionInfo{}, ErrUpdatesDisabled
	}
	if s.c.UploadDir == "" {
		return VersionInfo{}, ErrNotConfigured
	}
	if err := os.MkdirAll(s.c.UploadDir, 0o750); err != nil {
		return VersionInfo{}, fmt.Errorf("%w: upload dir: %w", errInternal, err)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	up, err := s.receive(mr)
	if err != nil {
		s.record(ctx, act, "system.upload", "", "rejected")
		return s.Version(), err
	}
	defer func() {
		if up.tmp != "" {
			_ = os.Remove(up.tmp) //nolint:gosec // путь создан os.CreateTemp в каталоге загрузки
		}
	}()
	if err := s.validate(up); err != nil {
		s.record(ctx, act, "system.upload", up.version, "rejected")
		return s.Version(), err
	}
	if err := s.commit(up); err != nil {
		return s.Version(), fmt.Errorf("%w: upload commit: %w", errInternal, err)
	}
	up.tmp = ""
	s.mu.Lock()
	s.uploaded, s.uploadedSize = up.version, up.size
	s.mu.Unlock()
	s.record(ctx, act, "system.upload", up.version, fmt.Sprintf("size=%d", up.size))
	return s.Version(), nil
}

func formErr(kind, msg string) error { return &UploadError{Kind: kind, Msg: msg} }

// receive читает multipart; при ошибке чистит временный файл.
func (s *SystemService) receive(mr *multipart.Reader) (_ *uploaded, err error) {
	up := &uploaded{}
	defer func() {
		if err != nil && up.tmp != "" {
			_ = os.Remove(up.tmp) //nolint:gosec // путь создан os.CreateTemp в каталоге загрузки
		}
	}()
	seen := map[string]bool{}
	for {
		part, perr := mr.NextPart()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			return nil, partErr(perr)
		}
		name := part.FormName()
		if seen[name] {
			_ = part.Close()
			return nil, formErr("bad_form", "поле "+name+" передано дважды")
		}
		seen[name] = true
		switch name {
		case FieldDeb:
			err = s.receiveDeb(part, up)
		case FieldChecksums:
			up.checksums, err = readMeta(part, "checksums.txt")
		case FieldSignature:
			up.sig, err = readMeta(part, "checksums.txt.minisig")
		default:
			_, _ = io.Copy(io.Discard, io.LimitReader(part, 1<<10))
			err = formErr("bad_form", "неизвестное поле формы")
		}
		_ = part.Close()
		if err != nil {
			return nil, err
		}
	}
	for _, f := range []struct{ field, label string }{
		{FieldDeb, "пакет .deb"}, {FieldChecksums, "checksums.txt"}, {FieldSignature, "checksums.txt.minisig"},
	} {
		if !seen[f.field] {
			return nil, formErr("missing", "нужны все три файла: пакет .deb, checksums.txt и checksums.txt.minisig (не хватает: "+f.label+")")
		}
	}
	return up, nil
}

func partErr(err error) error {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return ErrTooLargeUpload
	}
	return formErr("bad_form", "не удалось прочитать форму загрузки")
}

func readMeta(p *multipart.Part, label string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(p, maxUploadMeta+1))
	if err != nil {
		return nil, partErr(err)
	}
	if len(b) > maxUploadMeta {
		return nil, formErr("bad_form", label+" больше 1 МБ")
	}
	if len(b) == 0 {
		return nil, formErr("missing", "файл "+label+" пуст")
	}
	return b, nil
}

func (s *SystemService) receiveDeb(p *multipart.Part, up *uploaded) error {
	m := debNameRe.FindStringSubmatch(filepath.Base(p.FileName()))
	if m == nil || m[2] != s.c.Arch {
		return formErr("bad_name", "имя пакета должно быть tgproxy_<версия>_"+s.c.Arch+".deb")
	}
	if _, err := verify.ParseVersion(m[1]); err != nil {
		return formErr("bad_version", "в имени пакета неверная версия")
	}
	up.name, up.version = m[0], m[1]
	f, err := os.CreateTemp(s.c.UploadDir, ".up-*")
	if err != nil {
		return fmt.Errorf("%w: upload temp: %w", errInternal, err)
	}
	up.tmp = f.Name()
	h := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(f, h), io.LimitReader(p, s.c.MaxUpload+1))
	if serr := f.Close(); cerr == nil {
		cerr = serr
	}
	if cerr != nil {
		return partErr(cerr)
	}
	if n > s.c.MaxUpload {
		return ErrTooLargeUpload
	}
	if n == 0 {
		return formErr("missing", "файл пакета пуст")
	}
	up.size, up.sum = n, hex.EncodeToString(h.Sum(nil))
	return nil
}

// validate проверяет подпись checksums, sha256 пакета и версию. Ничего не публикует.
func (s *SystemService) validate(up *uploaded) error {
	if _, err := verify.Authenticate(up.checksums, up.sig, s.c.PubKeys); err != nil {
		if errors.Is(err, verify.ErrNoKeys) {
			return err
		}
		return formErr("bad_signature", "подпись checksums.txt не принята: файл подписан не доверенным ключом или повреждён")
	}
	want, err := verify.Sum(up.checksums, up.name)
	if err != nil {
		return formErr("bad_checksum", "пакета "+up.name+" нет в checksums.txt")
	}
	if want != up.sum {
		return formErr("bad_checksum", "sha256 пакета не совпадает с checksums.txt")
	}
	if err := verify.CheckVersion(up.version, s.c.MinVersion); err != nil {
		return formErr("bad_version", "версия "+up.version+" ниже минимально допустимой")
	}
	if c, cerr := verify.CompareVersions(up.version, s.c.Updater.Status().Current); cerr == nil && c <= 0 {
		return formErr("not_newer", "версия "+up.version+" не новее установленной")
	}
	return nil
}

// commit заменяет содержимое каталога загрузки проверенным набором. Пакет переименовывается
// последним: пока его нет, источник релиз не видит.
func (s *SystemService) commit(up *uploaded) error {
	ents, err := os.ReadDir(s.c.UploadDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if n == updater.ChecksumsName || n == updater.SigName || debNameRe.MatchString(n) {
			if err := os.Remove(filepath.Join(s.c.UploadDir, n)); err != nil {
				return err
			}
		}
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{updater.ChecksumsName, up.checksums}, {updater.SigName, up.sig}} {
		if err := writeFileAtomic(filepath.Join(s.c.UploadDir, f.name), f.data); err != nil {
			return err
		}
	}
	if err := os.Chmod(up.tmp, 0o640); err != nil { //nolint:gosec // читает тот же пользователь сервера
		return err
	}
	return os.Rename(up.tmp, filepath.Join(s.c.UploadDir, up.name)) //nolint:gosec // tmp — os.CreateTemp, name проверен debNameRe
}

func writeFileAtomic(dst string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(dst), ".up-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o640); err != nil { //nolint:gosec // читает тот же пользователь сервера
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// SystemFail переводит ошибку сервиса в HTTP-код, вид и сообщение для пользователя.
func SystemFail(err error) (code int, kind, msg string) {
	var (
		ue *UploadError
		ve *ValidationError
	)
	switch {
	case errors.As(err, &ue):
		return http.StatusUnprocessableEntity, ue.Kind, ue.Msg
	case errors.Is(err, ErrTooLargeUpload), errors.Is(err, updater.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, "too_large", "Файл больше допустимого размера (до 100 МБ)."
	case errors.Is(err, ErrConfirmRequired):
		return http.StatusBadRequest, "confirm_required", "Требуется подтверждение (confirm=yes)."
	case errors.Is(err, ErrUpdatesDisabled), errors.Is(err, ErrNotConfigured):
		return http.StatusNotImplemented, "not_configured", "Обновления выключены в конфиге (update.enabled: false)."
	case errors.Is(err, updater.ErrPending):
		return http.StatusConflict, "already_pending", "Обновление уже поставлено в очередь и ждёт установки. Второй запрос не создан."
	case errors.Is(err, updater.ErrBusy):
		return http.StatusConflict, "busy", "Операция уже выполняется, повторите чуть позже."
	case errors.As(err, &ve):
		return http.StatusUnprocessableEntity, "validation", "Ошибка валидации."
	case errors.Is(err, updater.ErrNotNewer):
		return http.StatusUnprocessableEntity, "not_newer", "Эта версия не новее установленной."
	case errors.Is(err, verify.ErrDowngrade):
		return http.StatusUnprocessableEntity, "downgrade", "Версия ниже минимально допустимой (update.min_version)."
	case errors.Is(err, verify.ErrBadSignature), errors.Is(err, verify.ErrChecksum), errors.Is(err, verify.ErrNotListed), errors.Is(err, verify.ErrNoKeys):
		return http.StatusUnprocessableEntity, "verification_failed", "Релиз не прошёл проверку подписи или sha256 и не принят."
	case errors.Is(err, errInternal):
		return http.StatusInternalServerError, "internal", "Внутренняя ошибка."
	case errors.Is(err, updater.ErrNoRelease), errors.Is(err, updater.ErrVersionUnavailable), errors.Is(err, updater.ErrAssetMissing):
		return http.StatusNotFound, "no_release", "Подходящий релиз в источнике не найден."
	}
	return http.StatusBadGateway, "source_error", "Источник обновлений не ответил: " + truncate(redact.String(err.Error()), 300)
}
