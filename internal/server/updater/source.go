// Package updater реализует серверную часть самообновления (§12): обнаружение
// релиза из выбранного источника, проверку minisign-подписи ДО помещения в кэш,
// кэш deb-пакетов и атомарный стейджинг для root-oneshot `tgproxy update apply`.
package updater

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/release"
)

// Имена артефактов релиза (.goreleaser.yaml).
const (
	ChecksumsName = release.ChecksumsName
	SigName       = release.SigName
)

// Лимиты скачивания.
const (
	maxMetaSize = 1 << 20   // checksums.txt, .minisig, JSON API
	maxDebSize  = 512 << 20 // как в deployhelper
)

// Ошибки updater'а.
var (
	ErrAssetMissing       = errors.New("updater: в релизе нет нужного артефакта")
	ErrNoRelease          = errors.New("updater: релиз не найден")
	ErrVersionUnavailable = errors.New("updater: запрошенная версия недоступна в источнике")
	ErrNotNewer           = errors.New("updater: версия не новее установленной")
	ErrPending            = errors.New("updater: обновление уже поставлено в очередь")
	ErrBusy               = errors.New("updater: операция уже выполняется")
	ErrTooLarge           = errors.New("updater: артефакт больше допустимого размера")
)

// Asset — файл релиза.
type Asset struct {
	Name string
	URL  string // для upload-источника пуст
	Size int64
}

// Release — описание релиза без скачанного содержимого.
type Release struct {
	Version     string // без префикса "v"
	Tag         string
	Notes       string
	PublishedAt time.Time
	Assets      []Asset
}

// Asset ищет артефакт по имени.
func (r Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Source — источник релизов. Fetch возвращает тело артефакта; закрывать обязан
// вызывающий. Доверия к источнику нет: подлинность даёт только подпись.
type Source interface {
	Latest(ctx context.Context) (Release, error)
	Fetch(ctx context.Context, a Asset) (io.ReadCloser, error)
}

// DebName — имя deb в релизе и в кэше.
func DebName(version, arch string) string { return release.DebName(version, arch) }
