package release

import (
	"fmt"
	"path/filepath"
)

// Раскладка пакетов (docs/architecture.md §8, §12). И непривилегированный кэш
// загрузок сервера (<data_dir>/updates/downloads), и доверенный root-кэш
// (DefaultCacheDir) хранят релиз одинаково:
//
//	<base>/<version>/tgproxy_<version>_<arch>.deb
//	<base>/<version>/checksums.txt
//	<base>/<version>/checksums.txt.minisig
const (
	// DefaultCacheDir — доверенный кэш: пишут только root-процессы после
	// собственной проверки minisign (update apply, deploy-helper stage).
	DefaultCacheDir = "/var/cache/tgproxy/packages"

	ChecksumsName = "checksums.txt"
	SigName       = "checksums.txt.minisig"
)

// DebName — имя deb в релизе.
func DebName(version, arch string) string {
	return fmt.Sprintf("tgproxy_%s_%s.deb", version, arch)
}

// VersionDir — каталог версии внутри кэша base.
func VersionDir(base, version string) string { return filepath.Join(base, version) }
