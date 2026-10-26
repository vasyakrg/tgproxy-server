package updater

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

var uploadNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// UploadSource — файлы, загруженные администратором вручную (UI «Загрузить
// файл»): в каталоге лежат tgproxy_<v>_<arch>.deb, checksums.txt и
// checksums.txt.minisig. Подлинность проверяется так же, как для сети.
type UploadSource struct {
	Dir  string
	Arch string
}

// Latest выбирает наибольшую версию deb в каталоге.
func (u UploadSource) Latest(context.Context) (Release, error) {
	ents, err := os.ReadDir(u.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return Release{}, ErrNoRelease
		}
		return Release{}, err
	}
	var (
		best    verify.Version
		bestStr string
		assets  []Asset
	)
	prefix, suffix := "tgproxy_", "_"+u.Arch+".deb"
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		n := e.Name()
		if n == ChecksumsName || n == SigName {
			assets = append(assets, Asset{Name: n, Size: fi.Size()})
			continue
		}
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, suffix) {
			continue
		}
		vs := strings.TrimSuffix(strings.TrimPrefix(n, prefix), suffix)
		v, err := verify.ParseVersion(vs)
		if err != nil {
			continue
		}
		assets = append(assets, Asset{Name: n, Size: fi.Size()})
		if bestStr == "" || v.Compare(best) > 0 {
			best, bestStr = v, vs
		}
	}
	if bestStr == "" {
		return Release{}, ErrNoRelease
	}
	return Release{Version: bestStr, Tag: "v" + bestStr, Assets: assets}, nil
}

// Fetch открывает файл из каталога загрузки (только обычные файлы, без симлинков).
func (u UploadSource) Fetch(_ context.Context, a Asset) (io.ReadCloser, error) {
	if !uploadNameRe.MatchString(a.Name) {
		return nil, fmt.Errorf("updater: недопустимое имя файла")
	}
	p := filepath.Join(u.Dir, a.Name)
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("updater: %s не обычный файл", a.Name)
	}
	return os.Open(p) // #nosec G304 -- имя проверено uploadNameRe, каталог фиксирован
}
