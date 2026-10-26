package updater

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/release"
)

const (
	tmpPrefix  = ".dl-"
	cacheFmode = 0o644
)

// Cache — непривилегированный кэш загрузок сервера: <Dir>/<версия>/ с тремя
// файлами релиза (tgproxy_<v>_<arch>.deb, checksums.txt, checksums.txt.minisig).
// Dir = <data_dir>/updates/downloads; updater пишет ТОЛЬКО сюда и в updates/staged.
// В кэш попадает только релиз, прошедший проверку подписи и sha256 (см. Updater.Stage).
// Доверенный root-кэш (/var/cache/tgproxy/packages) updater не трогает.
type Cache struct {
	Dir  string
	Arch string
}

// VersionDir — каталог версии v.
func (c Cache) VersionDir(v string) string { return release.VersionDir(c.Dir, v) }

// DebPath — путь кэшированного deb версии v.
func (c Cache) DebPath(v string) string { return filepath.Join(c.VersionDir(v), DebName(v, c.Arch)) }

// ChecksumsPath — путь к checksums.txt версии v.
func (c Cache) ChecksumsPath(v string) string { return filepath.Join(c.VersionDir(v), ChecksumsName) }

// SigPath — путь к checksums.txt.minisig версии v.
func (c Cache) SigPath(v string) string { return filepath.Join(c.VersionDir(v), SigName) }

// Has сообщает, что для версии v в кэше есть полный набор из трёх файлов.
func (c Cache) Has(v string) bool {
	return isRegular(c.DebPath(v)) && isRegular(c.ChecksumsPath(v)) && isRegular(c.SigPath(v))
}

// CreateTemp создаёт временный файл в каталоге кэша (одна ФС с итоговым путём).
func (c Cache) CreateTemp() (*os.File, error) {
	if err := os.MkdirAll(c.Dir, 0o750); err != nil {
		return nil, err
	}
	return os.CreateTemp(c.Dir, tmpPrefix+"*")
}

// CleanTemp удаляет недокачанные временные файлы (после рестарта процесса).
func (c Cache) CleanTemp() {
	ents, _ := os.ReadDir(c.Dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			_ = os.Remove(filepath.Join(c.Dir, e.Name()))
		}
	}
}

// Commit публикует проверенный tmp как deb версии v. Сначала подписанные
// метаданные, затем атомарный rename пакета: пока deb нет, Has == false.
func (c Cache) Commit(tmpPath, v string, checksums, sig []byte) error {
	if filepath.Dir(tmpPath) != filepath.Clean(c.Dir) {
		return errors.New("updater: tmp вне каталога кэша")
	}
	if err := os.MkdirAll(c.VersionDir(v), 0o750); err != nil {
		return err
	}
	if err := writeFileAtomic(c.ChecksumsPath(v), checksums); err != nil {
		return err
	}
	if err := writeFileAtomic(c.SigPath(v), sig); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, cacheFmode); err != nil {
		return err
	}
	return os.Rename(tmpPath, c.DebPath(v))
}

func isRegular(p string) bool {
	fi, err := os.Lstat(p) // #nosec G703 -- p строится из каталога кэша
	return err == nil && fi.Mode().IsRegular()
}

func writeFileAtomic(dst string, data []byte) error {
	return writeAtomic(dst, func(w io.Writer) error { _, err := w.Write(data); return err })
}

// writeAtomic пишет в temp рядом с dst, fsync и rename.
func writeAtomic(dst string, fill func(io.Writer) error) (err error) {
	var rnd [6]byte
	if _, err = rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := dst + ".tmp-" + hex.EncodeToString(rnd[:])
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, cacheFmode) // #nosec G304 -- путь внутри каталога кэша
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
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
