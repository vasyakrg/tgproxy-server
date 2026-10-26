package deployhelper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

func fileOwner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

func (h *Helper) rootOwned(fi os.FileInfo) bool {
	uid, ok := h.Owner(fi)
	return ok && uid == 0
}

// checkDir: настоящий каталог (не симлинк), владелец root, нет записи для «прочих».
func (h *Helper) checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("каталог %s: %w", dir, err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s не каталог", dir)
	}
	if !h.rootOwned(fi) || fi.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("%s: владелец должен быть root, запись для прочих запрещена", dir)
	}
	return nil
}

// openChecked открывает обычный файл без следования симлинкам и проверяет
// владельца root и отсутствие записи для группы/прочих (по fstat открытого файла).
func (h *Helper) openChecked(path string) (*os.File, error) {
	f, err := h.openRegular(path, maxDebSize)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !h.rootOwned(fi) || fi.Mode().Perm()&0o022 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%s: владелец должен быть root, запись для группы/прочих запрещена", path)
	}
	return f, nil
}

// openRegular: Lstat (не симлинк) + O_NOFOLLOW + fstat (обычный файл, размер).
func (h *Helper) openRegular(path string, limit int64) (*os.File, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if li.Mode()&os.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- путь построен хелпером
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > limit {
		_ = f.Close()
		return nil, fmt.Errorf("%s: не обычный файл или слишком большой", path)
	}
	return f, nil
}

// SHA256Verifier сверяет sha256 файла с <path>.sha256 ("<hex>" или "<hex>  имя").
type SHA256Verifier struct {
	Owner func(os.FileInfo) (uint32, bool)
}

// Verify реализует Verifier.
func (v SHA256Verifier) Verify(path string, f *os.File) error {
	h := &Helper{Owner: v.Owner}
	sf, err := h.openRegular(path+".sha256", 4096)
	if err != nil {
		return fmt.Errorf("нет файла контрольной суммы: %w", err)
	}
	defer func() { _ = sf.Close() }()
	if fi, err := sf.Stat(); err != nil || !h.rootOwned(fi) || fi.Mode().Perm()&0o022 != 0 {
		return errors.New("файл контрольной суммы: владелец должен быть root, запись для группы/прочих запрещена")
	}
	want, err := readSum(sf)
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hs := sha256.New()
	if _, err := io.Copy(hs, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(hs.Sum(nil)); got != want {
		return errors.New("sha256 пакета не совпадает с контрольной суммой")
	}
	return nil
}

func readSum(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 || len(f[0]) != 64 {
		return "", errors.New("некорректный файл контрольной суммы")
	}
	s := strings.ToLower(f[0])
	if _, err := hex.DecodeString(s); err != nil {
		return "", errors.New("некорректный файл контрольной суммы")
	}
	return s, nil
}

func randName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// writeAtomic пишет в temp внутри dir и переименовывает в dst (0644).
func writeAtomic(dir, dst string, fill func(io.Writer) error) (err error) {
	n, err := randName()
	if err != nil {
		return err
	}
	tmp := dir + "/.stage-" + n
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304
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
	if err = f.Chmod(0o644); err != nil {
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
