package deployhelper

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vasyakrg/tgproxy-server/internal/release"
)

// stage переносит релиз из incoming в доверенный кэш. Во incoming лежат три файла:
// <tmpfile> (deb), <tmpfile>.checksums и <tmpfile>.minisig. Хелпер сам проверяет
// minisign встроенными ключами, версию против установленной и sha256 deb по
// подписанному checksums.txt; в кэш пишет только прошедшее проверку:
// <packages>/<v>/{checksums.txt,checksums.txt.minisig,tgproxy_<v>_<arch>.deb}.
// deb переименовывается последним: пока его нет, install откажет.
func (h *Helper) stage(ctx context.Context, tmpfile, version string) error {
	if !filepath.IsAbs(tmpfile) || filepath.Clean(tmpfile) != tmpfile ||
		filepath.Dir(tmpfile) != h.IncomingDir || !baseRe.MatchString(filepath.Base(tmpfile)) {
		return usagef("tmpfile должен лежать прямо в %s", h.IncomingDir)
	}
	verDir, debName, err := h.relPaths(ctx, version)
	if err != nil {
		return err
	}
	if err := h.checkDir(h.IncomingDir); err != nil {
		return err
	}
	if err := h.checkDir(h.PackagesDir); err != nil {
		return err
	}
	src, err := h.openRegular(tmpfile, maxDebSize)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	checksums, err := h.readIncoming(tmpfile+ChecksumsSuffix, maxChecksumsSize)
	if err != nil {
		return fmt.Errorf("нет checksums.txt: %w", err)
	}
	sig, err := h.readIncoming(tmpfile+SigSuffix, maxSigSize)
	if err != nil {
		return fmt.Errorf("нет подписи: %w", err)
	}
	if err := h.verifyRelease(version, debName, checksums, sig, src); err != nil {
		return fmt.Errorf("проверка пакета: %w", err)
	}

	if err := os.Mkdir(verDir, 0o755); err != nil && !os.IsExist(err) { // #nosec G301 -- кэш читаем всем, пишет root
		return err
	}
	if err := os.Chmod(verDir, 0o755); err != nil { // #nosec G302 -- каталог, читаемый всем
		return err
	}
	if err := h.checkDir(verDir); err != nil {
		return err
	}
	// Сначала подписанные метаданные, затем (после повторной сверки при копировании) пакет.
	if err := writeAtomic(verDir, verDir+"/"+release.ChecksumsName, bytesFill(checksums)); err != nil {
		return err
	}
	if err := writeAtomic(verDir, verDir+"/"+release.SigName, bytesFill(sig)); err != nil {
		return err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	dst := verDir + "/" + debName
	copyErr := writeAtomic(verDir, dst+".new", func(w io.Writer) error {
		// Хэшируется ровно то, что записано: подмена файла во incoming после
		// проверки не попадёт в кэш.
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			done <- h.Verifier.CheckFile(checksums, debName, pr)
			_, _ = io.Copy(io.Discard, pr)
		}()
		_, cerr := io.Copy(io.MultiWriter(w, pw), io.LimitReader(src, maxDebSize+1))
		_ = pw.CloseWithError(cerr)
		if verr := <-done; verr != nil && cerr == nil {
			return fmt.Errorf("sha256: %w", verr)
		}
		return cerr
	})
	if copyErr != nil {
		_ = os.Remove(verDir + "/" + release.ChecksumsName)
		_ = os.Remove(verDir + "/" + release.SigName)
		return copyErr
	}
	if err := os.Rename(dst+".new", dst); err != nil {
		_ = os.Remove(dst + ".new")
		return err
	}
	for _, p := range []string{tmpfile, tmpfile + ChecksumsSuffix, tmpfile + SigSuffix} {
		_ = os.Remove(p)
	}
	return nil
}

func bytesFill(b []byte) func(io.Writer) error {
	return func(w io.Writer) error { _, err := w.Write(b); return err }
}

// readIncoming читает сопроводительный файл из incoming (без следования симлинкам).
func (h *Helper) readIncoming(path string, limit int64) ([]byte, error) {
	f, err := h.openRegular(path, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}
