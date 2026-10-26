package deployhelper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// stage переносит deb из incoming в packages: копирование с O_NOFOLLOW, sha256
// по <tmpfile>.sha256, атомарный rename; рядом кладётся <deb>.sha256 для install.
func (h *Helper) stage(ctx context.Context, tmpfile, version string) error {
	if !filepath.IsAbs(tmpfile) || filepath.Clean(tmpfile) != tmpfile ||
		filepath.Dir(tmpfile) != h.IncomingDir || !baseRe.MatchString(filepath.Base(tmpfile)) {
		return usagef("tmpfile должен лежать прямо в %s", h.IncomingDir)
	}
	dst, err := h.debPath(ctx, version)
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
	sf, err := h.openRegular(tmpfile+".sha256", 4096)
	if err != nil {
		return fmt.Errorf("нет файла контрольной суммы: %w", err)
	}
	want, err := readSum(sf)
	_ = sf.Close()
	if err != nil {
		return err
	}

	hs := sha256.New()
	copyErr := writeAtomic(h.PackagesDir, dst+".new", func(w io.Writer) error {
		_, err := io.Copy(io.MultiWriter(w, hs), io.LimitReader(src, maxDebSize+1))
		if err != nil {
			return err
		}
		if got := hex.EncodeToString(hs.Sum(nil)); got != want {
			return fmt.Errorf("sha256 файла %s не совпал с %s.sha256", filepath.Base(tmpfile), filepath.Base(tmpfile))
		}
		return nil
	})
	if copyErr != nil {
		return copyErr
	}
	// Сначала сумма, затем пакет: пока deb не на месте, install откажет.
	sumErr := writeAtomic(h.PackagesDir, dst+".sha256", func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "%s  %s\n", want, filepath.Base(dst))
		return err
	})
	if sumErr != nil {
		_ = os.Remove(dst + ".new")
		return sumErr
	}
	if err := os.Rename(dst+".new", dst); err != nil {
		_ = os.Remove(dst + ".new")
		return err
	}
	_ = os.Remove(tmpfile)
	_ = os.Remove(tmpfile + ".sha256")
	return nil
}
