package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

const (
	maxSecretSize = 64 << 10
	// allowedPermMask — максимум, что допустимо для файлов с секретами:
	// 0600 или 0640 (группа tgproxy читает, остальным — ничего).
	allowedPermMask fs.FileMode = 0o640
)

// checkPerm проверяет, что path — обычный файл с правами не шире 0600/0640.
func checkPerm(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&^allowedPermMask != 0 {
		return fmt.Errorf("%s: permissions %#o too open, want 0600 or 0640", path, perm)
	}
	return nil
}

// checkPermIfExists — проверка прав для файлов, которые читает не этот пакет
// (ключи TLS, KEK). Отсутствующий файл не ошибка конфигурации: его появление
// (dev-certs, enroll, провижининг) — забота потребителя.
func checkPermIfExists(path string) error {
	if path == "" {
		return nil
	}
	if err := checkPerm(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return nil
}

// readSecret читает секрет из файла: права, размер, обрезка пробелов/переводов строки.
func readSecret(path string) (Secret, error) {
	if err := checkPerm(path); err != nil {
		return "", err
	}
	f, err := os.Open(path) // #nosec G304 -- путь из конфигурации администратора
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSecretSize+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxSecretSize {
		return "", fmt.Errorf("%s: secret larger than %d bytes", path, maxSecretSize)
	}
	s := trimSecret(string(b))
	if s == "" {
		return "", fmt.Errorf("%s: secret file is empty", path)
	}
	return Secret(s), nil
}

func trimSecret(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' }
