package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// KEKSize — размер ключа шифрования ключей (AES-256).
const KEKSize = 32

// kekVersion — версия формата Seal; первый байт шифртекста. Позволяет
// ввести ротацию KEK/алгоритма без потери возможности расшифровать старое.
const kekVersion byte = 1

// ErrKEKExists — файл KEK уже существует; перезапись запрещена.
var ErrKEKExists = errors.New("pki: kek already exists")

// KEK — ключ шифрования ключей (секреты в БД и users_database.yml).
// Безопасен для конкурентного использования.
type KEK struct {
	aead cipher.AEAD
}

// LoadKEK читает KEK из файла. Файл должен быть обычным, ровно KEKSize байт,
// с правами только для владельца: 0400 (по архитектуре) или 0600 (допускается
// для dev и для файлов, которыми управляет root); любые биты group/other —
// ошибка.
func LoadKEK(path string) (*KEK, error) {
	f, err := os.Open(path) // #nosec G304 -- путь из конфигурации
	if err != nil {
		return nil, fmt.Errorf("pki: open kek: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("pki: stat kek: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("pki: kek %s is not a regular file", path)
	}
	if perm := st.Mode().Perm(); perm&0o177 != 0 {
		return nil, fmt.Errorf("pki: kek %s has mode %04o, want 0400 (0600 allowed)", path, perm)
	}
	if st.Size() != KEKSize {
		return nil, fmt.Errorf("pki: kek %s has %d bytes, want %d", path, st.Size(), KEKSize)
	}
	key := make([]byte, KEKSize)
	if _, err := io.ReadFull(f, key); err != nil {
		return nil, fmt.Errorf("pki: read kek: %w", err)
	}
	defer clear(key)
	return newKEK(key)
}

func newKEK(key []byte) (*KEK, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pki: kek cipher: %w", err)
	}
	aead, _ := cipher.NewGCM(block) // для AES-блока ошибки не бывает
	return &KEK{aead: aead}, nil
}

// GenerateKEK создаёт файл KEK (32 случайных байта, 0400). Существующий файл
// не перезаписывается: ErrKEKExists. Запись атомарна (временный файл + link).
func GenerateKEK(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("pki: mkdir kek dir: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%w: %s", ErrKEKExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("pki: stat kek: %w", err)
	}
	key := make([]byte, KEKSize)
	defer clear(key)
	_, _ = rand.Read(key) // с Go 1.24 никогда не возвращает ошибку
	tmpName, err := writeKeyTemp(dir, key)
	if err != nil {
		return fmt.Errorf("pki: write kek: %w", err)
	}
	defer func() { _ = os.Remove(tmpName) }()
	// link не перезаписывает существующий файл — атомарная защита от гонки.
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrKEKExists, path)
		}
		return fmt.Errorf("pki: install kek: %w", err)
	}
	return nil
}

// writeKeyTemp пишет key во временный файл 0400 рядом с целевым.
func writeKeyTemp(dir string, key []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, ".kek-*")
	if err != nil {
		return "", err
	}
	werr := tmp.Chmod(0o400)
	if werr == nil {
		_, werr = tmp.Write(key)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if err := errors.Join(werr, tmp.Close()); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// Seal шифрует pt (AES-256-GCM). aad — назначение шифртекста (например
// "ca-key", "totp:<user>"); при Open должно совпасть. Формат:
// версия(1) | nonce(12) | ciphertext+tag.
func (k *KEK) Seal(pt, aad []byte) ([]byte, error) { //nolint:unparam // реализует интерфейс Sealer
	ns := k.aead.NonceSize()
	out := make([]byte, 1+ns, 1+ns+len(pt)+k.aead.Overhead())
	out[0] = kekVersion
	_, _ = rand.Read(out[1:])
	return k.aead.Seal(out, out[1:1+ns], pt, adFor(kekVersion, aad)), nil // #nosec G407 -- nonce случайный (rand.Read выше)
}

// Open расшифровывает результат Seal; неверный ключ, AAD или повреждение —
// ошибка (не паника).
func (k *KEK) Open(ct, aad []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(ct) < 1+ns+k.aead.Overhead() {
		return nil, errors.New("pki: sealed data too short")
	}
	if ct[0] != kekVersion {
		return nil, fmt.Errorf("pki: unsupported sealed data version %d", ct[0])
	}
	pt, err := k.aead.Open(nil, ct[1:1+ns], ct[1+ns:], adFor(ct[0], aad))
	if err != nil {
		return nil, errors.New("pki: cannot decrypt sealed data (wrong key, purpose or corrupted)")
	}
	return pt, nil
}

// adFor привязывает версию формата к AAD (защита от подмены версии).
func adFor(version byte, aad []byte) []byte {
	return append([]byte{version}, aad...)
}
