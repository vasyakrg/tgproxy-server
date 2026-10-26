// Package verify проверяет подлинность релиза tgproxy: minisign-подпись
// checksums.txt (prehashed "ED", формат `minisign -S` по умолчанию),
// sha256 артефактов и минимально допустимую версию (защита от даунгрейда).
//
// Пакет не зависит от server/agent: им пользуются updater (сервер),
// selfupdate (root-oneshot) и deployhelper.
package verify

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"aead.dev/minisign"
)

// PublicKey — публичный ключ minisign.
type PublicKey = minisign.PublicKey

// Ошибки проверки.
var (
	ErrNoKeys       = errors.New("verify: не задано ни одного публичного ключа")
	ErrBadSignature = errors.New("verify: подпись не принята ни одним из доверенных ключей")
	ErrChecksum     = errors.New("verify: sha256 артефакта не совпадает с checksums.txt")
	ErrNotListed    = errors.New("verify: артефакта нет в checksums.txt")
	ErrDowngrade    = errors.New("verify: версия ниже min_version")
	ErrBadVersion   = errors.New("verify: некорректная версия")
)

// Info — результат успешной проверки подписи.
type Info struct {
	KeyIndex       int               // индекс принявшего ключа в pubkeys
	KeyID          uint64            // id ключа (из подписи)
	TrustedComment string            // подписанный комментарий целиком
	Fields         map[string]string // "timestamp:1 file:checksums.txt" -> {timestamp:1, file:checksums.txt}
	Prehashed      bool              // подпись формата "ED"
}

// ParsePublicKey принимает base64-строку ключа (`RWQ...`) либо содержимое
// minisign.pub (две строки, первая — untrusted comment).
func ParsePublicKey(s string) (PublicKey, error) {
	var pk PublicKey
	s = strings.TrimSpace(s)
	if s == "" {
		return pk, errors.New("verify: пустой публичный ключ")
	}
	if err := pk.UnmarshalText([]byte(s)); err != nil {
		return PublicKey{}, err
	}
	return pk, nil
}

// ParsePublicKeys разбирает список ключей; пустой список допустим.
func ParsePublicKeys(ss []string) ([]PublicKey, error) {
	out := make([]PublicKey, 0, len(ss))
	for i, s := range ss {
		pk, err := ParsePublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("pubkeys[%d]: %w", i, err)
		}
		out = append(out, pk)
	}
	return out, nil
}

// Verify проверяет подпись sig (содержимое .minisig) над checksums любым из
// pubkeys. Подпись trusted comment проверяется библиотекой.
func Verify(checksums, sig []byte, pubkeys []PublicKey) error {
	_, err := Authenticate(checksums, sig, pubkeys)
	return err
}

// Authenticate — как Verify, но возвращает разобранный trusted comment и ключ.
func Authenticate(checksums, sig []byte, pubkeys []PublicKey) (Info, error) {
	if len(pubkeys) == 0 {
		return Info{}, ErrNoKeys
	}
	var s minisign.Signature
	if err := s.UnmarshalText(sig); err != nil {
		return Info{}, fmt.Errorf("verify: подпись нечитаема: %w", err)
	}
	for i, pk := range pubkeys {
		if pk.ID() != s.KeyID {
			continue
		}
		if minisign.Verify(pk, checksums, sig) {
			return Info{
				KeyIndex:       i,
				KeyID:          s.KeyID,
				TrustedComment: s.TrustedComment,
				Fields:         parseComment(s.TrustedComment),
				Prehashed:      s.Algorithm == minisign.HashEdDSA,
			}, nil
		}
	}
	return Info{}, ErrBadSignature
}

func parseComment(c string) map[string]string {
	m := map[string]string{}
	for _, f := range strings.Fields(c) {
		if k, v, ok := strings.Cut(f, ":"); ok && k != "" {
			m[k] = v
		}
	}
	return m
}

// CheckFile сверяет sha256 содержимого r с записью name в checksums
// (формат sha256sum / goreleaser: "<hex>  <name>"). r читается до EOF.
func CheckFile(checksums []byte, name string, r io.Reader) error {
	want, err := lookup(checksums, name)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("verify: чтение %s: %w", name, err)
	}
	got := h.Sum(nil)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fmt.Errorf("%w: %s", ErrChecksum, name)
	}
	return nil
}

// Sum возвращает hex sha256 записи name из checksums.
func Sum(checksums []byte, name string) (string, error) {
	b, err := lookup(checksums, name)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func lookup(checksums []byte, name string) ([]byte, error) {
	for _, line := range strings.Split(string(checksums), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.TrimPrefix(f[1], "*") != name {
			continue
		}
		b, err := hex.DecodeString(f[0])
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("verify: некорректная сумма для %s", name)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrNotListed, name)
}

// Verifier — проверка релиза фиксированным набором ключей и нижней границей
// версии. Используется root-процессами (deploy-helper, update apply) и сервером.
type Verifier struct {
	Keys       []PublicKey
	MinVersion string // "" — без нижней границы (dev-сборка)
}

// Verify проверяет minisign-подпись checksums.txt.
func (v Verifier) Verify(checksums, sig []byte) error { return Verify(checksums, sig, v.Keys) }

// CheckFile сверяет sha256 содержимого r с записью name в checksums.
func (v Verifier) CheckFile(checksums []byte, name string, r io.Reader) error {
	return CheckFile(checksums, name, r)
}

// CheckVersion отвергает версию ниже MinVersion или нераспознаваемую.
func (v Verifier) CheckVersion(version string) error { return CheckVersion(version, v.MinVersion) }
