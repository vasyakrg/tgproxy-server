// Package auth — веб-аутентификация админов: users-файл (формат Authelia),
// argon2id, TOTP, сессии, login-флоу и middleware.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Параметры по умолчанию (Authelia) и пределы защиты от DoS.
const (
	DefaultM       uint32 = 65536 // KiB
	DefaultT       uint32 = 3
	DefaultP       uint8  = 4
	defaultSaltLen        = 16
	defaultKeyLen         = 32

	maxMemoryKiB uint32 = 1 << 20 // 1 GiB
	maxTime      uint32 = 10
	minSaltLen          = 8
	minKeyLen           = 4
	maxKeyLen           = 1024
	maxSaltLen          = 1024
)

// ErrBadHash — PHC-строка не разобрана или параметры недопустимы.
var ErrBadHash = errors.New("auth: bad argon2id hash")

// Params — параметры argon2id вместе с солью и ключом (для разобранной PHC-строки).
type Params struct {
	M    uint32 // память, KiB
	T    uint32 // итерации
	P    uint8  // параллелизм
	Salt []byte
	Key  []byte
}

func badHash(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadHash, fmt.Sprintf(format, a...))
}

// ParsePHC разбирает `$argon2id$v=19$m=..,t=..,p=..$salt$key`. Принимает base64 RawStd и Std.
func ParsePHC(s string) (Params, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, badHash("format")
	}
	if parts[1] != "argon2id" {
		return Params{}, badHash("variant %q not supported", parts[1])
	}
	if parts[2] != "v=19" {
		return Params{}, badHash("version %q not supported", parts[2])
	}
	var p Params
	var haveM, haveT, haveP bool
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return Params{}, badHash("parameter %q", kv)
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Params{}, badHash("parameter %q", kv)
		}
		switch k {
		case "m":
			p.M, haveM = uint32(n), true
		case "t":
			p.T, haveT = uint32(n), true
		case "p":
			if n > 255 {
				return Params{}, badHash("p too large")
			}
			p.P, haveP = uint8(n), true //nolint:gosec // n <= 255 проверено выше
		default:
			return Params{}, badHash("unknown parameter %q", k)
		}
	}
	if !haveM || !haveT || !haveP {
		return Params{}, badHash("missing m, t or p")
	}
	if p.P == 0 || p.T == 0 || p.M == 0 {
		return Params{}, badHash("zero parameter")
	}
	if p.M > maxMemoryKiB || p.T > maxTime {
		return Params{}, badHash("parameters exceed limits")
	}
	if p.M < 8*uint32(p.P) {
		return Params{}, badHash("m too small for p")
	}
	var err error
	if p.Salt, err = decodeB64(parts[4]); err != nil || len(p.Salt) < minSaltLen || len(p.Salt) > maxSaltLen {
		return Params{}, badHash("salt")
	}
	if p.Key, err = decodeB64(parts[5]); err != nil || len(p.Key) < minKeyLen || len(p.Key) > maxKeyLen {
		return Params{}, badHash("key")
	}
	return p, nil
}

func decodeB64(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return base64.StdEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// Verify сверяет пароль с PHC-хешем за константное время. Некорректный хеш -> false
// (без вычисления при превышении лимитов m/t).
func Verify(password, phc string) bool {
	p, err := ParsePHC(phc)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), p.Salt, p.T, p.M, p.P, uint32(len(p.Key))) // #nosec G115 -- длина ключа ограничена ParsePHC
	return subtle.ConstantTimeCompare(got, p.Key) == 1
}

// HashParams — параметры генерации хеша.
type HashParams struct {
	M, T    uint32
	P       uint8
	SaltLen int
	KeyLen  int
}

// DefaultHashParams — параметры Authelia: m=65536,t=3,p=4, salt 16, key 32.
func DefaultHashParams() HashParams {
	return HashParams{M: DefaultM, T: DefaultT, P: DefaultP, SaltLen: defaultSaltLen, KeyLen: defaultKeyLen}
}

// Hash возвращает PHC-строку argon2id (base64 RawStd, как у Authelia).
func Hash(password string, hp HashParams) (string, error) {
	if hp.M == 0 || hp.T == 0 || hp.P == 0 || hp.M > maxMemoryKiB || hp.T > maxTime {
		return "", badHash("invalid parameters")
	}
	if hp.SaltLen < minSaltLen || hp.KeyLen < minKeyLen {
		return "", badHash("salt/key length")
	}
	salt := make([]byte, hp.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, hp.T, hp.M, hp.P, uint32(hp.KeyLen)) // #nosec G115 -- KeyLen проверен
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", hp.M, hp.T, hp.P, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}
