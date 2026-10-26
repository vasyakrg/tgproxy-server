package access

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const (
	keyPrefix    = "tgp_"
	keyBodyLen   = 24
	keyPrefixLen = 8
	base62       = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// NewKey генерирует скрытый ключ: tgp_ + 24 символа base62. Хранить нужно
// только hash и prefix; plain показывается пользователю один раз.
func NewKey() (plain string, hash []byte, prefix string, err error) {
	body := make([]byte, 0, keyBodyLen)
	buf := make([]byte, 64)
	for len(body) < keyBodyLen {
		if _, err = rand.Read(buf); err != nil {
			return "", nil, "", fmt.Errorf("access: generate key: %w", err)
		}
		for _, b := range buf {
			if b < 248 && len(body) < keyBodyLen { // 248 = 62*4: без смещения
				body = append(body, base62[b%62])
			}
		}
	}
	plain = keyPrefix + string(body)
	return plain, HashKey(plain), plain[:keyPrefixLen], nil
}

// HashKey возвращает SHA-256 ключа.
func HashKey(plain string) []byte {
	s := sha256.Sum256([]byte(plain))
	return s[:]
}
