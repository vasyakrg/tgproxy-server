package faketls

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"slices"
	"time"
)

const (
	blockSize  = sha256.BlockSize
	digestSize = sha256.Size
)

var zeroBlock [randomLen]byte

// Match определяет, какому из keys принадлежит ClientHello: SNI должен быть
// равен domain, HMAC-SHA256(key, запись с обнулённым random) XOR random должен
// быть нулевым в первых 28 байтах, а последние 4 (LE) — unix-timestamp в окне
// ±skew от now. Перебираются ВСЕ ключи без раннего выхода; при нескольких
// совпадениях возвращается первый. Аллокаций на ключ нет.
func Match(h Hello, keys [][16]byte, domain string, now time.Time, skew time.Duration) (int, bool) {
	if len(h.Raw) < randomOffset+randomLen || !slices.Contains(h.ServerNames, domain) {
		return 0, false
	}
	hs := sha256.New()

	var (
		ipad, opad [blockSize]byte
		inner      [digestSize]byte
		mac        [digestSize]byte
		idx        = -1
	)
	pre, post := h.Raw[:randomOffset], h.Raw[randomOffset+randomLen:]
	for i, key := range keys {
		// HMAC (RFC 2104): ключ короче блока дополняется нулями.
		for j := range ipad {
			ipad[j], opad[j] = 0x36, 0x5c
		}
		for j, kb := range key {
			ipad[j] ^= kb
			opad[j] ^= kb
		}
		hs.Reset()
		hs.Write(ipad[:])
		hs.Write(pre)
		hs.Write(zeroBlock[:])
		hs.Write(post)
		hs.Sum(inner[:0])
		hs.Reset()
		hs.Write(opad[:])
		hs.Write(inner[:])
		hs.Sum(mac[:0])

		for j := range randomLen {
			mac[j] ^= h.Random[j]
		}
		digestOK := subtle.ConstantTimeCompare(zeroBlock[:randomLen-4], mac[:randomLen-4]) == 1
		ts := time.Unix(int64(binary.LittleEndian.Uint32(mac[randomLen-4:])), 0)
		inWindow := now.Sub(ts).Abs() <= skew
		if digestOK && inWindow && idx < 0 {
			idx = i
		}
	}
	if idx < 0 {
		return 0, false
	}
	return idx, true
}
