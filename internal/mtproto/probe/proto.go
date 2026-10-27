// Package probe — клиент проверки MTProto-прокси (FakeTLS → obfuscated2 →
// req_pq_multi → resPQ) и fake-DC для тестов и dev-стенда.
package probe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	ctorReqPQMulti uint32 = 0xbe7e8ef1
	ctorResPQ      uint32 = 0x05162463
	ctorVectorLong uint32 = 0x1cb5c415

	// padded intermediate: тег 0xdddddddd в кадре obfuscated2.
	tagPaddedIntermediate = 0xdd

	maxPacket = 1 << 16
)

var errBadFrame = errors.New("probe: некорректный кадр MTProto")

func newCTR(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // длина ключа фиксирована (32)
	}
	return cipher.NewCTR(block, iv)
}

// obfuscatedClient строит 64-байтный кадр клиента (dc со знаком, int16 LE).
// secret == nil — «открытый» режим как у соединения mtg→DC.
func obfuscatedClient(secret []byte, dc int) (wire []byte, send, recv cipher.Stream, err error) {
	var frame [64]byte
	for {
		if _, err = rand.Read(frame[:]); err != nil {
			return nil, nil, nil, fmt.Errorf("probe: rand: %w", err)
		}
		if frame[0] == 0xef {
			continue
		}
		// запрещённые начала кадра (HTTP, TLS, intermediate)
		switch binary.LittleEndian.Uint32(frame[:4]) {
		case 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0x02010316, 0xdddddddd, 0xeeeeeeee:
			continue
		}
		if binary.LittleEndian.Uint32(frame[4:8]) == 0 {
			continue
		}
		break
	}
	copy(frame[56:60], []byte{tagPaddedIntermediate, tagPaddedIntermediate, tagPaddedIntermediate, tagPaddedIntermediate})
	binary.LittleEndian.PutUint16(frame[60:62], u16(dc))

	keyed := func(f []byte) cipher.Stream {
		key := slices.Clone(f[8:40])
		if secret != nil {
			h := sha256.New()
			h.Write(f[8:40])
			h.Write(secret)
			key = h.Sum(nil)
		}
		return newCTR(key, f[40:56])
	}
	send = keyed(frame[:])
	rev := frame
	slices.Reverse(rev[8:56])
	recv = keyed(rev[:])

	var enc [64]byte
	send.XORKeyStream(enc[:], frame[:])
	copy(enc[8:56], frame[8:56])
	return enc[:], send, recv, nil
}

// unencryptedMessage собирает незашифрованное MTProto-сообщение
// (auth_key_id=0, msg_id, length, body).
func unencryptedMessage(msgID uint64, body []byte) []byte {
	m := make([]byte, 0, 20+len(body))
	m = binary.LittleEndian.AppendUint64(m, 0)
	m = binary.LittleEndian.AppendUint64(m, msgID)
	m = binary.LittleEndian.AppendUint32(m, u32(len(body)))
	return append(m, body...)
}

// parseUnencrypted возвращает msg_id и body незашифрованного сообщения.
func parseUnencrypted(p []byte) (msgID uint64, body []byte, err error) {
	if len(p) < 20 || binary.LittleEndian.Uint64(p) != 0 {
		return 0, nil, errBadFrame
	}
	n := int(binary.LittleEndian.Uint32(p[16:20]))
	if n < 4 || n > len(p)-20 {
		return 0, nil, errBadFrame
	}
	return binary.LittleEndian.Uint64(p[8:16]), p[20 : 20+n], nil
}

func reqPQMulti(nonce [16]byte) []byte {
	b := binary.LittleEndian.AppendUint32(make([]byte, 0, 20), ctorReqPQMulti)
	return append(b, nonce[:]...)
}

// Конверсии размеров/времени: значения ограничены протоколом (длины < 64 КиБ,
// unix-время > 0, DC — int16), переполнение невозможно.

func u32(n int) uint32 { return uint32(n) } // #nosec G115 -- длины ограничены maxPacket/размером записи

func u16(n int) uint16 { return uint16(n) } // #nosec G115 -- длина TLS-записи < 64 КиБ

func u8(n int) byte { return byte(n) } // #nosec G115 -- длины полей ClientHello < 256

func unix32(t time.Time) uint32 { return uint32(t.Unix()) } // #nosec G115 -- unix-время в LE-поле TLS по схеме FakeTLS

func msgIDAt(t time.Time, low uint64) uint64 { return uint64(t.Unix())<<32 | low } // #nosec G115 -- unix-время > 0

func signedDC(v uint16) int16 { return int16(v) } // #nosec G115 -- DC передаётся как int16 (media — отрицательный)
