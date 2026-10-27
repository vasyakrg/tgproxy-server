package faketls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

type genOpts struct {
	key       []byte
	sni       []string // имена host_name; пусто → расширения server_name нет
	timestamp time.Time
	sessionID []byte
	ciphers   []byte // по умолчанию GREASE + TLS_AES_128_GCM_SHA256
	extraExt  []byte // доп. расширения до server_name (готовые type+len+data)
	noHMAC    bool
}

func be16(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }

// buildHello — эталонный генератор: логика та же, что у FakeTLS-клиента tdlib/mtg.
func buildHello(o genOpts) []byte {
	var exts []byte
	exts = append(exts, o.extraExt...)
	if len(o.sni) > 0 {
		list := []byte{0} // формат mtg: тип записи один раз, затем [len name]*
		for _, n := range o.sni {
			list = append(list, be16(len(n))...)
			list = append(list, n...)
		}
		data := append(be16(len(list)), list...)
		exts = append(exts, 0, 0)
		exts = append(exts, be16(len(data))...)
		exts = append(exts, data...)
	}
	extBlock := append(be16(len(exts)), exts...)

	ciphers := o.ciphers
	if ciphers == nil {
		ciphers = []byte{0x0a, 0x0a, 0x13, 0x01}
	}
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(o.sessionID)))
	body = append(body, o.sessionID...)
	body = append(body, be16(len(ciphers))...)
	body = append(body, ciphers...)
	body = append(body, 0x01, 0x00)
	body = append(body, extBlock...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, be16(len(hs))...)
	rec = append(rec, hs...)

	if o.noHMAC {
		_, _ = rand.Read(rec[randomOffset : randomOffset+randomLen])
		return rec
	}
	mac := hmac.New(sha256.New, o.key)
	mac.Write(rec)
	random := mac.Sum(nil)
	ts := binary.LittleEndian.AppendUint32(nil, uint32(o.timestamp.Unix()))
	for i := range 4 {
		random[28+i] ^= ts[i]
	}
	copy(rec[randomOffset:], random)
	return rec
}

func sid() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}
