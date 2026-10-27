// Package faketls разбирает первую TLS-запись FakeTLS-клиента MTProto и
// определяет, какому секрету она принадлежит. Алгоритм совпадает с mtg v2.2.8
// (mtglib/internal/tls/fake): HMAC-SHA256(key, ClientHello с обнулённым random),
// timestamp в последних 4 байтах random.
package faketls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxRecord — максимальная длина тела TLS-записи (RFC 8446: 2^14).
	MaxRecord = 16 * 1024

	recordHeaderLen = 5
	recordHandshake = 0x16
	typeClientHello = 0x01

	// randomOffset — смещение random в записи: заголовок записи (5) +
	// тип рукопожатия (1) + uint24 длина (3) + client_version (2).
	randomOffset = recordHeaderLen + 1 + 3 + 2
	randomLen    = 32

	greaseMask  = 0x0f0f
	greaseValue = 0x0a0a
)

// Ошибки разбора. Все они означают «не наш клиент» — вызывающий уходит в fallthrough.
var (
	ErrNotHandshake = errors.New("faketls: не TLS handshake запись")
	ErrBadVersion   = errors.New("faketls: неверная версия TLS")
	ErrBadLength    = errors.New("faketls: неверная длина записи")
	ErrTooLarge     = errors.New("faketls: запись больше допустимого")
	ErrNotHello     = errors.New("faketls: не ClientHello")
	ErrMalformed    = errors.New("faketls: повреждённый ClientHello")
)

// Hello — разобранный ClientHello. Raw и SessionID ссылаются на исходный буфер.
type Hello struct {
	SNI         string   // первое имя host_name из расширения server_name
	ServerNames []string // все host_name (mtg принимает, если среди них есть нужное)
	Random      [32]byte
	SessionID   []byte
	Raw         []byte // вся TLS-запись, включая 5-байтный заголовок
}

// ReadFirstRecord читает ровно одну TLS-запись Handshake (заголовок + тело) и
// проверяет заголовок: тип 0x16, версия 3.x, длина тела 1..max (max<=0 → MaxRecord).
// При ошибке возвращает уже прочитанные байты — их нужно повторить при fallthrough.
func ReadFirstRecord(r io.Reader, maxLen int) ([]byte, error) {
	if maxLen <= 0 {
		maxLen = MaxRecord
	}
	var hdr [recordHeaderLen]byte
	n, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return append([]byte(nil), hdr[:n]...), fmt.Errorf("faketls: чтение заголовка: %w", err)
	}
	if hdr[0] != recordHandshake {
		return append([]byte(nil), hdr[:]...), ErrNotHandshake
	}
	if hdr[1] != 0x03 || hdr[2] > 0x04 {
		return append([]byte(nil), hdr[:]...), ErrBadVersion
	}
	l := int(binary.BigEndian.Uint16(hdr[3:]))
	if l == 0 {
		return append([]byte(nil), hdr[:]...), ErrBadLength
	}
	if l > maxLen {
		return append([]byte(nil), hdr[:]...), ErrTooLarge
	}
	rec := make([]byte, recordHeaderLen+l)
	copy(rec, hdr[:])
	m, err := io.ReadFull(r, rec[recordHeaderLen:])
	if err != nil {
		return rec[:recordHeaderLen+m], fmt.Errorf("faketls: чтение тела: %w", err)
	}
	return rec, nil
}

// Parse разбирает одну TLS-запись с ClientHello (фрагментация ClientHello на
// несколько записей не поддерживается — tdlib шлёт одну).
func Parse(b []byte) (Hello, error) {
	var h Hello
	if len(b) < recordHeaderLen {
		return h, ErrBadLength
	}
	if b[0] != recordHandshake {
		return h, ErrNotHandshake
	}
	if b[1] != 0x03 || b[2] > 0x04 {
		return h, ErrBadVersion
	}
	if int(binary.BigEndian.Uint16(b[3:])) != len(b)-recordHeaderLen || len(b) == recordHeaderLen {
		return h, ErrBadLength
	}
	if len(b) < randomOffset+randomLen+1 || b[5] != typeClientHello {
		return h, ErrNotHello
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	if hsLen != len(b)-recordHeaderLen-4 {
		return h, ErrBadLength
	}
	h.Raw = b
	copy(h.Random[:], b[randomOffset:randomOffset+randomLen])

	p := parser{b: b[randomOffset+randomLen:]}
	sidLen, ok := p.u8()
	if !ok {
		return Hello{}, ErrMalformed
	}
	if h.SessionID, ok = p.take(int(sidLen)); !ok {
		return Hello{}, ErrMalformed
	}
	csLen, ok := p.u16()
	if !ok || csLen%2 != 0 {
		return Hello{}, ErrMalformed
	}
	cs, ok := p.take(int(csLen))
	if !ok {
		return Hello{}, ErrMalformed
	}
	// mtg отвергает ClientHello, где нет ни одного не-GREASE шифра.
	hasCipher := false
	for i := 0; i+1 < len(cs); i += 2 {
		if binary.BigEndian.Uint16(cs[i:])&greaseMask != greaseValue {
			hasCipher = true
			break
		}
	}
	if !hasCipher {
		return Hello{}, ErrMalformed
	}
	cmLen, ok := p.u8()
	if !ok {
		return Hello{}, ErrMalformed
	}
	if _, ok = p.take(int(cmLen)); !ok {
		return Hello{}, ErrMalformed
	}
	extLen, ok := p.u16()
	if !ok {
		return Hello{}, ErrMalformed
	}
	exts, ok := p.take(int(extLen))
	if !ok {
		return Hello{}, ErrMalformed
	}
	names, err := parseSNI(exts)
	if err != nil {
		return Hello{}, err
	}
	h.ServerNames = names
	if len(names) > 0 {
		h.SNI = names[0]
	}
	return h, nil
}

func parseSNI(exts []byte) ([]string, error) {
	p := parser{b: exts}
	for len(p.b) > 0 {
		typ, ok1 := p.u16()
		l, ok2 := p.u16()
		if !ok1 || !ok2 {
			return nil, ErrMalformed
		}
		data, ok := p.take(int(l))
		if !ok {
			return nil, ErrMalformed
		}
		if typ != 0 { // не server_name
			continue
		}
		d := parser{b: data}
		listLen, ok := d.u16()
		if !ok {
			return nil, ErrMalformed
		}
		if listLen == 0 {
			return nil, nil
		}
		kind, ok := d.u8()
		if !ok || kind != 0 {
			return nil, ErrMalformed
		}
		var names []string
		for len(d.b) > 0 {
			nl, ok := d.u16()
			if !ok {
				return nil, ErrMalformed
			}
			name, ok := d.take(int(nl))
			if !ok {
				return nil, ErrMalformed
			}
			names = append(names, string(name))
		}
		return names, nil
	}
	return nil, nil
}

type parser struct{ b []byte }

func (p *parser) take(n int) ([]byte, bool) {
	if n < 0 || n > len(p.b) {
		return nil, false
	}
	out := p.b[:n:n]
	p.b = p.b[n:]
	return out, true
}

func (p *parser) u8() (byte, bool) {
	s, ok := p.take(1)
	if !ok {
		return 0, false
	}
	return s[0], true
}

func (p *parser) u16() (uint16, bool) {
	s, ok := p.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(s), true
}
