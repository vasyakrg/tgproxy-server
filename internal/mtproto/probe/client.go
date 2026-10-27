package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// DefaultDC — DC, к которому ходит Run.
	DefaultDC = 2

	defaultTimeout = 10 * time.Second
	randomOffset   = 11 // 5 (заголовок записи) + 4 (заголовок handshake) + 2 (версия)

	recHandshake = 0x16
	recCCS       = 0x14
	recAppData   = 0x17
)

// Result — итог пробы.
type Result struct {
	RTT         time.Duration // от начала dial до получения resPQ
	DCResponded bool          // DC ответил валидным resPQ с нашим nonce
}

// Run проходит FakeTLS-рукопожатие с прокси на addr, затем obfuscated2 к DC 2
// и обменивается req_pq_multi/resPQ. Все операции ограничены дедлайном ctx
// (без дедлайна — 10 с). Ключ в ошибки не попадает.
func Run(ctx context.Context, addr string, key [16]byte, domain string) (Result, error) {
	return RunDC(ctx, addr, key, domain, DefaultDC)
}

// RunDC — как Run, но к указанному DC (отрицательный — media).
func RunDC(ctx context.Context, addr string, key [16]byte, domain string, dc int) (Result, error) {
	start := time.Now()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("probe: подключение к прокси: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	s, err := handshake(conn, key, domain, dc)
	if err != nil {
		return Result{}, ctxErr(ctx, err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Result{}, fmt.Errorf("probe: rand: %w", err)
	}
	msgID := msgIDAt(time.Now(), 0x4) // клиентский msg_id кратен 4
	if err := s.writePacket(unencryptedMessage(msgID, reqPQMulti(nonce))); err != nil {
		return Result{}, ctxErr(ctx, fmt.Errorf("probe: отправка req_pq_multi: %w", err))
	}
	pkt, err := s.readPacket()
	if err != nil {
		return Result{}, ctxErr(ctx, fmt.Errorf("probe: чтение resPQ: %w", err))
	}
	_, body, err := parseUnencrypted(pkt)
	if err != nil || len(body) < 20 || binary.LittleEndian.Uint32(body) != ctorResPQ {
		return Result{}, errors.New("probe: ответ DC не resPQ")
	}
	if !bytes.Equal(body[4:20], nonce[:]) {
		return Result{}, errors.New("probe: nonce в resPQ не совпал")
	}
	return Result{RTT: time.Since(start), DCResponded: true}, nil
}

func ctxErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%w: %w", cerr, err)
	}
	return err
}

// session — obfuscated2-поток поверх записей ApplicationData FakeTLS.
type session struct {
	conn    net.Conn
	br      *bufio.Reader
	send    cipher.Stream
	recv    cipher.Stream
	pending []byte
}

func handshake(conn net.Conn, key [16]byte, domain string, dc int) (*session, error) {
	hello, clientRandom := buildClientHello(key[:], domain, time.Now())
	if _, err := conn.Write(hello); err != nil {
		return nil, fmt.Errorf("probe: отправка ClientHello: %w", err)
	}
	br := bufio.NewReader(conn)
	if err := readServerHello(br, key[:], clientRandom); err != nil {
		return nil, err
	}
	wire, send, recv, err := obfuscatedClient(key[:], dc)
	if err != nil {
		return nil, err
	}
	s := &session{conn: conn, br: br, send: send, recv: recv}
	if err := writeRecord(conn, recAppData, wire); err != nil {
		return nil, fmt.Errorf("probe: отправка obfuscated2: %w", err)
	}
	return s, nil
}

func be16(v int) []byte { return binary.BigEndian.AppendUint16(nil, u16(v)) }

// buildClientHello строит запись ClientHello; random = HMAC-SHA256(key, запись
// с нулевым random), последние 4 байта XOR LE-timestamp (схема mtg/FakeTLS).
func buildClientHello(key []byte, sni string, now time.Time) (rec, random []byte) {
	name := []byte(sni)
	entry := append([]byte{0}, be16(len(name))...)
	entry = append(entry, name...)
	list := append(be16(len(entry)), entry...)
	ext := append(append(be16(0), be16(len(list))...), list...)
	exts := append(be16(len(ext)), ext...)

	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		panic(err)
	}
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, u8(len(sid)))
	body = append(body, sid...)
	body = append(body, be16(4)...)
	body = append(body, 0x0a, 0x0a, 0x13, 0x01) // GREASE + TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)
	body = append(body, exts...)

	hs := []byte{0x01, u8(len(body) >> 16), u8(len(body) >> 8), u8(len(body))}
	hs = append(hs, body...)
	rec = append([]byte{recHandshake, 0x03, 0x01}, be16(len(hs))...)
	rec = append(rec, hs...)

	mac := hmac.New(sha256.New, key)
	mac.Write(rec)
	random = mac.Sum(nil)
	ts := binary.LittleEndian.AppendUint32(nil, unix32(now))
	for i := range 4 {
		random[28+i] ^= ts[i]
	}
	copy(rec[randomOffset:], random)
	return rec, random
}

func readRecord(r io.Reader) (typ byte, hdr, body []byte, err error) {
	var h [5]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return 0, nil, nil, err
	}
	n := int(binary.BigEndian.Uint16(h[3:]))
	body = make([]byte, n)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, nil, nil, err
	}
	return h[0], h[:], body, nil
}

func writeRecord(w io.Writer, typ byte, p []byte) error {
	rec := append([]byte{typ, 0x03, 0x03}, be16(len(p))...)
	_, err := w.Write(append(rec, p...))
	return err
}

// readServerHello читает ServerHello+CCS+ApplicationData и сверяет серверный
// HMAC = HMAC(key, clientRandom || все три записи с нулевым random).
// Это отличает mtg с нашим секретом от настоящего сайта (fronting).
func readServerHello(r io.Reader, key, clientRandom []byte) error {
	var all []byte
	for i, want := range []byte{recHandshake, recCCS, recAppData} {
		typ, hdr, body, err := readRecord(r)
		if err != nil {
			return fmt.Errorf("probe: чтение ответа прокси (запись %d): %w", i+1, err)
		}
		if typ != want {
			return fmt.Errorf("probe: рукопожатие FakeTLS не принято (запись %d, тип %#x): неверный секрет или не MTProto-прокси", i+1, typ)
		}
		all = append(all, hdr...)
		all = append(all, body...)
	}
	if len(all) < randomOffset+32 {
		return errors.New("probe: слишком короткий ServerHello")
	}
	got := bytes.Clone(all[randomOffset : randomOffset+32])
	clear(all[randomOffset : randomOffset+32])
	mac := hmac.New(sha256.New, key)
	mac.Write(clientRandom)
	mac.Write(all)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("probe: HMAC ServerHello не совпал: неверный секрет")
	}
	return nil
}

func (s *session) writePacket(p []byte) error {
	buf := binary.LittleEndian.AppendUint32(nil, u32(len(p)))
	buf = append(buf, p...)
	enc := make([]byte, len(buf))
	s.send.XORKeyStream(enc, buf)
	return writeRecord(s.conn, recAppData, enc)
}

func (s *session) readN(n int) ([]byte, error) {
	for len(s.pending) < n {
		typ, _, body, err := readRecord(s.br)
		if err != nil {
			return nil, err
		}
		if typ != recAppData {
			continue
		}
		dec := make([]byte, len(body))
		s.recv.XORKeyStream(dec, body)
		s.pending = append(s.pending, dec...)
	}
	out := s.pending[:n:n]
	s.pending = s.pending[n:]
	return out, nil
}

func (s *session) readPacket() ([]byte, error) {
	h, err := s.readN(4)
	if err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint32(h))
	if n < 1 || n > maxPacket {
		return nil, errBadFrame
	}
	return s.readN(n)
}
