package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// Conn — открытая сессия probe: FakeTLS + obfuscated2 уже пройдены, поверх можно
// многократно обмениваться req_pq_multi/resPQ. Нужна интеграционным тестам
// (долгоживущие соединения, отзыв секрета, нагрузка).
type Conn struct {
	conn net.Conn
	s    *session
}

// Dial проходит рукопожатие как Run, но не закрывает соединение. Дедлайн ctx
// ограничивает только установку.
func Dial(ctx context.Context, addr string, key [16]byte, domain string, dc int) (*Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("probe: подключение к прокси: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	s, err := handshake(conn, key, domain, dc)
	if err != nil {
		_ = conn.Close()
		return nil, ctxErr(ctx, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &Conn{conn: conn, s: s}, nil
}

// Exchange отправляет req_pq_multi и ждёт resPQ с тем же nonce не дольше timeout.
func (c *Conn) Exchange(timeout time.Duration) error {
	_ = c.conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("probe: rand: %w", err)
	}
	if err := c.s.writePacket(unencryptedMessage(msgIDAt(time.Now(), 0x4), reqPQMulti(nonce))); err != nil {
		return fmt.Errorf("probe: отправка req_pq_multi: %w", err)
	}
	pkt, err := c.s.readPacket()
	if err != nil {
		return fmt.Errorf("probe: чтение resPQ: %w", err)
	}
	_, body, err := parseUnencrypted(pkt)
	if err != nil || len(body) < 20 || binary.LittleEndian.Uint32(body) != ctorResPQ {
		return errors.New("probe: ответ DC не resPQ")
	}
	if !bytes.Equal(body[4:20], nonce[:]) {
		return errors.New("probe: nonce в resPQ не совпал")
	}
	return nil
}

// WritePacket отправляет один пакет (длина + payload) в obfuscated2-потоке.
// Вместе с ReadPacket допускает по одной горутине на запись и на чтение
// (конвейерный обмен для нагрузочных тестов); дедлайны — на вызывающем (SetDeadline).
func (c *Conn) WritePacket(p []byte) error { return c.s.writePacket(p) }

// ReadPacket читает один пакет (см. WritePacket).
func (c *Conn) ReadPacket() ([]byte, error) { return c.s.readPacket() }

// SetDeadline задаёт дедлайн чтения и записи соединения.
func (c *Conn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// Close закрывает соединение.
func (c *Conn) Close() error { return c.conn.Close() }

// ClientHello строит запись FakeTLS ClientHello с HMAC для key (тесты replay:
// отправить одни и те же байты дважды).
func ClientHello(key [16]byte, domain string, now time.Time) []byte {
	rec, _ := buildClientHello(key[:], domain, now)
	return rec
}
