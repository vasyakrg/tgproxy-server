package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// FakeDC — TCP-сервер, имитирующий DC Telegram: принимает obfuscated2
// (без секрета, ключ/IV из открытых байт 8..56) и на req_pq_multi отвечает
// resPQ с тем же nonce. Предназначен для тестов и dev-стенда.
type FakeDC struct {
	ln net.Listener
	wg sync.WaitGroup

	accepted atomic.Int64
	answered atomic.Int64
	lastDC   atomic.Int64
}

const fakeDCReadTimeout = 30 * time.Second

// NewFakeDC слушает 127.0.0.1:0 и возвращает сервер и его адрес.
func NewFakeDC() (*FakeDC, string, error) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	d := &FakeDC{ln: ln}
	d.wg.Add(1)
	go d.loop()
	return d, ln.Addr().String(), nil
}

// Addr — адрес прослушивания.
func (d *FakeDC) Addr() string { return d.ln.Addr().String() }

// Accepted — число принятых соединений.
func (d *FakeDC) Accepted() int { return int(d.accepted.Load()) }

// Answered — число отправленных resPQ.
func (d *FakeDC) Answered() int { return int(d.answered.Load()) }

// LastDC — DC (после abs не применяется: со знаком) из последнего handshake.
func (d *FakeDC) LastDC() int { return int(d.lastDC.Load()) }

// Close останавливает сервер и ждёт завершения обработчиков.
func (d *FakeDC) Close() error {
	err := d.ln.Close()
	d.wg.Wait()
	return err
}

func (d *FakeDC) loop() {
	defer d.wg.Done()
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	var cw sync.WaitGroup
	defer func() {
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		cw.Wait()
	}()
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
		cw.Add(1)
		go func() {
			defer cw.Done()
			defer func() {
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
				_ = c.Close()
			}()
			d.handle(c)
		}()
	}
}

func (d *FakeDC) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(fakeDCReadTimeout))
	var frame [64]byte
	if _, err := io.ReadFull(c, frame[:]); err != nil {
		return
	}
	recv := newCTR(frame[8:40], frame[40:56])
	var dec [64]byte
	recv.XORKeyStream(dec[:], frame[:])
	if !bytes.Equal(dec[56:60], bytes.Repeat([]byte{tagPaddedIntermediate}, 4)) {
		return
	}
	rev := slices.Clone(frame[8:56])
	slices.Reverse(rev)
	send := newCTR(rev[0:32], rev[32:48])
	d.accepted.Add(1)
	d.lastDC.Store(int64(signedDC(binary.LittleEndian.Uint16(dec[60:62]))))

	readN := func(n int) ([]byte, error) {
		b := make([]byte, n)
		if _, err := io.ReadFull(c, b); err != nil {
			return nil, err
		}
		recv.XORKeyStream(b, b)
		return b, nil
	}
	for {
		h, err := readN(4)
		if err != nil {
			return
		}
		n := int(binary.LittleEndian.Uint32(h))
		if n < 1 || n > maxPacket {
			return
		}
		pkt, err := readN(n)
		if err != nil {
			return
		}
		_, body, err := parseUnencrypted(pkt)
		if err != nil || len(body) < 20 || binary.LittleEndian.Uint32(body) != ctorReqPQMulti {
			return
		}
		msg, err := resPQ(body[4:20])
		if err != nil {
			return
		}
		out := append(binary.LittleEndian.AppendUint32(nil, u32(len(msg))), msg...)
		send.XORKeyStream(out, out)
		if _, err := c.Write(out); err != nil {
			return
		}
		d.answered.Add(1)
	}
}

// resPQ собирает незашифрованное сообщение resPQ с заданным nonce.
func resPQ(nonce []byte) ([]byte, error) {
	var serverNonce [16]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		return nil, err
	}
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, ctorResPQ)
	b = append(b, nonce...)
	b = append(b, serverNonce[:]...)
	b = append(b, 8, 0x17, 0xed, 0x48, 0x94, 0x1a, 0x08, 0xf9, 0x81, 0, 0, 0) // pq: TL bytes(8) + паддинг до 12
	b = binary.LittleEndian.AppendUint32(b, ctorVectorLong)
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint64(b, 0xc3b42b026ce86b21) // fingerprint
	msgID := msgIDAt(time.Now(), 0x1)                           // серверный msg_id: ≡ 1 (mod 4)
	return unencryptedMessage(msgID, b), nil
}
