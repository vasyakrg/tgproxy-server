package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// ErrNotSupported — реализация StreamTransport для режима связи отсутствует
// (reverse до M11-T1).
var ErrNotSupported = errors.New("transport: mtproto stream not supported")

// MTProtoPath — эндпоинт агента: POST /_agent/mtproto/dc/{dc}.
const MTProtoPath = "/_agent/mtproto/dc/"

// StreamTransport — full-duplex байтовые стримы к DC через агента. Отдельно от
// AgentTransport: другой пул соединений, другая семантика (docs/mtproto.md §4.2).
type StreamTransport interface {
	// OpenMTProto открывает стрим к DC dc и возвращает его после ответа 200
	// (агент уже соединился с DC). Ошибка — *PhaseError; отмена ctx — как есть.
	// ctx ограничивает только установку: после возврата жизнью стрима управляют
	// Close и дедлайны conn.
	OpenMTProto(ctx context.Context, agent AgentRef, dc int) (net.Conn, error)
}

// StreamStatusError — агент отказал в открытии стрима (не-200).
type StreamStatusError struct {
	AgentID string
	Status  int
}

func (e *StreamStatusError) Error() string {
	return fmt.Sprintf("transport: agent %s: mtproto stream refused: HTTP %d", e.AgentID, e.Status)
}

// deadline — как pipeDeadline в net.Pipe: ожидание срабатывания перенастраиваемого дедлайна.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{} // закрыт — дедлайн истёк
}

func newDeadline() *deadline { return &deadline{cancel: make(chan struct{})} }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // дождаться завершения сработавшего таймера
	}
	d.timer = nil
	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		d.timer = time.AfterFunc(dur, func() { close(d.cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func (d *deadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// bodyPipe — io.Pipe с дедлайном записи: тело запроса h2. Write возвращается,
// когда транспорт забрал все байты (или по дедлайну/закрытию).
type bodyPipe struct {
	wrMu     sync.Mutex
	wrTx     chan []byte
	wrRx     chan int
	wclosed  chan struct{} // CloseWrite: читателю io.EOF
	rclosed  chan struct{} // транспорт закрыл тело: писателю io.ErrClosedPipe
	wOnce    sync.Once
	rOnce    sync.Once
	wdeadl   *deadline
	closeErr error // причина rclosed, до закрытия канала
}

func newBodyPipe() *bodyPipe {
	return &bodyPipe{
		wrTx: make(chan []byte), wrRx: make(chan int),
		wclosed: make(chan struct{}), rclosed: make(chan struct{}),
		wdeadl: newDeadline(),
	}
}

func (p *bodyPipe) Write(b []byte) (int, error) {
	p.wrMu.Lock()
	defer p.wrMu.Unlock()
	switch {
	case isClosedChan(p.wclosed):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.rclosed):
		return 0, p.closeErr
	case isClosedChan(p.wdeadl.wait()):
		return 0, os.ErrDeadlineExceeded
	}
	n := 0
	for once := true; once || len(b) > 0; once = false {
		select {
		case p.wrTx <- b:
			nw := <-p.wrRx
			b = b[nw:]
			n += nw
		case <-p.wclosed:
			return n, io.ErrClosedPipe
		case <-p.rclosed:
			return n, p.closeErr
		case <-p.wdeadl.wait():
			return n, os.ErrDeadlineExceeded
		}
	}
	return n, nil
}

// Read вызывает транспорт h2.
func (p *bodyPipe) Read(b []byte) (int, error) {
	select {
	case <-p.rclosed:
		return 0, io.ErrClosedPipe
	default:
	}
	select {
	case bw := <-p.wrTx:
		nr := copy(b, bw)
		p.wrRx <- nr
		return nr, nil
	case <-p.wclosed:
		return 0, io.EOF
	case <-p.rclosed:
		return 0, io.ErrClosedPipe
	}
}

// Close вызывает транспорт h2 по завершении запроса.
func (p *bodyPipe) Close() error {
	p.abort(io.ErrClosedPipe)
	return nil
}

func (p *bodyPipe) abort(err error) {
	p.rOnce.Do(func() {
		p.closeErr = err
		close(p.rclosed)
	})
}

func (p *bodyPipe) closeWrite() {
	p.wOnce.Do(func() { close(p.wclosed) })
}

type readResult struct {
	n   int
	err error
}

const pumpBuf = 32 << 10

// streamConn — net.Conn поверх h2-стрима: запись -> тело запроса, чтение <-
// тело ответа. Чтение идёт через pump-горутину: так работает дедлайн чтения
// (Read h2-тела не прерывается ничем, кроме закрытия стрима).
type streamConn struct {
	body   io.ReadCloser
	wp     *bodyPipe
	cancel context.CancelFunc

	local, remote *net.TCPAddr

	chunks   chan readResult
	ack      chan struct{}
	closed   chan struct{} // Close
	pumpDone chan struct{}
	buf      []byte

	rdMu     sync.Mutex // сериализует Read; защищает cur/off/rerr
	cur      readResult
	off      int
	pending  bool // выдан chunk, ack ещё не отправлен
	readDead *deadline
	rclosed  chan struct{} // CloseRead
	rcOnce   sync.Once
	closeMu  sync.Once
}

var _ net.Conn = (*streamConn)(nil)

func newStreamConn(body io.ReadCloser, wp *bodyPipe, cancel context.CancelFunc, local, remote *net.TCPAddr) *streamConn {
	c := &streamConn{
		body: body, wp: wp, cancel: cancel, local: local, remote: remote,
		chunks: make(chan readResult), ack: make(chan struct{}),
		closed: make(chan struct{}), pumpDone: make(chan struct{}),
		buf: make([]byte, pumpBuf), readDead: newDeadline(), rclosed: make(chan struct{}),
	}
	go c.pump()
	return c
}

// pump читает тело ответа; после CloseRead продолжает читать и выбрасывать
// байты, чтобы не сбросить стрим (RST закрыл бы и запись).
func (c *streamConn) pump() {
	defer close(c.pumpDone)
	for {
		n, err := c.body.Read(c.buf)
		if isClosedChan(c.rclosed) {
			if err != nil {
				return
			}
			continue
		}
		select {
		case c.chunks <- readResult{n, err}:
		case <-c.rclosed:
			if err != nil {
				return
			}
			continue
		case <-c.closed:
			return
		}
		if err != nil {
			return
		}
		select {
		case <-c.ack:
		case <-c.rclosed:
		case <-c.closed:
			return
		}
	}
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.rdMu.Lock()
	defer c.rdMu.Unlock()
	if isClosedChan(c.closed) || isClosedChan(c.rclosed) {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	for c.off >= c.cur.n {
		if c.pending {
			c.pending = false
			select {
			case c.ack <- struct{}{}:
			case <-c.pumpDone:
			case <-c.closed:
				return 0, net.ErrClosed
			}
		}
		if c.cur.err != nil {
			return 0, c.cur.err
		}
		select {
		case r := <-c.chunks:
			c.cur, c.off, c.pending = r, 0, true
		case <-c.pumpDone:
			if c.cur.err != nil {
				return 0, c.cur.err
			}
			return 0, io.ErrUnexpectedEOF
		case <-c.readDead.wait():
			return 0, os.ErrDeadlineExceeded
		case <-c.rclosed:
			return 0, net.ErrClosed
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(p, c.buf[c.off:c.cur.n])
	c.off += n
	return n, nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	if isClosedChan(c.closed) {
		return 0, net.ErrClosed
	}
	return c.wp.Write(p)
}

// CloseWrite завершает тело запроса (END_STREAM): агент видит EOF и закрывает
// запись в DC; чтение продолжает работать.
func (c *streamConn) CloseWrite() error {
	c.wp.closeWrite()
	return nil
}

// CloseRead прекращает чтение: байты от DC дальше отбрасываются, запись
// продолжает работать (закрытие тела ответа сбросило бы весь стрим).
func (c *streamConn) CloseRead() error {
	c.rcOnce.Do(func() { close(c.rclosed) })
	return nil
}

// Close закрывает оба направления и сбрасывает стрим. Идемпотентен.
func (c *streamConn) Close() error {
	c.closeMu.Do(func() {
		close(c.closed)
		c.wp.closeWrite()
		c.wp.abort(net.ErrClosed)
		c.cancel()
		_ = c.body.Close()
		<-c.pumpDone
		c.readDead.stop()
		c.wp.wdeadl.stop()
	})
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	if isClosedChan(c.closed) {
		return net.ErrClosed
	}
	c.readDead.set(t)
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	if isClosedChan(c.closed) {
		return net.ErrClosed
	}
	c.wp.wdeadl.set(t)
	return nil
}

// tcpAddr приводит адрес соединения к *net.TCPAddr (h2 поверх TLS поверх TCP);
// нетиповой адрес заменяется нулевым, чтобы тип был стабильным.
func tcpAddr(a net.Addr) *net.TCPAddr {
	if t, ok := a.(*net.TCPAddr); ok && t != nil {
		return t
	}
	return &net.TCPAddr{}
}
