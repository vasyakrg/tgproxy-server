// Package trace связывает клиентское MTProto-соединение со стримом к агенту и
// определяет, какая сторона завершила relay первой (диагностика журнала сессий).
//
// mtglib не передаёт в Network.Dial ни контекст, ни id потока, но ServeConn,
// Dial и отправка событий идут синхронно в одной горутине. Поэтому соединение
// регистрируется по id горутины на время ServeConn: Dial и события находят его
// через Current. В чужой горутине Current возвращает nil, и все методы *Conn
// безопасны для nil — диагностика тогда просто пропадает.
package trace

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/9seconds/mtg/v2/essentials"
)

// Причины завершения соединения (mtproto_sessions.close_reason).
const (
	ReasonClientEOF     = "client_eof"     // клиент закрыл соединение
	ReasonClientError   = "client_error"   // ошибка сокета клиента (RST, обрыв)
	ReasonUpstreamEOF   = "upstream_eof"   // агент/DC завершил стрим
	ReasonUpstreamError = "upstream_error" // ошибка стрима к агенту
	ReasonIdle          = "idle_timeout"   // mtg: нет трафика idle_timeout
	ReasonServer        = "server_close"   // закрыто сервером: отзыв секрета, остановка
	ReasonDialFailed    = "dial_failed"    // ни один агент не открыл стрим к DC
	ReasonNotConnected  = "not_connected"  // завершено до выбора агента (рукопожатие)
	ReasonUnknown       = "closed"         // причина не определена
)

// Направления relay mtg: какой pump завершился первым.
const (
	toTelegram = 1 // клиент → Telegram
	toClient   = 2 // Telegram → клиент
)

// Conn — диагностика одного клиентского соединения.
type Conn struct {
	agent     atomic.Pointer[string]
	connected atomic.Bool
	reason    atomic.Pointer[string]

	// Последняя ошибка каждой операции; успешное чтение сбрасывает ошибку
	// чтения (таймаут дедлайна, который mtg повторяет, не считается).
	clientRead, clientWrite atomic.Pointer[error]
	upRead, upWrite         atomic.Pointer[error]
}

// Agent — агент последнего Dial ("" — Dial не было).
func (c *Conn) Agent() string {
	if c == nil {
		return ""
	}
	if p := c.agent.Load(); p != nil {
		return *p
	}
	return ""
}

// Dial фиксирует попытку открыть стрим через agent; ok — стрим открыт.
func (c *Conn) Dial(agent string, ok bool) {
	if c == nil {
		return
	}
	c.agent.Store(&agent)
	if ok {
		c.connected.Store(true)
	}
}

// Reason — причина завершения; вызывается после конца relay.
func (c *Conn) Reason() string {
	if c == nil {
		return ReasonUnknown
	}
	if p := c.reason.Load(); p != nil {
		return *p
	}
	switch {
	case c.connected.Load():
		return ReasonUnknown
	case c.agent.Load() != nil:
		return ReasonDialFailed
	}
	return ReasonNotConnected
}

// shutdown вызывается на первом half-close mtg: dir — завершившийся pump.
// Причина — ошибка, на которой он остановился (чтение источника или запись приёмника).
func (c *Conn) shutdown(dir int) {
	if c == nil || c.reason.Load() != nil || !c.connected.Load() {
		return
	}
	var r string
	if dir == toTelegram {
		r = classify(c.clientRead.Load(), ReasonClientEOF, ReasonClientError)
		if r == "" {
			r = classify(c.upWrite.Load(), ReasonUpstreamEOF, ReasonUpstreamError)
		}
	} else {
		r = classify(c.upRead.Load(), ReasonUpstreamEOF, ReasonUpstreamError)
		if r == "" {
			r = classify(c.clientWrite.Load(), ReasonClientEOF, ReasonClientError)
		}
	}
	if r == "" {
		r = ReasonUnknown
	}
	c.reason.CompareAndSwap(nil, &r)
}

func classify(p *error, eof, other string) string {
	if p == nil {
		return ""
	}
	err := *p
	var ne net.Error
	switch {
	case errors.Is(err, io.EOF):
		return eof
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ReasonIdle
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		return ReasonServer
	}
	return other
}

func record(slot *atomic.Pointer[error], n int, err error) {
	switch {
	case err != nil:
		slot.Store(&err)
	case n > 0:
		slot.Store(nil)
	}
}

// Upstream вызывается обёрткой стрима к агенту на каждой операции.
func (c *Conn) Upstream(read bool, n int, err error) {
	if c == nil {
		return
	}
	if read {
		record(&c.upRead, n, err)
	} else {
		record(&c.upWrite, n, err)
	}
}

// UpstreamCloseRead — mtg вызывает его, когда завершился pump клиент → Telegram.
func (c *Conn) UpstreamCloseRead() { c.shutdown(toTelegram) }

// UpstreamCloseWrite — mtg вызывает его, когда завершился pump Telegram → клиент.
func (c *Conn) UpstreamCloseWrite() { c.shutdown(toClient) }

// WrapClient оборачивает клиентское соединение, переданное в ServeConn.
func (c *Conn) WrapClient(conn essentials.Conn) essentials.Conn {
	if c == nil {
		return conn
	}
	return &clientConn{Conn: conn, t: c}
}

type clientConn struct {
	essentials.Conn
	t *Conn
}

func (c *clientConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	record(&c.t.clientRead, n, err)
	return n, err
}

func (c *clientConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	record(&c.t.clientWrite, n, err)
	return n, err
}

// CloseRead: pump mtg Telegram → клиент завершился.
func (c *clientConn) CloseRead() error {
	c.t.shutdown(toClient)
	return c.Conn.CloseRead()
}

// CloseWrite: pump mtg клиент → Telegram завершился.
func (c *clientConn) CloseWrite() error {
	c.t.shutdown(toTelegram)
	return c.Conn.CloseWrite()
}

// Registry — соединения по id горутины ServeConn.
type Registry struct {
	m sync.Map // uint64 → *Conn
}

// Bind регистрирует новое соединение за текущей горутиной; unbind снимает.
func (r *Registry) Bind() (c *Conn, unbind func()) {
	if r == nil {
		return nil, func() {}
	}
	id := goid()
	c = &Conn{}
	r.m.Store(id, c)
	return c, func() { r.m.CompareAndDelete(id, c) }
}

// Current — соединение текущей горутины или nil.
func (r *Registry) Current() *Conn {
	if r == nil {
		return nil
	}
	if v, ok := r.m.Load(goid()); ok {
		return v.(*Conn)
	}
	return nil
}

var goroutinePrefix = []byte("goroutine ")

// goid — id текущей горутины из первой строки runtime.Stack ("goroutine N [...").
func goid() uint64 {
	var buf [64]byte
	b := bytes.TrimPrefix(buf[:runtime.Stack(buf[:], false)], goroutinePrefix)
	if i := bytes.IndexByte(b, ' '); i > 0 {
		b = b[:i]
	}
	id, _ := strconv.ParseUint(string(b), 10, 64)
	return id
}
