// Package mux разводит соединения общего TCP-листенера: валидный FakeTLS-клиент
// MTProto уходит в Route.Serve, всё остальное (в том числе отказы по HMAC,
// SNI, timestamp) без изменений отдаётся TLS-обработчику через Accept.
package mux

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/mtproto/faketls"
)

// Reason — причина закрытия соединения muxListener-ом.
type Reason string

// Причины закрытия, передаваемые в Hooks.OnReject.
const (
	ReasonConnLimit        Reason = "conn_limit"        // превышен лимит соединений/IP/рукопожатий
	ReasonHandshakeTimeout Reason = "handshake_timeout" // первая запись не пришла вовремя
	ReasonBadRecord        Reason = "bad_record"        // клиент ушёл, не дослав первую запись
)

// Router отдаёт согласованный снимок секретов; nil — MTProto сейчас недоступен
// (нет секретов/capable-агентов) → fallthrough.
type Router interface{ Route() Route }

// Route — неизменяемый снимок секретов на время одного соединения.
type Route interface {
	Keys() [][16]byte
	Domain() string
	Skew() time.Duration
	Serve(idx int, conn net.Conn) // блокирует до конца MTProto-соединения
}

// Hooks — точки наблюдения; любая может быть nil.
type Hooks struct {
	Banned        func(netip.Addr) bool // до чтения ClientHello
	OnReject      func(netip.Addr, Reason)
	OnFallthrough func()
}

// Options — лимиты и таймауты; нулевые значения заменяются дефолтами.
type Options struct {
	MaxConns             int           // глобально (20000)
	MaxConnsPerIP        int           // на IP, включая активные MTProto (64)
	MaxPendingHandshakes int           // незавершённые рукопожатия (1024)
	HandshakeTimeout     time.Duration // чтение первой записи (10s)
	Now                  func() time.Time
	Logger               *slog.Logger
}

func (o *Options) setDefaults() {
	if o.MaxConns <= 0 {
		o.MaxConns = 20000
	}
	if o.MaxConnsPerIP <= 0 {
		o.MaxConnsPerIP = 64
	}
	if o.MaxPendingHandshakes <= 0 {
		o.MaxPendingHandshakes = 1024
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
}

// Listener — net.Listener, чей Accept отдаёт только fallthrough-соединения.
type Listener struct {
	inner  net.Listener
	front  net.Listener
	router Router
	hooks  Hooks
	opts   Options
	lim    *limits

	out    chan net.Conn
	done   chan struct{}
	failed chan struct{}
	errMu  sync.Mutex
	err    error

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

// New запускает приём на inner и fronting-листенер на 127.0.0.1:0.
func New(inner net.Listener, router Router, hooks Hooks, opts Options) (*Listener, error) {
	if inner == nil || router == nil {
		return nil, errors.New("mux: inner и router обязательны")
	}
	opts.setDefaults()
	front, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("mux: fronting-листенер: %w", err)
	}
	l := &Listener{
		inner: inner, front: front, router: router, hooks: hooks, opts: opts,
		lim:    newLimits(opts.MaxConns, opts.MaxConnsPerIP, opts.MaxPendingHandshakes),
		out:    make(chan net.Conn),
		done:   make(chan struct{}),
		failed: make(chan struct{}),
		conns:  make(map[net.Conn]struct{}),
	}
	l.wg.Add(2)
	go l.acceptLoop()
	go l.frontingLoop()
	return l, nil
}

// Accept возвращает следующее fallthrough-соединение.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.out:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.failed:
		l.errMu.Lock()
		defer l.errMu.Unlock()
		return nil, l.err
	}
}

// Addr — адрес внешнего листенера.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Close закрывает оба листенера и все соединения в рукопожатии/MTProto и ждёт горутины.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	conns := make([]net.Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()

	err := l.inner.Close()
	_ = l.front.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	l.wg.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (l *Listener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// spawn запускает f в учтённой горутине; false — листенер закрыт.
func (l *Listener) spawn(f func()) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		f()
	}()
	return true
}

func (l *Listener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.conns[c] = struct{}{}
	return true
}

func (l *Listener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

// deliver отдаёт соединение в Accept; при закрытии листенера закрывает его.
func (l *Listener) deliver(c net.Conn) {
	select {
	case l.out <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// acceptRetry решает, продолжать ли цикл после ошибки Accept (с паузой).
func (l *Listener) acceptRetry(err error) bool {
	var ne net.Error
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		(errors.As(err, &ne) && ne.Timeout()) {
		l.opts.Logger.Warn("mux: временная ошибка accept", "err", err)
		select {
		case <-time.After(50 * time.Millisecond):
			return true
		case <-l.done:
			return false
		}
	}
	return false
}

func (l *Listener) acceptLoop() {
	defer l.wg.Done()
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			if l.isClosed() {
				return
			}
			if l.acceptRetry(err) {
				continue
			}
			l.errMu.Lock()
			l.err = err
			l.errMu.Unlock()
			close(l.failed)
			return
		}
		if !l.spawn(func() { l.handle(raw) }) {
			_ = raw.Close()
			return
		}
	}
}

func (l *Listener) reject(ip netip.Addr, r Reason) {
	if l.hooks.OnReject != nil {
		l.hooks.OnReject(ip, r)
	}
}

func (l *Listener) handOff(c net.Conn) {
	if l.hooks.OnFallthrough != nil {
		l.hooks.OnFallthrough()
	}
	l.deliver(c)
}

// handle ведёт одно соединение: бан → лимиты → первая запись → разводка.
func (l *Listener) handle(raw net.Conn) {
	ip, ok := addrOf(raw.RemoteAddr())
	if !ok {
		_ = raw.Close()
		return
	}
	if l.hooks.Banned != nil && l.hooks.Banned(ip) {
		_ = raw.Close()
		return
	}
	if !l.lim.admit(ip) {
		l.reject(ip, ReasonConnLimit)
		_ = raw.Close()
		return
	}
	pending, held := true, true
	// freeSlots идемпотентно освобождает слоты; для fallthrough вызывается до
	// передачи соединения TLS-обработчику, иначе — при выходе из handle.
	freeSlots := func() {
		if pending {
			l.lim.handshakeDone()
			pending = false
		}
		if held {
			l.lim.release(ip)
			held = false
		}
	}
	defer freeSlots()
	if !l.track(raw) {
		_ = raw.Close()
		return
	}
	tracked := true
	defer func() {
		if tracked {
			l.untrack(raw)
		}
	}()

	_ = raw.SetReadDeadline(time.Now().Add(l.opts.HandshakeTimeout))
	rec, err := faketls.ReadFirstRecord(raw, faketls.MaxRecord)
	_ = raw.SetReadDeadline(time.Time{})
	if err != nil && !isFormatErr(err) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			l.reject(ip, ReasonHandshakeTimeout)
		} else {
			l.reject(ip, ReasonBadRecord)
		}
		_ = raw.Close()
		return
	}
	rc := newReplayConn(raw, rec)

	idx, route := -1, Route(nil)
	if err == nil {
		route = l.router.Route()
		if route != nil {
			if h, perr := faketls.Parse(rec); perr == nil {
				if i, matched := faketls.Match(h, route.Keys(), route.Domain(), l.opts.Now(), route.Skew()); matched {
					idx = i
				}
			}
		}
	}

	if idx < 0 {
		l.untrack(raw)
		tracked = false
		freeSlots()
		l.handOff(rc)
		return
	}

	l.lim.handshakeDone()
	pending = false
	l.serve(route, idx, rc, ip)
}

func (l *Listener) serve(route Route, idx int, c *replayConn, ip netip.Addr) {
	defer func() {
		if r := recover(); r != nil {
			l.opts.Logger.Error("mux: паника в MTProto-обработчике", "panic", fmt.Sprint(r), "ip", ip.String())
		}
		_ = c.Close()
	}()
	route.Serve(idx, c)
}

func isFormatErr(err error) bool {
	return errors.Is(err, faketls.ErrNotHandshake) || errors.Is(err, faketls.ErrBadVersion) ||
		errors.Is(err, faketls.ErrBadLength) || errors.Is(err, faketls.ErrTooLarge)
}
