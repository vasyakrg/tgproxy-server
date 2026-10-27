package mux

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testDomain = "front.example.test"

func be16(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }

// helloFor строит ClientHello с валидным HMAC для key (схема FakeTLS).
func helloFor(key [16]byte, sni string, ts time.Time) []byte {
	name := []byte(sni)
	entry := append([]byte{0}, be16(len(name))...)
	entry = append(entry, name...)
	list := append(be16(len(entry)), entry...)
	ext := append(append(be16(0), be16(len(list))...), list...)
	exts := append(be16(len(ext)), ext...)

	sid := make([]byte, 32)
	_, _ = rand.Read(sid)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(sid)))
	body = append(body, sid...)
	body = append(body, be16(4)...)
	body = append(body, 0x0a, 0x0a, 0x13, 0x01, 0x01, 0x00)
	body = append(body, exts...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, be16(len(hs))...)
	rec = append(rec, hs...)

	mac := hmac.New(sha256.New, key[:])
	mac.Write(rec)
	random := mac.Sum(nil)
	t := binary.LittleEndian.AppendUint32(nil, uint32(ts.Unix()))
	for i := range 4 {
		random[28+i] ^= t[i]
	}
	copy(rec[11:], random)
	return rec
}

type served struct {
	idx  int
	conn net.Conn
}

type fakeRoute struct {
	keys   [][16]byte
	serve  func(idx int, c net.Conn)
	called chan served
	// limits[i] — ограничения секрета i; нет записи — без ограничений, id = i+1.
	limits map[int]secretLim
}

type secretLim struct {
	id    int64
	cidrs []netip.Prefix
	max   int
}

func (r *fakeRoute) Limits(i int) (int64, []netip.Prefix, int) {
	if l, ok := r.limits[i]; ok {
		return l.id, l.cidrs, l.max
	}
	return int64(i + 1), nil, 0
}

func (r *fakeRoute) Keys() [][16]byte    { return r.keys }
func (r *fakeRoute) Domain() string      { return testDomain }
func (r *fakeRoute) Skew() time.Duration { return 2 * time.Minute }
func (r *fakeRoute) Serve(i int, c net.Conn) {
	if r.called != nil {
		r.called <- served{i, c}
	}
	if r.serve != nil {
		r.serve(i, c)
	}
}

type fakeRouter struct {
	mu sync.Mutex
	r  Route
	n  atomic.Int32
}

func (f *fakeRouter) Route() Route {
	f.n.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.r
}

type rec struct {
	mu       sync.Mutex
	rejects  map[Reason]int
	falls    atomic.Int32
	banned   map[netip.Addr]bool
	bannedCh atomic.Int32
}

func newRec() *rec { return &rec{rejects: map[Reason]int{}, banned: map[netip.Addr]bool{}} }

func (r *rec) hooks() Hooks {
	return Hooks{
		Banned: func(a netip.Addr) bool {
			r.bannedCh.Add(1)
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.banned[a]
		},
		OnReject: func(_ netip.Addr, reason Reason) {
			r.mu.Lock()
			r.rejects[reason]++
			r.mu.Unlock()
		},
		OnFallthrough: func() { r.falls.Add(1) },
	}
}

func (r *rec) rejectCount(x Reason) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rejects[x]
}

func startMux(t *testing.T, router Router, hooks Hooks, opts Options) *Listener {
	t.Helper()
	inner, err := listenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(inner, router, hooks, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func dial(t *testing.T, l *Listener) *net.TCPConn {
	t.Helper()
	c, err := dialAddr(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.TCPConn)
}

// acceptOne принимает одно fallthrough-соединение или падает по таймауту.
func acceptOne(t *testing.T, l *Listener) net.Conn {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := l.Accept(); ch <- res{c, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		t.Cleanup(func() { _ = r.c.Close() })
		return r.c
	case <-time.After(5 * time.Second):
		t.Fatal("Accept: таймаут")
		return nil
	}
}

// expectClosed проверяет, что сервер закрыл соединение без единого байта.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if err == nil || n != 0 {
		t.Fatalf("ожидали закрытие, прочитали n=%d err=%v", n, err)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("соединение не закрыто (таймаут)")
	}
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("условие не выполнилось")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func listenLoopback() (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
}

func dialAddr(addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", addr)
}
