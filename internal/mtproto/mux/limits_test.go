package mux

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func sendHello(t *testing.T, l *Listener, key [16]byte) *net.TCPConn {
	t.Helper()
	c := dial(t, l)
	if _, err := c.Write(helloFor(key, testDomain, time.Now())); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSecretMaxConnsClosesWithConnLimit(t *testing.T) {
	block := make(chan struct{})
	router, route := routeWith(func(int, net.Conn) { <-block })
	route.limits = map[int]secretLim{1: {id: 7, max: 2}}
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{})
	t.Cleanup(func() { close(block) })

	for range 2 {
		sendHello(t, l, testKey)
		<-route.called
	}
	c3 := sendHello(t, l, testKey)
	expectClosed(t, c3)
	if got := rc.rejectCount(ReasonConnLimit); got != 1 {
		t.Fatalf("conn_limit = %d, want 1", got)
	}
	if len(route.called) != 0 {
		t.Fatal("третье соединение дошло до Serve")
	}
}

func TestSecretMaxConnsReleasedAfterServe(t *testing.T) {
	var release atomic.Bool
	router, route := routeWith(func(int, net.Conn) {
		for !release.Load() {
			time.Sleep(time.Millisecond)
		}
	})
	route.limits = map[int]secretLim{1: {id: 7, max: 1}}
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{})

	sendHello(t, l, testKey)
	<-route.called
	release.Store(true)
	eventually(t, func() bool {
		c := sendHello(t, l, testKey)
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		select {
		case <-route.called:
			return true
		case <-time.After(200 * time.Millisecond):
			return false
		}
	})
}

func TestSecretMaxConnsIsPerSecret(t *testing.T) {
	block := make(chan struct{})
	router, route := routeWith(func(int, net.Conn) { <-block })
	route.limits = map[int]secretLim{1: {id: 7, max: 1}}
	l := startMux(t, router, newRec().hooks(), Options{})
	t.Cleanup(func() { close(block) })

	sendHello(t, l, testKey)
	<-route.called
	sendHello(t, l, [16]byte{9}) // другой секрет без лимита
	if s := <-route.called; s.idx != 0 {
		t.Fatalf("idx = %d", s.idx)
	}
}

func TestSecretCIDRForeignNetworkFallsThrough(t *testing.T) {
	router, route := routeWith(nil)
	route.limits = map[int]secretLim{1: {id: 7, cidrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{})

	hello := helloFor(testKey, testDomain, time.Now())
	c := dial(t, l)
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	got := acceptOne(t, l)
	buf := make([]byte, len(hello))
	if _, err := readFull(got, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(hello) {
		t.Fatal("байты fallthrough искажены")
	}
	if len(route.called) != 0 {
		t.Fatal("Serve вызван для чужой сети")
	}
	if rc.falls.Load() != 1 || rc.rejectCount(ReasonConnLimit) != 0 {
		t.Fatalf("falls=%d", rc.falls.Load())
	}
}

func TestSecretCIDRAllowedNetworkServed(t *testing.T) {
	router, route := routeWith(nil)
	route.limits = map[int]secretLim{1: {id: 7, cidrs: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
	}}}
	l := startMux(t, router, newRec().hooks(), Options{})
	sendHello(t, l, testKey)
	if s := <-route.called; s.idx != 1 {
		t.Fatalf("idx = %d", s.idx)
	}
}

func TestSetOptionsAppliesWithoutDroppingLive(t *testing.T) {
	block := make(chan struct{})
	router, route := routeWith(func(int, net.Conn) { <-block })
	route.limits = map[int]secretLim{1: {id: 7}}
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{MaxConnsPerIP: 10})
	t.Cleanup(func() { close(block) })

	live := make([]*net.TCPConn, 0, 3)
	for range 3 {
		live = append(live, sendHello(t, l, testKey))
		<-route.called
	}
	l.SetOptions(Options{MaxConnsPerIP: 3})

	for _, c := range live {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("неожиданные данные")
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("живое соединение разорвано: %v", err)
		}
	}
	expectClosed(t, sendHello(t, l, testKey))
	if rc.rejectCount(ReasonConnLimit) != 1 {
		t.Fatalf("conn_limit = %d", rc.rejectCount(ReasonConnLimit))
	}
	l.SetOptions(Options{MaxConnsPerIP: 20})
	sendHello(t, l, testKey)
	<-route.called
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
