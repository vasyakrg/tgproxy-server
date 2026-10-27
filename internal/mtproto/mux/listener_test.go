package mux

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

var testKey = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: testDomain},
		DNSNames:  []string{testDomain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return cert, pool
}

func routeWith(serve func(int, net.Conn)) (*fakeRouter, *fakeRoute) {
	r := &fakeRoute{keys: [][16]byte{{9}, testKey}, serve: serve, called: make(chan served, 8)}
	return &fakeRouter{r: r}, r
}

func TestFallthroughRealTLSHandshake(t *testing.T) {
	cert, pool := selfSigned(t)
	router, _ := routeWith(nil)
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{})
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	c, err := (&tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: testDomain}}).DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	if rc.falls.Load() != 1 {
		t.Fatalf("fallthrough=%d", rc.falls.Load())
	}
}

func TestFallthroughBytesIdentical(t *testing.T) {
	router, _ := routeWith(nil)
	l := startMux(t, router, Hooks{}, Options{})
	c := dial(t, l)
	// HTTP-мусор: не TLS → fallthrough с повтором прочитанных байтов + хвост.
	payload := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	srv := acceptOne(t, l)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srv, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestFallthroughWrongSecretDomainAndStale(t *testing.T) {
	now := time.Now()
	cases := map[string][]byte{
		"неверный секрет": helloFor([16]byte{7}, testDomain, now),
		"неверный SNI":    helloFor(testKey, "other.example", now),
		"timestamp":       helloFor(testKey, testDomain, now.Add(-time.Hour)),
	}
	for name, hello := range cases {
		t.Run(name, func(t *testing.T) {
			router, route := routeWith(nil)
			l := startMux(t, router, Hooks{}, Options{})
			c := dial(t, l)
			_, _ = c.Write(hello)
			srv := acceptOne(t, l)
			got := make([]byte, len(hello))
			if _, err := io.ReadFull(srv, got); err != nil || !bytes.Equal(got, hello) {
				t.Fatalf("байты расходятся: %v", err)
			}
			select {
			case <-route.called:
				t.Fatal("Serve не должен вызываться")
			default:
			}
		})
	}
}

func TestValidHMACServesMTProto(t *testing.T) {
	gotCh := make(chan []byte, 1)
	router, route := routeWith(func(_ int, c net.Conn) {
		buf := make([]byte, 5+3)
		_, _ = io.ReadFull(c, buf)
		gotCh <- buf
		_ = c.(interface{ CloseWrite() error }).CloseWrite()
		_, _ = io.Copy(io.Discard, c)
	})
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{})
	c := dial(t, l)
	hello := helloFor(testKey, testDomain, time.Now())
	_, _ = c.Write(hello)
	var s served
	select {
	case s = <-route.called:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve не вызван")
	}
	if s.idx != 1 {
		t.Fatalf("idx=%d, ожидали 1", s.idx)
	}
	if _, ok := s.conn.RemoteAddr().(*net.TCPAddr); !ok {
		t.Fatalf("RemoteAddr %T", s.conn.RemoteAddr())
	}
	if _, ok := s.conn.LocalAddr().(*net.TCPAddr); !ok {
		t.Fatalf("LocalAddr %T", s.conn.LocalAddr())
	}
	got := <-gotCh
	if !bytes.Equal(got, hello[:8]) {
		t.Fatalf("replay байт: %x", got)
	}
	// CloseWrite доставил EOF клиенту
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("ожидали EOF, %v", err)
	}
	_ = c.Close()
	if rc.falls.Load() != 0 {
		t.Fatal("MTProto не должен считаться fallthrough")
	}
}

func TestNoRouteFallsThrough(t *testing.T) {
	router := &fakeRouter{}
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{})
	c := dial(t, l)
	hello := helloFor(testKey, testDomain, time.Now())
	_, _ = c.Write(hello)
	srv := acceptOne(t, l)
	got := make([]byte, len(hello))
	if _, err := io.ReadFull(srv, got); err != nil || !bytes.Equal(got, hello) {
		t.Fatalf("байты: %v", err)
	}
	if rc.falls.Load() != 1 {
		t.Fatal("OnFallthrough не вызван")
	}
}

func TestSilentClientsDoNotBlockAccept(t *testing.T) {
	router, _ := routeWith(nil)
	l := startMux(t, router, Hooks{}, Options{MaxConnsPerIP: 1000, MaxPendingHandshakes: 1000, HandshakeTimeout: time.Minute})
	for range 100 {
		dial(t, l)
	}
	c := dial(t, l)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	srv := acceptOne(t, l)
	b := make([]byte, 3)
	if _, err := io.ReadFull(srv, b); err != nil || string(b) != "GET" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestBannedClosedBeforeRead(t *testing.T) {
	router, route := routeWith(nil)
	rc := newRec()
	rc.banned[netip.MustParseAddr("127.0.0.1")] = true
	l := startMux(t, router, rc.hooks(), Options{})
	c := dial(t, l)
	expectClosed(t, c)
	if router.n.Load() != 0 || len(route.called) != 0 {
		t.Fatal("роутер не должен вызываться для забаненного")
	}
}

func TestPerIPLimitCountsActiveMTProto(t *testing.T) {
	block := make(chan struct{})
	router, route := routeWith(func(_ int, _ net.Conn) { <-block })
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{MaxConnsPerIP: 2})
	defer close(block)
	hello := helloFor(testKey, testDomain, time.Now())
	for range 2 {
		c := dial(t, l)
		_, _ = c.Write(hello)
		<-route.called
	}
	c3 := dial(t, l)
	expectClosed(t, c3)
	eventually(t, func() bool { return rc.rejectCount(ReasonConnLimit) == 1 })
}

func TestGlobalAndPendingLimits(t *testing.T) {
	for name, opts := range map[string]Options{
		"global":  {MaxConns: 1, MaxConnsPerIP: 10, MaxPendingHandshakes: 10, HandshakeTimeout: time.Minute},
		"pending": {MaxConns: 10, MaxConnsPerIP: 10, MaxPendingHandshakes: 1, HandshakeTimeout: time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			router, _ := routeWith(nil)
			rc := newRec()
			l := startMux(t, router, rc.hooks(), opts)
			dial(t, l) // молчун занимает слот
			eventually(t, func() bool { return rc.bannedCh.Load() == 1 })
			c2 := dial(t, l)
			expectClosed(t, c2)
			eventually(t, func() bool { return rc.rejectCount(ReasonConnLimit) == 1 })
		})
	}
}

func TestFallthroughReleasesSlots(t *testing.T) {
	router, _ := routeWith(nil)
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{MaxConnsPerIP: 1, MaxConns: 1, MaxPendingHandshakes: 1})
	for range 3 {
		c := dial(t, l)
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		srv := acceptOne(t, l)
		_ = srv.Close()
		_ = c.Close()
		eventually(t, func() bool { l.lim.mu.Lock(); defer l.lim.mu.Unlock(); return l.lim.total == 0 })
	}
	if rc.rejectCount(ReasonConnLimit) != 0 {
		t.Fatal("fallthrough не освободил слот")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	router, _ := routeWith(nil)
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{HandshakeTimeout: 100 * time.Millisecond})
	c := dial(t, l)
	_, _ = c.Write([]byte{0x16, 0x03}) // половина заголовка и тишина
	expectClosed(t, c)
	eventually(t, func() bool { return rc.rejectCount(ReasonHandshakeTimeout) == 1 })
}

func TestBadRecordOnEarlyEOF(t *testing.T) {
	router, _ := routeWith(nil)
	rc := newRec()
	l := startMux(t, router, rc.hooks(), Options{})
	c := dial(t, l)
	_, _ = c.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x20, 1, 2}) // тело неполное
	_ = c.CloseWrite()
	eventually(t, func() bool { return rc.rejectCount(ReasonBadRecord) == 1 })
}

func TestServePanicDoesNotKillListener(t *testing.T) {
	var boom atomic.Bool
	boom.Store(true)
	router, route := routeWith(func(int, net.Conn) {
		if boom.Load() {
			panic("boom")
		}
	})
	l := startMux(t, router, Hooks{}, Options{})
	c := dial(t, l)
	_, _ = c.Write(helloFor(testKey, testDomain, time.Now()))
	<-route.called
	expectClosed(t, c)

	boom.Store(false)
	c2 := dial(t, l)
	_, _ = c2.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	acceptOne(t, l)
}

func TestCloseDropsActiveAndWaits(t *testing.T) {
	started := make(chan struct{})
	router, _ := routeWith(func(_ int, c net.Conn) {
		close(started)
		_, _ = io.Copy(io.Discard, c) // блокируется до закрытия
	})
	inner, _ := listenLoopback()
	l, err := New(inner, router, Hooks{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := dialAddr(l.Addr().String())
	defer func() { _ = c.Close() }()
	_, _ = c.Write(helloFor(testKey, testDomain, time.Now()))
	<-started
	done := make(chan error, 1)
	go func() { done <- l.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close завис")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept после Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("повторный Close: %v", err)
	}
}

type failListener struct {
	net.Listener
	err error
}

func (f failListener) Accept() (net.Conn, error) { return nil, f.err }

func TestFatalAcceptErrorSurfaces(t *testing.T) {
	inner, _ := listenLoopback()
	boom := errors.New("boom")
	l, err := New(failListener{inner, boom}, &fakeRouter{}, Hooks{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if _, err := l.Accept(); !errors.Is(err, boom) {
		t.Fatalf("Accept: %v", err)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(nil, &fakeRouter{}, Hooks{}, Options{}); err == nil {
		t.Fatal("ожидали ошибку на nil inner")
	}
}
