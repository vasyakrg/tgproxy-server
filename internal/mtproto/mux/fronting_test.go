package mux

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

func proxyV2(t *testing.T, src, dst string) []byte {
	t.Helper()
	s, _ := net.ResolveTCPAddr("tcp", src)
	d, _ := net.ResolveTCPAddr("tcp", dst)
	h := proxyproto.HeaderProxyFromAddrs(2, s, d)
	b, err := h.Format()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func frontConn(t *testing.T, l *Listener) net.Conn {
	t.Helper()
	c, err := dialAddr(l.FrontingAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestFrontingAcceptsProxyV2WithSourceIP(t *testing.T) {
	l := startMux(t, &fakeRouter{}, Hooks{}, Options{})
	if !l.FrontingAddr().IP.IsLoopback() || l.FrontingAddr().Port == 0 {
		t.Fatalf("FrontingAddr: %v", l.FrontingAddr())
	}
	c := frontConn(t, l)
	_, _ = c.Write(append(proxyV2(t, "203.0.113.7:5555", "127.0.0.1:443"), "hello"...))
	srv := acceptOne(t, l)
	if got := srv.RemoteAddr().String(); got != "203.0.113.7:5555" {
		t.Fatalf("RemoteAddr=%s", got)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(srv, b); err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestFrontingRejectsWithoutProxyV2(t *testing.T) {
	v1 := []byte("PROXY TCP4 203.0.113.7 127.0.0.1 5555 443\r\nGET / HTTP/1.1\r\n\r\n")
	for name, data := range map[string][]byte{
		"без PROXY": []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"PROXY v1":  v1,
	} {
		t.Run(name, func(t *testing.T) {
			l := startMux(t, &fakeRouter{}, Hooks{}, Options{})
			c := frontConn(t, l)
			_, _ = c.Write(data)
			expectClosed(t, c)
		})
	}
}

func TestFrontingRejectsLocalCommand(t *testing.T) {
	l := startMux(t, &fakeRouter{}, Hooks{}, Options{})
	c := frontConn(t, l)
	h := proxyproto.Header{Version: 2, Command: proxyproto.LOCAL}
	b, _ := h.Format()
	_, _ = c.Write(b)
	expectClosed(t, c)
}

func TestFrontingHeaderTimeout(t *testing.T) {
	l := startMux(t, &fakeRouter{}, Hooks{}, Options{HandshakeTimeout: 100 * time.Millisecond})
	c := frontConn(t, l)
	expectClosed(t, c)
}

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (a addrConn) RemoteAddr() net.Addr { return a.remote }

func TestFrontingRejectsNonLoopback(t *testing.T) {
	l := startMux(t, &fakeRouter{}, Hooks{}, Options{})
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.frontingHandle(addrConn{a, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}})
	}()
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("ожидали EOF, %v", err)
	}
}
