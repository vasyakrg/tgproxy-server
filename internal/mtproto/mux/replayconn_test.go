package mux

import (
	"io"
	"net"
	"net/netip"
	"testing"
)

type strAddr string

func (strAddr) Network() string  { return "x" }
func (s strAddr) String() string { return string(s) }

func TestAsTCPAddr(t *testing.T) {
	if a := asTCPAddr(strAddr("198.51.100.1:99")); a.IP.String() != "198.51.100.1" || a.Port != 99 {
		t.Fatalf("%v", a)
	}
	if a := asTCPAddr(strAddr("мусор")); a == nil {
		t.Fatal("nil")
	}
	if a := asTCPAddr(nil); a == nil {
		t.Fatal("nil для nil")
	}
	if _, ok := addrOf(strAddr("мусор")); ok {
		t.Fatal("ожидали !ok")
	}
	if ip, ok := addrOf(strAddr("[::ffff:1.2.3.4]:5")); !ok || !ip.Is4() {
		t.Fatalf("unmap: %v %v", ip, ok)
	}
}

func TestReplayConnReadsPrefixThenSocket(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	rc := newReplayConn(a, []byte("abcdef"))
	go func() { _, _ = b.Write([]byte("XYZ")) }()
	buf := make([]byte, 4)
	n, _ := rc.Read(buf)
	if string(buf[:n]) != "abcd" {
		t.Fatalf("%q", buf[:n])
	}
	rest := make([]byte, 5)
	if _, err := io.ReadFull(rc, rest); err != nil || string(rest) != "efXYZ" {
		t.Fatalf("%q %v", rest, err)
	}
	// net.Pipe не умеет half-close
	if err := rc.CloseRead(); err == nil {
		t.Fatal("ожидали ErrUnsupported")
	}
	if err := rc.CloseWrite(); err == nil {
		t.Fatal("ожидали ErrUnsupported")
	}
	if _, ok := rc.RemoteAddr().(*net.TCPAddr); !ok {
		t.Fatal("RemoteAddr не TCPAddr")
	}
	_ = rc.Close()
}

func TestLimits(t *testing.T) {
	l := newLimits(2, 1, 2)
	ip1, ip2 := addr("10.0.0.1"), addr("10.0.0.2")
	if !l.admit(ip1) || l.admit(ip1) {
		t.Fatal("per-IP")
	}
	if !l.admit(ip2) || l.admit(addr("10.0.0.3")) {
		t.Fatal("global")
	}
	l.handshakeDone()
	l.release(ip1)
	if !l.admit(ip1) {
		t.Fatal("слот не освободился")
	}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }
