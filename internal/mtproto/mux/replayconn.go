package mux

import (
	"errors"
	"net"
	"net/netip"
)

// replayConn сначала отдаёт уже прочитанные байты (prefix), затем читает сокет.
// RemoteAddr/LocalAddr всегда *net.TCPAddr: mtglib делает на них type assertion.
// Read вызывается из одной горутины (как и у любого net.Conn под TLS/mtg).
type replayConn struct {
	net.Conn
	prefix []byte
}

func newReplayConn(c net.Conn, prefix []byte) *replayConn {
	return &replayConn{Conn: c, prefix: prefix}
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *replayConn) RemoteAddr() net.Addr { return asTCPAddr(c.Conn.RemoteAddr()) }
func (c *replayConn) LocalAddr() net.Addr  { return asTCPAddr(c.Conn.LocalAddr()) }

// CloseRead делегирует нижележащему соединению (*net.TCPConn).
func (c *replayConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return errors.ErrUnsupported
}

// CloseWrite делегирует нижележащему соединению (*net.TCPConn).
func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// asTCPAddr приводит адрес к *net.TCPAddr; нераспознанный даёт нулевой адрес.
func asTCPAddr(a net.Addr) *net.TCPAddr {
	if t, ok := a.(*net.TCPAddr); ok && t != nil {
		return t
	}
	if a != nil {
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return net.TCPAddrFromAddrPort(ap)
		}
	}
	return &net.TCPAddr{IP: net.IPv4zero}
}

// addrOf возвращает IP клиента (без IPv4-mapped формы).
func addrOf(a net.Addr) (netip.Addr, bool) {
	t := asTCPAddr(a)
	ip, ok := netip.AddrFromSlice(t.IP)
	ip = ip.Unmap()
	if !ok || ip.IsUnspecified() {
		return netip.Addr{}, false
	}
	return ip, true
}
