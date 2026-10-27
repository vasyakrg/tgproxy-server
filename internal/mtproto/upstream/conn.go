package upstream

import (
	"net"
	"sync"
)

// leaseConn — essentials.Conn поверх стрима агента: Release балансировщика
// происходит ровно один раз, на Close.
type leaseConn struct {
	net.Conn
	lease Lease
	once  sync.Once
}

func (c *leaseConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return c.Close()
}

func (c *leaseConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (c *leaseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.lease.Release)
	return err
}
