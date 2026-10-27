package upstream

import (
	"net"
	"sync"
)

// leaseConn — essentials.Conn поверх стрима агента: Release балансировщика
// происходит ровно один раз, на Close. Считает байты и активные стримы по
// (agent, dc): направление «in» — запись к Telegram, «out» — чтение от него.
type leaseConn struct {
	net.Conn
	lease Lease
	once  sync.Once
	m     Metrics
	agent string
	dc    int
}

func (c *leaseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.m.MTProtoBytes(c.agent, "out", n)
	return n, err
}

func (c *leaseConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.m.MTProtoBytes(c.agent, "in", n)
	return n, err
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
	c.once.Do(func() {
		c.m.MTProtoStreams(c.agent, c.dc, -1)
		c.lease.Release()
	})
	return err
}
