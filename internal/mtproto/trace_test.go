package mtproto

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/essentials"

	"github.com/vasyakrg/tgproxy-server/internal/mtproto/trace"
)

// tracedNetwork повторяет хуки upstream.Network поверх fakeNetwork: агент из
// trace.Registry текущей горутины и ошибки стрима — как в leaseConn.
type tracedNetwork struct {
	*fakeNetwork
	reg *trace.Registry
}

func (n tracedNetwork) Dial(network, address string) (essentials.Conn, error) {
	tr := n.reg.Current()
	c, err := n.fakeNetwork.Dial(network, address)
	if err != nil {
		tr.Dial("ag1", false)
		return nil, err
	}
	tr.Dial("ag1", true)
	return &tracedUp{Conn: c, tr: tr}, nil
}

type tracedUp struct {
	essentials.Conn
	tr *trace.Conn
}

func (c *tracedUp) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.tr.Upstream(true, n, err)
	return n, err
}

func (c *tracedUp) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.tr.Upstream(false, n, err)
	return n, err
}

func (c *tracedUp) CloseRead() error  { c.tr.UpstreamCloseRead(); return c.Conn.CloseRead() }
func (c *tracedUp) CloseWrite() error { c.tr.UpstreamCloseWrite(); return c.Conn.CloseWrite() }

// finishObs запоминает агента и причину завершения.
type finishObs struct {
	mu     sync.Mutex
	agent  string
	reason chan string
}

func (o *finishObs) Start(int64, string, netip.Addr)   {}
func (o *finishObs) Traffic(int64, string, uint, bool) {}
func (o *finishObs) ConnectedToDC(int64, string, int)  {}
func (o *finishObs) Finish(_ int64, _, reason, agent string) {
	o.mu.Lock()
	o.agent = agent
	o.mu.Unlock()
	o.reason <- reason
}

func (o *finishObs) wait(t *testing.T) (agent, reason string) {
	t.Helper()
	select {
	case reason = <-o.reason:
	case <-time.After(testTimeout):
		t.Fatal("Finish не пришёл")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.agent, reason
}

func newTracedEnv(t *testing.T, idle time.Duration) (*env, *finishObs, *serveSrv, [16]byte) {
	t.Helper()
	reg := &trace.Registry{}
	obs := &finishObs{reason: make(chan string, 4)}
	var tn tracedNetwork
	e, _ := newEnv(t, func(o *Options) {
		tn = tracedNetwork{fakeNetwork: o.Network.(*fakeNetwork), reg: reg}
		o.Network, o.Observer, o.Trace = tn, obs, reg
		if idle > 0 {
			o.Config.IdleTimeout = idle
		}
	})
	srv := startServe(t, e.m)
	_, key := e.addSecret("one")
	r := e.waitKeys(1)
	srv.idx.Store(int64(keyIdx(t, r, key)))
	return e, obs, srv, key
}

func TestTrace_CloseReasons(t *testing.T) {
	t.Run("клиент закрыл", func(t *testing.T) {
		e, obs, srv, key := newTracedEnv(t, 0)
		sess := dialSession(t, srv.addr(), key, 2)
		sess.roundtrip(t, []byte("ping"))
		e.dc.waitConn(t)
		_ = sess.conn.Close()
		if agent, reason := obs.wait(t); agent != "ag1" || reason != trace.ReasonClientEOF {
			t.Fatalf("agent=%q reason=%q", agent, reason)
		}
	})
	t.Run("RST клиента", func(t *testing.T) {
		e, obs, srv, key := newTracedEnv(t, 0)
		sess := dialSession(t, srv.addr(), key, 2)
		sess.roundtrip(t, []byte("ping"))
		e.dc.waitConn(t)
		_ = sess.conn.SetLinger(0)
		_ = sess.conn.Close()
		if _, reason := obs.wait(t); reason != trace.ReasonClientError {
			t.Fatalf("reason=%q", reason)
		}
	})
	t.Run("DC закрыл", func(t *testing.T) {
		e, obs, srv, key := newTracedEnv(t, 0)
		sess := dialSession(t, srv.addr(), key, 2)
		sess.roundtrip(t, []byte("ping"))
		_ = e.dc.waitConn(t).conn.Close()
		if _, reason := obs.wait(t); reason != trace.ReasonUpstreamEOF {
			t.Fatalf("reason=%q", reason)
		}
	})
	t.Run("idle", func(t *testing.T) {
		e, obs, srv, key := newTracedEnv(t, 300*time.Millisecond)
		sess := dialSession(t, srv.addr(), key, 2)
		sess.roundtrip(t, []byte("ping"))
		e.dc.waitConn(t)
		if _, reason := obs.wait(t); reason != trace.ReasonIdle {
			t.Fatalf("reason=%q", reason)
		}
	})
	t.Run("отзыв секрета", func(t *testing.T) {
		e, obs, srv, key := newTracedEnv(t, 0)
		sess := dialSession(t, srv.addr(), key, 2)
		sess.roundtrip(t, []byte("ping"))
		e.dc.waitConn(t)
		ss, _, err := e.repo.ListActive(context.Background(), e.clk.Now())
		if err != nil || len(ss) != 1 {
			t.Fatalf("секреты: %v %v", ss, err)
		}
		if err := e.repo.Revoke(context.Background(), ss[0].ID, e.clk.Now()); err != nil {
			t.Fatal(err)
		}
		if _, reason := obs.wait(t); reason != trace.ReasonServer {
			t.Fatalf("reason=%q", reason)
		}
	})
	t.Run("Dial не удался", func(t *testing.T) {
		e, obs, srv, key := newTracedEnv(t, 0)
		e.net.mu.Lock()
		e.net.failAll = true
		e.net.mu.Unlock()
		dialSession(t, srv.addr(), key, 2)
		if agent, reason := obs.wait(t); agent != "ag1" || reason != trace.ReasonDialFailed {
			t.Fatalf("agent=%q reason=%q", agent, reason)
		}
	})
}
