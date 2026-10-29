package trace

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
)

func TestGoid_DistinctPerGoroutine(t *testing.T) {
	a := goid()
	if a == 0 || goid() != a {
		t.Fatalf("goid нестабилен: %d", a)
	}
	var b uint64
	var wg sync.WaitGroup
	wg.Go(func() { b = goid() })
	wg.Wait()
	if b == 0 || b == a {
		t.Fatalf("goid другой горутины: %d (своя %d)", b, a)
	}
}

func TestRegistry_BindCurrentUnbind(t *testing.T) {
	var r Registry
	if r.Current() != nil {
		t.Fatal("Current без Bind")
	}
	c, unbind := r.Bind()
	if r.Current() != c {
		t.Fatal("Current не нашёл соединение своей горутины")
	}
	var other *Conn
	var wg sync.WaitGroup
	wg.Go(func() { other = r.Current() })
	wg.Wait()
	if other != nil {
		t.Fatal("соединение видно из чужой горутины")
	}
	unbind()
	if r.Current() != nil {
		t.Fatal("Current после unbind")
	}
	var nilReg *Registry
	nc, nu := nilReg.Bind()
	nu()
	if nc != nil || nilReg.Current() != nil {
		t.Fatal("nil Registry должен быть no-op")
	}
}

func TestConn_NilSafe(t *testing.T) {
	var c *Conn
	c.Dial("a", true)
	c.Upstream(true, 0, io.EOF)
	c.UpstreamCloseRead()
	c.UpstreamCloseWrite()
	if c.Agent() != "" || c.Reason() != ReasonUnknown {
		t.Fatal("nil Conn")
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Read([]byte) (int, error)  { return 0, nil }
func (nopConn) Write([]byte) (int, error) { return 0, nil }
func (nopConn) CloseRead() error          { return nil }
func (nopConn) CloseWrite() error         { return nil }

type errConn struct {
	nopConn
	rerr, werr error
}

func (c errConn) Read([]byte) (int, error)  { return 0, c.rerr }
func (c errConn) Write([]byte) (int, error) { return 0, c.werr }

func TestConn_Reason(t *testing.T) {
	timeout := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	cases := []struct {
		name string
		run  func(c *Conn)
		want string
	}{
		{"не дошли до Dial", func(*Conn) {}, ReasonNotConnected},
		{"Dial не удался", func(c *Conn) { c.Dial("a", false) }, ReasonDialFailed},
		{"клиент закрыл", func(c *Conn) {
			cl := c.WrapClient(errConn{rerr: io.EOF})
			_, _ = cl.Read(nil)
			_ = cl.CloseWrite() // pump клиент → Telegram
			_ = cl.CloseRead()  // и второй pump следом
		}, ReasonClientEOF},
		{"RST клиента", func(c *Conn) {
			cl := c.WrapClient(errConn{rerr: errors.New("connection reset by peer")})
			_, _ = cl.Read(nil)
			c.UpstreamCloseRead()
		}, ReasonClientError},
		{"DC закрыл", func(c *Conn) {
			c.Upstream(true, 0, io.EOF)
			c.UpstreamCloseWrite()
			_ = c.WrapClient(errConn{rerr: io.EOF}).CloseRead()
		}, ReasonUpstreamEOF},
		{"обрыв стрима", func(c *Conn) {
			c.Upstream(true, 0, errors.New("stream reset"))
			c.UpstreamCloseWrite()
		}, ReasonUpstreamError},
		{"клиент не принимает", func(c *Conn) {
			cl := c.WrapClient(errConn{werr: errors.New("broken pipe")})
			_, _ = cl.Write([]byte{1})
			_ = cl.CloseRead()
		}, ReasonClientError},
		{"idle", func(c *Conn) {
			c.Upstream(true, 0, timeout)
			c.UpstreamCloseWrite()
		}, ReasonIdle},
		{"повторённый таймаут не idle", func(c *Conn) {
			c.Upstream(true, 0, timeout)
			c.Upstream(true, 5, nil) // mtg повторил чтение — данные пошли
			c.Upstream(true, 0, io.EOF)
			c.UpstreamCloseWrite()
		}, ReasonUpstreamEOF},
		{"закрыто сервером", func(c *Conn) {
			cl := c.WrapClient(errConn{rerr: net.ErrClosed})
			_, _ = cl.Read(nil)
			_ = cl.CloseWrite()
		}, ReasonServer},
		{"без ошибки", func(c *Conn) { c.UpstreamCloseWrite() }, ReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Conn{}
			if tc.want != ReasonNotConnected && tc.want != ReasonDialFailed {
				c.Dial("ag", true)
			}
			tc.run(c)
			if got := c.Reason(); got != tc.want {
				t.Fatalf("Reason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConn_AgentIsLastDial(t *testing.T) {
	c := &Conn{}
	c.Dial("a", false)
	c.Dial("b", true)
	if c.Agent() != "b" {
		t.Fatalf("agent=%q", c.Agent())
	}
}
