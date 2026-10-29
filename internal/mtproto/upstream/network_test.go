package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/mtglib"

	"github.com/vasyakrg/tgproxy-server/internal/mtproto/trace"
	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

var _ mtglib.Network = (*Network)(nil)

const dc2Addr = "149.154.167.51:443"

type fakeLease struct {
	agent    string
	mu       sync.Mutex
	reports  []balancer.Result
	released int
}

func (l *fakeLease) Agent() string { return l.agent }
func (l *fakeLease) Report(r balancer.Result) {
	l.mu.Lock()
	l.reports = append(l.reports, r)
	l.mu.Unlock()
}
func (l *fakeLease) Release() { l.mu.Lock(); l.released++; l.mu.Unlock() }

type fakePicker struct {
	mu     sync.Mutex
	agents []string
	calls  int
	excl   [][]string
	leases []*fakeLease
	dcs    []int
}

func (p *fakePicker) Pick(_ context.Context, dc int, exclude ...string) (Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.dcs = append(p.dcs, dc)
	p.excl = append(p.excl, exclude)
	for _, a := range p.agents {
		skip := false
		for _, e := range exclude {
			skip = skip || e == a
		}
		if !skip {
			l := &fakeLease{agent: a}
			p.leases = append(p.leases, l)
			return l, nil
		}
	}
	return nil, balancer.ErrNoCandidates
}

type fakeStreams struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]error
	conn  func() net.Conn
	delay time.Duration
}

func (s *fakeStreams) OpenMTProto(ctx context.Context, a transport.AgentRef, _ int) (net.Conn, error) {
	s.mu.Lock()
	s.calls = append(s.calls, a.ID)
	err := s.fail[a.ID]
	s.mu.Unlock()
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return s.conn(), nil
}

func resolve(id string) (transport.AgentRef, bool) {
	if id == "ghost" {
		return transport.AgentRef{}, false
	}
	return transport.AgentRef{ID: id}, true
}

type halfConn struct {
	net.Conn
	cr, cw bool
}

func (h *halfConn) CloseRead() error  { h.cr = true; return nil }
func (h *halfConn) CloseWrite() error { h.cw = true; return nil }

func newNet(t *testing.T, p Picker, s Streams) *Network {
	t.Helper()
	n, err := New(Options{Picker: p, Streams: s, Resolve: resolve, DialTimeout: time.Second})
	req.NoError(t, err)
	return n
}

func pipeConn() net.Conn { a, b := net.Pipe(); _ = b; return a }

func TestNew_Validation(t *testing.T) {
	_, err := New(Options{})
	req.Error(t, err)
}

func TestDial_UnknownAddressNoAgents(t *testing.T) {
	p, s := &fakePicker{agents: []string{"a"}}, &fakeStreams{}
	n := newNet(t, p, s)
	for _, addr := range []string{"1.2.3.4:443", "149.154.167.51:80", "bad", "example.com:443", "149.154.167.51:x"} {
		_, err := n.Dial("tcp", addr)
		req.Error(t, err, addr)
	}
	_, err := n.Dial("tcp", "1.2.3.4:443")
	req.ErrorIs(t, err, ErrUnknownAddress)
	_, err = n.Dial("udp", dc2Addr)
	req.Error(t, err)
	req.Zero(t, p.calls)
	req.Empty(t, s.calls)
}

func TestDial_OKAndReleaseOnClose(t *testing.T) {
	p := &fakePicker{agents: []string{"a"}}
	hc := &halfConn{Conn: pipeConn()}
	s := &fakeStreams{conn: func() net.Conn { return hc }}
	n := newNet(t, p, s)

	c, err := n.Dial("tcp4", dc2Addr)
	req.NoError(t, err)
	l := p.leases[0]
	req.Equal(t, []int{2}, p.dcs)
	req.Equal(t, []string{"a"}, s.calls)
	req.Len(t, l.reports, 1)
	req.False(t, l.reports[0].TransportError)
	req.Zero(t, l.released, "inflight не освобождается на открытии")

	req.NoError(t, c.CloseRead())
	req.NoError(t, c.CloseWrite())
	req.True(t, hc.cr && hc.cw)
	req.Zero(t, l.released)

	req.NoError(t, c.Close())
	_ = c.Close()
	req.Equal(t, 1, l.released, "Release ровно один раз")
}

func TestDial_CloseHalvesFallbackToClose(t *testing.T) {
	p := &fakePicker{agents: []string{"a"}}
	s := &fakeStreams{conn: pipeConn}
	n := newNet(t, p, s)
	c, err := n.Dial("tcp", dc2Addr)
	req.NoError(t, err)
	req.NoError(t, c.CloseRead())
	req.Equal(t, 1, p.leases[0].released)
	req.NoError(t, c.CloseWrite())
	req.Equal(t, 1, p.leases[0].released)
}

func TestDial_IPv6AndMappedAddress(t *testing.T) {
	p := &fakePicker{agents: []string{"a"}}
	s := &fakeStreams{conn: pipeConn}
	n := newNet(t, p, s)
	c, err := n.Dial("tcp6", "[2001:b28:f23d:f001::a]:443")
	req.NoError(t, err)
	_ = c.Close()
	c, err = n.Dial("tcp", "[::ffff:149.154.175.50]:443")
	req.NoError(t, err)
	_ = c.Close()
	req.Equal(t, []int{1, 1}, p.dcs)
}

func TestDial_FailoverToNextAgent(t *testing.T) {
	p := &fakePicker{agents: []string{"a", "b"}}
	s := &fakeStreams{
		fail: map[string]error{"a": &transport.PhaseError{Phase: "dial", Source: transport.SourceServerAgent, Err: errors.New("boom")}},
		conn: pipeConn,
	}
	n := newNet(t, p, s)

	_, err := n.Dial("tcp", dc2Addr)
	var pe *transport.PhaseError
	req.ErrorAs(t, err, &pe)
	req.True(t, p.leases[0].reports[0].TransportError)
	req.Equal(t, 1, p.leases[0].released)

	c, err := n.Dial("tcp", dc2Addr) // следующий адрес DC от mtg
	req.NoError(t, err)
	defer func() { _ = c.Close() }()
	req.Equal(t, []string{"a", "b"}, s.calls)
	req.Equal(t, []string{"a"}, p.excl[1])
}

func TestDial_ExcludeFallsBackWhenOnlyAgent(t *testing.T) {
	p := &fakePicker{agents: []string{"a"}}
	s := &fakeStreams{fail: map[string]error{"a": errors.New("x")}, conn: pipeConn}
	n := newNet(t, p, s)
	_, _ = n.Dial("tcp", dc2Addr)
	s.mu.Lock()
	delete(s.fail, "a")
	s.mu.Unlock()
	c, err := n.Dial("tcp", dc2Addr)
	req.NoError(t, err)
	_ = c.Close()
}

func TestDial_ExcludeExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	p := &fakePicker{agents: []string{"a", "b"}}
	s := &fakeStreams{fail: map[string]error{"a": errors.New("x")}, conn: pipeConn}
	n, err := New(Options{Picker: p, Streams: s, Resolve: resolve, RetryMemory: time.Second, Now: func() time.Time { return now }})
	req.NoError(t, err)
	_, _ = n.Dial("tcp", dc2Addr)
	now = now.Add(2 * time.Second)
	_, _ = n.Dial("tcp", dc2Addr)
	req.Empty(t, p.excl[1])
}

func TestDial_NoCandidatesAndResolveFail(t *testing.T) {
	n := newNet(t, &fakePicker{}, &fakeStreams{})
	_, err := n.Dial("tcp", dc2Addr)
	req.ErrorIs(t, err, balancer.ErrNoCandidates)

	p := &fakePicker{agents: []string{"ghost"}}
	n = newNet(t, p, &fakeStreams{})
	_, err = n.Dial("tcp", dc2Addr)
	req.ErrorIs(t, err, ErrNoAgent)
	req.Equal(t, 1, p.leases[0].released)
	req.True(t, p.leases[0].reports[0].TransportError)
}

func TestDialContext_CancelNotTransportError(t *testing.T) {
	p := &fakePicker{agents: []string{"a"}}
	s := &fakeStreams{delay: time.Minute, conn: pipeConn}
	n := newNet(t, p, s)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err := n.DialContext(ctx, "tcp", dc2Addr)
	req.ErrorIs(t, err, context.Canceled)
	r := p.leases[0].reports[0]
	req.True(t, r.Canceled)
	req.False(t, r.TransportError)
	req.Equal(t, 1, p.leases[0].released)
}

func TestDial_TimeoutIsTransportError(t *testing.T) {
	p := &fakePicker{agents: []string{"a"}}
	s := &fakeStreams{delay: time.Minute, conn: pipeConn}
	n, err := New(Options{Picker: p, Streams: s, Resolve: resolve, DialTimeout: 30 * time.Millisecond})
	req.NoError(t, err)
	_, err = n.Dial("tcp", dc2Addr)
	req.ErrorIs(t, err, context.DeadlineExceeded)
	req.True(t, p.leases[0].reports[0].TransportError)
}

func TestConnDeadlines(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	p := &fakePicker{agents: []string{"a"}}
	n := newNet(t, p, &fakeStreams{conn: func() net.Conn { return a }})
	c, err := n.Dial("tcp", dc2Addr)
	req.NoError(t, err)
	defer func() { _ = c.Close() }()
	req.NoError(t, c.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	req.ErrorAs(t, err, &ne)
	req.True(t, ne.Timeout())
}

func TestNativeAndHTTPClient(t *testing.T) {
	n := newNet(t, &fakePicker{}, &fakeStreams{})
	req.NotNil(t, n.NativeDialer())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	resp, err := n.MakeHTTPClient(nil).Do(getReq(t, srv.URL))
	req.NoError(t, err)
	_ = resp.Body.Close()

	called := false
	cl := n.MakeHTTPClient(func(ctx context.Context, network, address string) (essentials.Conn, error) {
		called = true
		c, err := n.NativeDialer().DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return essentials.WrapNetConn(c), nil
	})
	resp, err = cl.Do(getReq(t, srv.URL))
	req.NoError(t, err)
	_ = resp.Body.Close()
	req.True(t, called)
}

// Защита от рассинхрона таблиц: IPv4/IPv6-наборы tgapi.DCAddrs ≡ mtg.
func TestTablesInSyncWithTgapi(t *testing.T) {
	want := map[int]map[netip.AddrPort]bool{}
	for dc, list := range essentials.TelegramCoreAddresses {
		want[dc] = map[netip.AddrPort]bool{}
		for _, s := range list {
			want[dc][netip.MustParseAddrPort(s)] = true
		}
	}
	req.ElementsMatch(t, keys(want), tgapi.KnownDCs())
	for dc, set := range want {
		got := map[netip.AddrPort]bool{}
		for _, v6 := range []bool{false, true} {
			for _, a := range tgapi.DCAddrs(dc, v6) {
				got[a] = true
			}
		}
		req.Equal(t, set, got, "dc %d", dc)
	}
	for ap, dc := range addrMap() {
		req.True(t, want[dc][ap])
	}
}

func keys(m map[int]map[netip.AddrPort]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestKeyedPickerAdapter(t *testing.T) {
	k := balancer.NewKeyed()
	k.Update([]balancer.KeyedCandidate{{ID: "a", Weight: 1, Healthy: true, Capable: true,
		DC: map[int]balancer.DCState{2: {Up: true, RTT: time.Millisecond}}}})
	kp := KeyedPicker{K: k}
	l, err := kp.Pick(context.Background(), 2)
	req.NoError(t, err)
	req.Equal(t, "a", l.Agent())
	l.Release()
	_, err = kp.Pick(context.Background(), 3)
	req.ErrorIs(t, err, balancer.ErrNoCandidates)
	_, err = kp.Pick(context.Background(), 2, "a")
	req.Error(t, err)
}

type reqT struct{}

var req reqT

func fail(t *testing.T, msg string, a []any) {
	t.Helper()
	t.Fatalf("%s %v", msg, a)
}

func (reqT) NoError(t *testing.T, err error, a ...any) {
	t.Helper()
	if err != nil {
		fail(t, "unexpected error: "+err.Error(), a)
	}
}
func (reqT) Error(t *testing.T, err error, a ...any) {
	t.Helper()
	if err == nil {
		fail(t, "expected error", a)
	}
}
func (reqT) ErrorIs(t *testing.T, err, target error, a ...any) {
	t.Helper()
	if !errors.Is(err, target) {
		fail(t, "error "+fmt.Sprint(err)+" is not "+fmt.Sprint(target), a)
	}
}
func (reqT) ErrorAs(t *testing.T, err error, target any, a ...any) {
	t.Helper()
	if !errors.As(err, target) {
		fail(t, "error "+fmt.Sprint(err)+" has wrong type", a)
	}
}
func (reqT) True(t *testing.T, v bool, a ...any) {
	t.Helper()
	if !v {
		fail(t, "expected true", a)
	}
}
func (reqT) False(t *testing.T, v bool, a ...any) {
	t.Helper()
	if v {
		fail(t, "expected false", a)
	}
}
func (reqT) NotNil(t *testing.T, v any, a ...any) {
	t.Helper()
	if v == nil {
		fail(t, "expected non-nil", a)
	}
}
func (reqT) Zero(t *testing.T, v any, a ...any) {
	t.Helper()
	if !reflect.ValueOf(v).IsZero() {
		fail(t, fmt.Sprintf("expected zero, got %v", v), a)
	}
}
func (reqT) Empty(t *testing.T, v any, a ...any) {
	t.Helper()
	if rv := reflect.ValueOf(v); rv.Len() != 0 {
		fail(t, fmt.Sprintf("expected empty, got %v", v), a)
	}
}
func (reqT) Len(t *testing.T, v any, n int, a ...any) {
	t.Helper()
	if l := reflect.ValueOf(v).Len(); l != n {
		fail(t, fmt.Sprintf("len %d != %d", l, n), a)
	}
}
func (reqT) Equal(t *testing.T, want, got any, a ...any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		fail(t, fmt.Sprintf("want %v, got %v", want, got), a)
	}
}
func (reqT) ElementsMatch(t *testing.T, x, y []int, a ...any) {
	t.Helper()
	x, y = append([]int(nil), x...), append([]int(nil), y...)
	sort.Ints(x)
	sort.Ints(y)
	if !reflect.DeepEqual(x, y) {
		fail(t, fmt.Sprintf("%v != %v", x, y), a)
	}
}

func getReq(t *testing.T, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	req.NoError(t, err)
	return r
}

func TestDial_TraceAgentAndUpstreamClose(t *testing.T) {
	p := &fakePicker{agents: []string{"a", "b"}}
	s := &fakeStreams{conn: func() net.Conn { return &halfConn{Conn: pipeConn()} }, fail: map[string]error{"a": errors.New("boom")}}
	reg := &trace.Registry{}
	n, err := New(Options{Picker: p, Streams: s, Resolve: resolve, DialTimeout: time.Second, Trace: reg})
	req.NoError(t, err)
	tr, unbind := reg.Bind()
	defer unbind()

	_, err = n.Dial("tcp", dc2Addr)
	req.Error(t, err)
	req.Equal(t, "a", tr.Agent())
	req.Equal(t, trace.ReasonDialFailed, tr.Reason())

	c, err := n.Dial("tcp", dc2Addr)
	req.NoError(t, err)
	req.Equal(t, "b", tr.Agent())
	_ = c.(*leaseConn).Conn.Close() // DC/агент закрыл стрим
	_, rerr := c.Read(make([]byte, 1))
	req.Error(t, rerr)
	req.NoError(t, c.CloseWrite()) // mtg: pump Telegram → клиент завершён
	req.Equal(t, trace.ReasonServer, tr.Reason(), "io.ErrClosedPipe закрытого pipe — локальное закрытие")
}
