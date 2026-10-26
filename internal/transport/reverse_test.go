package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// tcpPair возвращает две стороны одного TCP-соединения: (сервер, агент).
func tcpPair(t *testing.T) (srv, agent net.Conn) {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := l.Accept(); ch <- res{c, err} }()
	agent, err = (&net.Dialer{}).DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { _ = r.c.Close(); _ = agent.Close() })
	return r.c, agent
}

// attachAgent подключает «агента» с обработчиком h; возвращает его сторону соединения.
func attachAgent(t *testing.T, p *ReversePool, id string, h http.Handler) net.Conn {
	t.Helper()
	srv, ag := tcpPair(t)
	go (&http2.Server{}).ServeConn(ag, &http2.ServeConnOpts{Handler: h}) //nolint:staticcheck // SA1019: нужен ServeConn поверх готового соединения
	if err := p.Attach(id, srv); err != nil {
		t.Fatal(err)
	}
	return ag
}

func revRef(id string) AgentRef { return AgentRef{ID: id, Mode: config.AgentModeReverse} }

func newPool(t *testing.T, opts ...ReverseOption) *ReversePool {
	t.Helper()
	p := NewReversePool(opts...)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting: %s", what)
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(tgapi.HeaderSource, tgapi.SourceTelegram)
	w.Header().Set("X-Seen-Host", r.Host)
	w.Header().Set("X-Seen-Path", r.URL.EscapedPath()+"?"+r.URL.RawQuery)
	_, _ = io.Copy(w, r.Body)
})

// rtGet выполняет GET, вычитывает и закрывает тело; возвращает статус.
func rtGet(t *testing.T, p *ReversePool, id, path string) (int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := p.RoundTrip(ctx, revRef(id), newReq(ctx, t, http.MethodGet, path, nil))
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func TestReverseBodyByteForByteAndURL(t *testing.T) {
	p := newPool(t)
	attachAgent(t, p, "a1", okHandler)
	body := make([]byte, 300_000)
	_, _ = rand.Read(body)
	ctx := context.Background()
	req := newReq(ctx, t, http.MethodPost, "/tg/bot1:AAA/sendMessage?x=1", bytes.NewReader(body))
	resp, err := p.RoundTrip(ctx, revRef("a1"), req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, body) {
		t.Fatal("body mismatch")
	}
	if resp.ProtoMajor != 2 || resp.Header.Get("X-Seen-Host") != "a1.reverse" ||
		resp.Header.Get("X-Seen-Path") != "/tg/bot1:AAA/sendMessage?x=1" {
		t.Fatalf("proto=%s host=%q path=%q", resp.Proto, resp.Header.Get("X-Seen-Host"), resp.Header.Get("X-Seen-Path"))
	}
	if req.URL.Host != "" {
		t.Fatalf("original request mutated: %v", req.URL)
	}
}

type genReader struct {
	left int64
	h    interface{ Write([]byte) (int, error) }
}

func (g *genReader) Read(b []byte) (int, error) {
	if g.left <= 0 {
		return 0, io.EOF
	}
	n := min(int64(len(b)), g.left)
	for i := range b[:n] {
		b[i] = byte(i * 7)
	}
	_, _ = g.h.Write(b[:n])
	g.left -= n
	return int(n), nil
}

func TestReverseStream20MB(t *testing.T) {
	const size = 20 << 20
	p := newPool(t)
	var peak atomic.Int64
	attachAgent(t, p, "a1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(tgapi.HeaderSource, tgapi.SourceTelegram)
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		buf := make([]byte, 32<<10)
		var total int64
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				total += int64(n)
				_, _ = w.Write(buf[:n])
				fl.Flush()
				peak.Store(total)
			}
			if err != nil {
				return
			}
		}
	}))
	hSent, hRecv := sha256.New(), sha256.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := newReq(ctx, t, http.MethodPost, "/tg/bot1:AAA/sendDocument", io.NopCloser(&genReader{left: size, h: hSent}))
	resp, err := p.RoundTrip(ctx, revRef("a1"), req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(hRecv, resp.Body)
	if err != nil || n != size {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !bytes.Equal(hSent.Sum(nil), hRecv.Sum(nil)) {
		t.Fatal("stream hash mismatch")
	}
}

func TestReverseNoConnIsDialNotSent(t *testing.T) {
	p := newPool(t)
	_, err := rtGet(t, p, "ghost", "/tg/bot1:AAA/getMe")
	out := Classify(nil, err, false)
	if out.Phase != tgapi.PhaseDial || !out.NotSent || !errors.Is(err, ErrNoReverseConn) {
		t.Fatalf("%+v %v", out, err)
	}
	if _, err := p.RoundTrip(context.Background(), AgentRef{}, newReq(context.Background(), t, "GET", "/", nil)); !errors.Is(err, ErrBadAgent) { //nolint:bodyclose // ошибка, тела нет
		t.Fatalf("empty id: %v", err)
	}
}

func TestReverseOneOfTwoDropsZeroErrors(t *testing.T) {
	p := newPool(t)
	c1 := attachAgent(t, p, "a1", okHandler)
	attachAgent(t, p, "a1", okHandler)
	if p.Conns("a1") != 2 {
		t.Fatalf("conns=%d", p.Conns("a1"))
	}
	var wg sync.WaitGroup
	var fails atomic.Int32
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 300 {
			if _, err := rtGet(t, p, "a1", "/tg/bot1:AAA/getMe"); err != nil {
				fails.Add(1)
			}
		}
	}()
	time.Sleep(5 * time.Millisecond)
	_ = c1.Close() // обрыв со стороны агента
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatalf("%d errors after one conn dropped", fails.Load())
	}
	eventually(t, "conns==1", func() bool { return p.Conns("a1") == 1 })
}

func TestReverseAllDownThenReconnect(t *testing.T) {
	var down atomic.Int32
	var detach atomic.Int32
	var attach atomic.Int32
	p := newPool(t,
		WithOnDown(func(string) { down.Add(1) }),
		WithOnDetach(func(string, int) { detach.Add(1) }),
		WithOnAttach(func(string, int) { attach.Add(1) }))
	c1 := attachAgent(t, p, "a1", okHandler)
	c2 := attachAgent(t, p, "a1", okHandler)
	_ = c1.Close()
	eventually(t, "one left", func() bool { return p.Conns("a1") == 1 })
	if down.Load() != 0 {
		t.Fatal("OnDown with a live conn")
	}
	_ = c2.Close()
	eventually(t, "zero", func() bool { return p.Conns("a1") == 0 && down.Load() == 1 })
	_, err := rtGet(t, p, "a1", "/tg/bot1:AAA/getMe")
	var pe *PhaseError
	if !errors.As(err, &pe) || pe.Phase != tgapi.PhaseDial || !tgapi.PhaseNotSent(pe.Phase) {
		t.Fatalf("want dial/NotSent: %v", err)
	}
	attachAgent(t, p, "a1", okHandler)
	code, err := rtGet(t, p, "a1", "/tg/bot1:AAA/getMe")
	if err != nil || code != 200 {
		t.Fatalf("after reconnect: %v", err)
	}
	if attach.Load() != 3 || detach.Load() != 2 || down.Load() != 1 {
		t.Fatalf("attach=%d detach=%d down=%d", attach.Load(), detach.Load(), down.Load())
	}
}

func TestReverseThirdEvictsOldest(t *testing.T) {
	var detached atomic.Int32
	p := newPool(t, WithOnDetach(func(_ string, n int) {
		if n == 2 {
			detached.Add(1)
		}
	}), WithDrainTimeout(time.Second))
	c1 := attachAgent(t, p, "a1", okHandler)
	attachAgent(t, p, "a1", okHandler)
	attachAgent(t, p, "a1", okHandler)
	if p.Conns("a1") != 2 {
		t.Fatalf("conns=%d", p.Conns("a1"))
	}
	// самое старое соединение закрыто пулом: агент видит EOF
	_ = c1.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1<<16)
	var rerr error
	for rerr == nil {
		_, rerr = c1.Read(buf)
	}
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatal("evicted conn not closed")
	}
	if detached.Load() != 1 {
		t.Fatalf("detach events=%d", detached.Load())
	}
	if code, err := rtGet(t, p, "a1", "/x"); err != nil || code != 200 {
		t.Fatalf("%v", err)
	}
}

func TestReversePingTimeoutDropsConn(t *testing.T) {
	var down atomic.Int32
	p := newPool(t, WithReversePing(20*time.Millisecond, 20*time.Millisecond, 2), WithOnDown(func(string) { down.Add(1) }))
	srv, ag := tcpPair(t) // «агент» молчит: ни SETTINGS, ни ack на PING
	_ = ag
	if err := p.Attach("a1", srv); err != nil {
		t.Fatal(err)
	}
	eventually(t, "conn dropped by ping", func() bool { return p.Conns("a1") == 0 && down.Load() == 1 })
}

type fakePinger struct {
	results chan error
	calls   atomic.Int32
}

func (f *fakePinger) Ping(ctx context.Context) error {
	f.calls.Add(1)
	select {
	case err := <-f.results:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestPingLoopMissesReset(t *testing.T) {
	f := &fakePinger{results: make(chan error, 8)}
	// miss, ok (сброс), miss, miss -> dead
	for _, e := range []error{errors.New("x"), nil, errors.New("x"), errors.New("x")} {
		f.results <- e
	}
	dead := make(chan struct{})
	go pingLoop(context.Background(), f, 5*time.Millisecond, time.Second, 2, func() { close(dead) })
	select {
	case <-dead:
	case <-time.After(5 * time.Second):
		t.Fatal("not dead")
	}
	if f.calls.Load() != 4 {
		t.Fatalf("calls=%d", f.calls.Load())
	}
}

func TestPingLoopCancel(t *testing.T) {
	f := &fakePinger{results: make(chan error)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pingLoop(ctx, f, time.Millisecond, time.Hour, 2, func() { t.Error("onDead after cancel") })
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not stop")
	}
}

func TestReverseStatus(t *testing.T) {
	p := newPool(t)
	attachAgent(t, p, "a1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != StatusPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(AgentStatus{Version: "1.2.3", Inflight: 4})
	}))
	st, err := p.Status(context.Background(), revRef("a1"))
	if err != nil || st.Version != "1.2.3" || st.Inflight != 4 {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := p.Status(context.Background(), revRef("none")); err == nil {
		t.Fatal("status without conn must fail")
	}
}

func TestReverseSpreadsLoadAndClose(t *testing.T) {
	p := newPool(t)
	attachAgent(t, p, "a1", okHandler)
	attachAgent(t, p, "a1", okHandler)
	if p.Attach("", &net.TCPConn{}) == nil {
		t.Fatal("empty id must fail")
	}
	_ = p.Close()
	if p.Conns("a1") != 0 {
		t.Fatal("conns after Close")
	}
	srv, _ := tcpPair(t)
	if err := p.Attach("a1", srv); !errors.Is(err, ErrClosed) {
		t.Fatalf("attach after close: %v", err)
	}
}

func TestReverseRetriesOnDeadConnBeforeWrite(t *testing.T) {
	p := newPool(t)
	c1 := attachAgent(t, p, "a1", okHandler)
	attachAgent(t, p, "a1", okHandler)
	_ = c1.Close()
	for range 50 {
		if _, err := rtGet(t, p, "a1", "/x"); err != nil {
			t.Fatal(err)
		}
	}
}

// --- общий table-test классификации фаз для обеих реализаций ---

type implCase struct {
	name string
	// make возвращает транспорт и ref для агента с обработчиком h
	// (h == nil — агент недоступен).
	make func(t *testing.T, e *env, h http.Handler) (AgentTransport, AgentRef)
}

func implementations() []implCase {
	return []implCase{
		{"dial", func(t *testing.T, e *env, h http.Handler) (AgentTransport, AgentRef) {
			if h == nil {
				return e.dial(t), AgentRef{ID: "a1", URL: closedPortURL(t), Mode: config.AgentModeDial}
			}
			return e.dial(t), e.fakeAgent(t, e.ca, "a1", h)
		}},
		{"reverse", func(t *testing.T, _ *env, h http.Handler) (AgentTransport, AgentRef) {
			p := newPool(t)
			if h != nil {
				attachAgent(t, p, "a1", h)
			}
			return p, revRef("a1")
		}},
	}
}

func TestClassifyMatrixBothImpls(t *testing.T) {
	e := newEnv(t)
	rst := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		panic(http.ErrAbortHandler)
	})
	hang := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	})
	tests := []struct {
		name    string
		h       http.Handler
		timeout time.Duration
		kind    Kind
		phase   string
		source  string
		notSent bool
	}{
		{"агент недоступен -> dial", nil, 0, KindTransport, tgapi.PhaseDial, SourceServerAgent, true},
		{"502 + dial", agentSays(tgapi.SourceAgent, tgapi.PhaseDial, 502), 0, KindTransport, tgapi.PhaseDial, tgapi.SourceAgent, true},
		{"503 + pre-send", agentSays(tgapi.SourceAgent, tgapi.PhasePreSend, 503), 0, KindTransport, tgapi.PhasePreSend, tgapi.SourceAgent, true},
		{"502 + write", agentSays(tgapi.SourceAgent, tgapi.PhaseWrite, 502), 0, KindTransport, tgapi.PhaseWrite, tgapi.SourceAgent, false},
		{"RST после тела -> write", rst, 0, KindTransport, tgapi.PhaseWrite, SourceServerAgent, false},
		{"таймаут ответа -> timeout", hang, 300 * time.Millisecond, KindTransport, tgapi.PhaseTimeout, SourceServerAgent, false},
		{"telegram 500 -> не транспорт", agentSays(tgapi.SourceTelegram, "", 500), 0, KindTelegramError, "", tgapi.SourceTelegram, false},
		{"telegram 200 -> OK", agentSays(tgapi.SourceTelegram, "", 200), 0, KindOK, "", tgapi.SourceTelegram, false},
	}
	for _, impl := range implementations() {
		for _, tc := range tests {
			t.Run(impl.name+"/"+tc.name, func(t *testing.T) {
				tr, ref := impl.make(t, e, tc.h)
				ctx := context.Background()
				if tc.timeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.timeout)
					defer cancel()
				}
				body := []byte(`{"chat_id":1,"text":"hi"}`)
				resp, err := tr.RoundTrip(ctx, ref, newReq(ctx, t, http.MethodPost, "/tg/bot1:AAA/sendMessage", bytes.NewReader(body)))
				if resp != nil {
					defer func() { _ = resp.Body.Close() }()
				}
				got := Classify(resp, err, true)
				if got.Kind != tc.kind || got.Phase != tc.phase || got.Source != tc.source || got.NotSent != tc.notSent {
					t.Fatalf("got %+v (err=%v), want kind=%v phase=%q source=%q notSent=%v",
						got, err, tc.kind, tc.phase, tc.source, tc.notSent)
				}
			})
		}
	}
}

func TestReverseContextCanceledIsNotPhase(t *testing.T) {
	p := newPool(t)
	started := make(chan struct{})
	attachAgent(t, p, "a1", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	resp, err := p.RoundTrip(ctx, revRef("a1"), newReq(ctx, t, http.MethodGet, "/x", nil))
	if resp != nil {
		_ = resp.Body.Close()
	}
	if out := Classify(nil, err, false); !out.Canceled {
		t.Fatalf("%+v", out)
	}
}
