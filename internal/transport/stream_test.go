package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// flushWriter сбрасывает каждую запись: стрим без буферизации.
type flushWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		err = f.rc.Flush()
	}
	return n, err
}

func accept(w http.ResponseWriter) flushWriter {
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	return flushWriter{w, rc}
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	fw := accept(w)
	_, _ = io.Copy(fw, r.Body)
}

// streamAgent поднимает фейковый h2-агент с лимитом параллельных стримов.
func (e *env) streamAgent(t *testing.T, id string, maxStreams int, h http.Handler) AgentRef {
	t.Helper()
	cfg, err := pki.ServerTLSConfig(agentCert(t, e.ca, id), e.pool, pki.VerifyServerPeer(e.pool))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = cfg
	s.EnableHTTP2 = true
	if maxStreams > 0 {
		s.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: maxStreams}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	return AgentRef{ID: id, URL: u, Mode: config.AgentModeDial}
}

func (e *env) streams(t *testing.T, opts ...Option) *DialStream {
	t.Helper()
	d := NewDialStream(e.srvCert, e.pool, opts...)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func open(t *testing.T, st StreamTransport, ref AgentRef, dc int) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := st.OpenMTProto(ctx, ref, dc)
	if err != nil {
		t.Fatalf("OpenMTProto: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type halfCloser interface {
	CloseWrite() error
	CloseRead() error
}

func TestStreamRequestShape(t *testing.T) {
	e := newEnv(t)
	got := make(chan *http.Request, 1)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r
		echoHandler(w, r)
	}))
	c := open(t, e.streams(t), ref, -2)
	r := <-got
	if r.Method != http.MethodPost || r.URL.Path != "/_agent/mtproto/dc/-2" || r.Proto != "HTTP/2.0" {
		t.Fatalf("%s %s %s", r.Method, r.URL.Path, r.Proto)
	}
	if r.Header.Get(HeaderDC) != "-2" {
		t.Fatalf("dc header %q", r.Header.Get(HeaderDC))
	}
	if _, err := ulid.ParseStrict(r.Header.Get(tgapi.HeaderRequestID)); err != nil {
		t.Fatalf("request id: %v", err)
	}
	if _, ok := c.(halfCloser); !ok {
		t.Fatal("conn без CloseWrite/CloseRead")
	}
}

func TestStreamOpenReturnsOnlyAfter200(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // «агент ещё соединяется с DC»
		echoHandler(w, r)
	}))
	st := e.streams(t)
	type res struct {
		c   net.Conn
		err error
	}
	done := make(chan res, 1)
	go func() {
		c, err := st.OpenMTProto(context.Background(), ref, 2)
		done <- res{c, err}
	}()
	select {
	case <-done:
		t.Fatal("OpenMTProto вернулся до ответа 200")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		t.Cleanup(func() { _ = r.c.Close() })
	case <-time.After(5 * time.Second):
		t.Fatal("OpenMTProto не вернулся после 200")
	}
}

func TestStreamAgentRefusals(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name   string
		code   int
		phase  string
		want   string
		source string
	}{
		{"bad dc", 400, "", tgapi.PhasePreSend, tgapi.SourceAgent},
		{"forbidden", 403, "", tgapi.PhasePreSend, tgapi.SourceAgent},
		{"disabled", 404, "", tgapi.PhasePreSend, tgapi.SourceAgent},
		{"dc dial", 502, tgapi.PhaseDial, tgapi.PhaseDial, tgapi.SourceAgent},
		{"dc timeout", 502, tgapi.PhaseTimeout, tgapi.PhaseTimeout, tgapi.SourceAgent},
		{"limit", 503, tgapi.PhasePreSend, tgapi.PhasePreSend, tgapi.SourceAgent},
		{"garbage phase", 502, "bogus", tgapi.PhasePreSend, tgapi.SourceAgent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := e.streamAgent(t, "a1", 0, agentSays(tgapi.SourceAgent, tc.phase, tc.code))
			_, err := e.streams(t).OpenMTProto(context.Background(), ref, 2) //nolint:bodyclose // не http-ответ
			var pe *PhaseError
			if !errors.As(err, &pe) {
				t.Fatalf("want *PhaseError, got %v", err)
			}
			if pe.Phase != tc.want || pe.Source != tc.source {
				t.Fatalf("phase=%q source=%q", pe.Phase, pe.Source)
			}
			var se *StreamStatusError
			if !errors.As(err, &se) || se.Status != tc.code || se.AgentID != "a1" {
				t.Fatalf("status error: %v", err)
			}
			if out := Classify(nil, err, false); out.NotSent != tgapi.PhaseNotSent(tc.want) {
				t.Fatalf("NotSent=%v", out.NotSent)
			}
		})
	}
}

func TestStreamHalfClose(t *testing.T) {
	e := newEnv(t)
	gotBody := make(chan []byte, 1)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fw := accept(w)
		_, _ = fw.Write([]byte("hello"))
		b, _ := io.ReadAll(r.Body) // вернётся только по EOF от клиента
		gotBody <- b
		_, _ = fw.Write([]byte("bye"))
	}))
	c := open(t, e.streams(t), ref, 2)
	hc := c.(halfCloser)

	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("%q %v", buf, err)
	}
	if _, err := c.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gotBody:
		t.Fatal("агент увидел EOF до CloseWrite")
	case <-time.After(100 * time.Millisecond):
	}
	if err := hc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if b := <-gotBody; string(b) != "abc" {
		t.Fatalf("agent got %q", b)
	}
	rest, err := io.ReadAll(c) // обратное направление живо; EOF после завершения хендлера
	if err != nil || string(rest) != "bye" {
		t.Fatalf("%q %v", rest, err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write после CloseWrite должен падать")
	}
}

func TestStreamCloseReadKeepsWrite(t *testing.T) {
	e := newEnv(t)
	gotBody := make(chan []byte, 1)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fw := accept(w)
		_, _ = fw.Write([]byte("ignored"))
		b, _ := io.ReadAll(r.Body)
		gotBody <- b
	}))
	c := open(t, e.streams(t), ref, 2)
	hc := c.(halfCloser)
	_ = hc.CloseRead()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read после CloseRead: %v", err)
	}
	if _, err := c.Write([]byte("xyz")); err != nil {
		t.Fatal(err)
	}
	_ = hc.CloseWrite()
	if b := <-gotBody; string(b) != "xyz" {
		t.Fatalf("%q", b)
	}
}

func TestStreamEchoLarge(t *testing.T) {
	e := newEnv(t)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(echoHandler))
	c := open(t, e.streams(t), ref, 2)

	payload := make([]byte, 5<<20)
	_, _ = rand.Read(payload)
	werr := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		werr <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if err := <-werr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("эхо не совпало")
	}
}

func TestStreamAddrs(t *testing.T) {
	e := newEnv(t)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(echoHandler))
	c := open(t, e.streams(t), ref, 2)
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.String() != ref.URL.Host {
		t.Fatalf("remote %v (%T), want %s", c.RemoteAddr(), c.RemoteAddr(), ref.URL.Host)
	}
	la, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || la.Port == 0 {
		t.Fatalf("local %v (%T)", c.LocalAddr(), c.LocalAddr())
	}
}

func TestStreamReadDeadline(t *testing.T) {
	e := newEnv(t)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fw := accept(w)
		_, _ = io.ReadFull(r.Body, make([]byte, 1)) // ждём байт от клиента
		_, _ = fw.Write([]byte("late"))
		<-r.Context().Done()
	}))
	c := open(t, e.streams(t), ref, 2)

	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := c.Read(make([]byte, 4))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want timeout, got %v", err)
	}
	// Дедлайн переустанавливается: данные, пришедшие позже, читаются.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("k")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "late" {
		t.Fatalf("%q %v", buf, err)
	}
	// Дедлайн в прошлом срабатывает сразу.
	_ = c.SetReadDeadline(time.Unix(1, 0))
	if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestStreamWriteDeadline(t *testing.T) {
	e := newEnv(t)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept(w)
		<-r.Context().Done() // тело не читаем: окно заполнится
	}))
	c := open(t, e.streams(t, WithStreamWindow(64<<10)), ref, 2)
	_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	start := time.Now()
	_, err := c.Write(make([]byte, 64<<20))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("дедлайн записи не сработал вовремя")
	}
}

func TestStreamCloseResetsStream(t *testing.T) {
	e := newEnv(t)
	ended := make(chan struct{}, 1)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept(w)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		ended <- struct{}{}
	}))
	c := open(t, e.streams(t), ref, 2)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil { // идемпотентность
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("агент не увидел сброс стрима")
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read: %v", err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write: %v", err)
	}
	if err := c.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetDeadline: %v", err)
	}
}

func TestStreamAgentClosesStream(t *testing.T) {
	e := newEnv(t)
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fw := accept(w)
		_, _ = fw.Write([]byte("last"))
	}))
	c := open(t, e.streams(t), ref, 2)
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "last" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF должен быть липким: %v", err)
	}
	// Агент завершил ответ: запись больше невозможна.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := c.Write([]byte("x")); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("запись в закрытый агентом стрим не завершилась ошибкой")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStreamOpenCtx(t *testing.T) {
	e := newEnv(t)
	hold := make(chan struct{})
	ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hold:
		case <-r.Context().Done():
			return
		}
		echoHandler(w, r)
	}))
	st := e.streams(t)
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		_, err := st.OpenMTProto(ctx, ref, 2) //nolint:bodyclose // не http-ответ
		var pe *PhaseError
		if !errors.As(err, &pe) || pe.Phase != tgapi.PhaseTimeout {
			t.Fatalf("want timeout PhaseError, got %v", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(100 * time.Millisecond); cancel() }()
		_, err := st.OpenMTProto(ctx, ref, 2) //nolint:bodyclose // не http-ответ
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want Canceled, got %v", err)
		}
	})
	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := st.OpenMTProto(ctx, ref, 2); !errors.Is(err, context.Canceled) { //nolint:bodyclose // не http-ответ
			t.Fatalf("%v", err)
		}
	})
	t.Run("ctx cancel after open does not kill stream", func(t *testing.T) {
		close(hold)
		ctx, cancel := context.WithCancel(context.Background())
		c, err := st.OpenMTProto(ctx, ref, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		cancel()
		time.Sleep(100 * time.Millisecond)
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%q %v", buf, err)
		}
	})
}

func TestStreamDialErrors(t *testing.T) {
	e := newEnv(t)
	st := e.streams(t, WithDialTimeout(time.Second))

	t.Run("connection refused", func(t *testing.T) {
		ref := AgentRef{ID: "a1", URL: closedPortURL(t), Mode: config.AgentModeDial}
		_, err := st.OpenMTProto(context.Background(), ref, 2) //nolint:bodyclose // не http-ответ
		var pe *PhaseError
		if !errors.As(err, &pe) || pe.Phase != tgapi.PhaseDial || pe.Source != SourceServerAgent {
			t.Fatalf("%v", err)
		}
	})
	t.Run("agent identity mismatch", func(t *testing.T) {
		ref := e.streamAgent(t, "other-agent", 0, http.HandlerFunc(echoHandler))
		ref.ID = "a1"
		_, err := st.OpenMTProto(context.Background(), ref, 2) //nolint:bodyclose // не http-ответ
		var pe *PhaseError
		if !errors.As(err, &pe) || pe.Phase != tgapi.PhaseTLS {
			t.Fatalf("%v", err)
		}
	})
	t.Run("bad ref", func(t *testing.T) {
		if _, err := st.OpenMTProto(context.Background(), AgentRef{ID: "x"}, 2); !errors.Is(err, ErrBadAgent) { //nolint:bodyclose // не http-ответ
			t.Fatalf("%v", err)
		}
	})
	t.Run("closed", func(t *testing.T) {
		d := NewDialStream(e.srvCert, e.pool)
		_ = d.Close()
		ref := e.streamAgent(t, "a1", 0, http.HandlerFunc(echoHandler))
		if _, err := d.OpenMTProto(context.Background(), ref, 2); !errors.Is(err, ErrClosed) { //nolint:bodyclose // не http-ответ
			t.Fatalf("%v", err)
		}
	})
}

// Bot API-запросы (Dial) и MTProto-стримы (DialStream) идут по разным TCP:
// 500 стримов не занимают соединение Bot API.
func TestStreamSeparateTCPFromBotAPI(t *testing.T) {
	const n = 500
	e := newEnv(t)
	var (
		mu       sync.Mutex
		streamRA = map[string]bool{}
		botRA    = map[string]bool{}
		started  sync.WaitGroup
	)
	started.Add(n)
	ref := e.streamAgent(t, "a1", n, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.URL.Path == "/tg/ping" {
			botRA[r.RemoteAddr] = true
			mu.Unlock()
			w.Header().Set(tgapi.HeaderSource, tgapi.SourceTelegram)
			_, _ = w.Write([]byte("{}"))
			return
		}
		streamRA[r.RemoteAddr] = true
		mu.Unlock()
		accept(w)
		started.Done()
		<-r.Context().Done()
	}))
	st := e.streams(t)
	dial := e.dial(t)

	conns := make([]net.Conn, n)
	var wg sync.WaitGroup
	for i := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c, err := st.OpenMTProto(ctx, ref, 2)
			if err != nil {
				t.Error(err)
				return
			}
			conns[i] = c
		}()
	}
	wg.Wait()
	t.Cleanup(func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	})
	started.Wait()

	for range 3 {
		resp, _ := do(t, dial, ref, http.MethodGet, "/tg/ping", nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if len(botRA) == 0 || len(streamRA) == 0 {
		t.Fatalf("bot=%d stream=%d", len(botRA), len(streamRA))
	}
	for a := range botRA {
		if streamRA[a] {
			t.Fatalf("Bot API и MTProto делят TCP-соединение %s", a)
		}
	}
	// 500 стримов при лимите агента 500 умещаются в небольшое число соединений.
	if len(streamRA) > 4 {
		t.Fatalf("слишком много TCP под стримы: %d", len(streamRA))
	}
}

// Достигнут SETTINGS_MAX_CONCURRENT_STREAMS агента — поднимается новое
// соединение, а не блокируется вызывающий.
func TestStreamOpensNewTCPAtStreamLimit(t *testing.T) {
	e := newEnv(t)
	var (
		mu sync.Mutex
		ra = map[string]bool{}
	)
	ref := e.streamAgent(t, "a1", 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ra[r.RemoteAddr] = true
		mu.Unlock()
		echoHandler(w, r)
	}))
	st := e.streams(t)
	for range 6 {
		open(t, st, ref, 2)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ra) < 3 {
		t.Fatalf("ожидалось ≥3 TCP при лимите 2 стрима на соединение, есть %d", len(ra))
	}
}

func TestStreamKeepsConnAcrossAgents(t *testing.T) {
	e := newEnv(t)
	a := e.streamAgent(t, "a1", 0, http.HandlerFunc(echoHandler))
	b := e.streamAgent(t, "a2", 0, http.HandlerFunc(echoHandler))
	st := e.streams(t)
	ca, cb := open(t, st, a, 2), open(t, st, b, 3)
	if ca.RemoteAddr().String() == cb.RemoteAddr().String() {
		t.Fatal("разные агенты — разные соединения")
	}
	for _, c := range []net.Conn{ca, cb} {
		if _, err := c.Write([]byte(strconv.Itoa(7))); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		if _, err := io.ReadFull(c, buf); err != nil || buf[0] != '7' {
			t.Fatalf("%q %v", buf, err)
		}
	}
}

type fakeStream struct {
	calls int
	err   error
}

func (f *fakeStream) OpenMTProto(context.Context, AgentRef, int) (net.Conn, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	c, _ := net.Pipe()
	return c, nil
}

func TestRegistryOpenMTProto(t *testing.T) {
	r := NewRegistry(nil)
	ctx := context.Background()
	dial := &fakeStream{}
	r.RegisterStream(config.AgentModeDial, dial)

	c, err := r.OpenMTProto(ctx, AgentRef{ID: "a", Mode: config.AgentModeDial}, 2)
	if err != nil || dial.calls != 1 {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, err := r.OpenMTProto(ctx, AgentRef{ID: "a", Mode: config.AgentModeReverse}, 2); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("reverse: %v", err)
	}
	if _, err := r.OpenMTProto(ctx, AgentRef{ID: "a", Mode: "weird"}, 2); !errors.Is(err, ErrModeUnsupported) {
		t.Fatalf("weird: %v", err)
	}
	rev := &fakeStream{}
	r.RegisterStream(config.AgentModeReverse, rev) // M11-T1: без изменения интерфейса
	c, err = r.OpenMTProto(ctx, AgentRef{ID: "a", Mode: config.AgentModeReverse}, 2)
	if err != nil || rev.calls != 1 {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestBothOpenMTProto(t *testing.T) {
	ctx := context.Background()
	ref := AgentRef{ID: "a", Mode: config.AgentModeBoth}
	notSent := &PhaseError{Phase: tgapi.PhaseDial, Source: SourceServerAgent, Err: errors.New("refused")}
	sent := &PhaseError{Phase: tgapi.PhaseWrite, Source: SourceServerAgent, Err: errors.New("reset")}

	t.Run("dial ok", func(t *testing.T) {
		d, r := &fakeStream{}, &fakeStream{}
		c, err := Both{DialStream: d, ReverseStream: r}.OpenMTProto(ctx, ref, 2)
		if err != nil || d.calls != 1 || r.calls != 0 {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("not sent falls back", func(t *testing.T) {
		d, r := &fakeStream{err: notSent}, &fakeStream{}
		c, err := Both{DialStream: d, ReverseStream: r}.OpenMTProto(ctx, ref, 2)
		if err != nil || r.calls != 1 {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("sent does not fall back", func(t *testing.T) {
		d, r := &fakeStream{err: sent}, &fakeStream{}
		if _, err := (Both{DialStream: d, ReverseStream: r}).OpenMTProto(ctx, ref, 2); err != sent || r.calls != 0 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("reverse unsupported keeps dial error", func(t *testing.T) {
		d, r := &fakeStream{err: notSent}, &fakeStream{err: ErrNotSupported}
		if _, err := (Both{DialStream: d, ReverseStream: r}).OpenMTProto(ctx, ref, 2); err != notSent {
			t.Fatalf("%v", err)
		}
	})
	t.Run("no reverse impl", func(t *testing.T) {
		d := &fakeStream{err: notSent}
		if _, err := (Both{DialStream: d}).OpenMTProto(ctx, ref, 2); err != notSent {
			t.Fatalf("%v", err)
		}
	})
	t.Run("no dial impl", func(t *testing.T) {
		if _, err := (Both{}).OpenMTProto(ctx, ref, 2); !errors.Is(err, ErrNotSupported) {
			t.Fatalf("%v", err)
		}
	})
}
