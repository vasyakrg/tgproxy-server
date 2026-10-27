package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// mtAgentSide — фейковый агент MTProto-класса: фиксирует стримы по метке соединения
// и сигналы PUT /pool.
type mtAgentSide struct {
	mu      sync.Mutex
	streams map[string]int // метка соединения -> число принятых стримов
	pool    []int
	seen    []*http.Request
}

func newMTAgentSide() *mtAgentSide { return &mtAgentSide{streams: map[string]int{}} }

func (a *mtAgentSide) handler(label string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == MTProtoPoolPath:
			var pr PoolRequest
			_ = json.NewDecoder(r.Body).Decode(&pr)
			a.mu.Lock()
			a.pool = append(a.pool, pr.Conns)
			a.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && len(r.URL.Path) > len(MTProtoPath) && r.URL.Path[:len(MTProtoPath)] == MTProtoPath:
			a.mu.Lock()
			a.streams[label]++
			a.seen = append(a.seen, r.Clone(r.Context()))
			a.mu.Unlock()
			echoHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (a *mtAgentSide) poolCalls() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]int(nil), a.pool...)
}

func (a *mtAgentSide) count(label string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.streams[label]
}

func attachMT(t *testing.T, s *ReverseStream, id string, h http.Handler) net.Conn {
	t.Helper()
	srv, ag := tcpPair(t)
	go (&http2.Server{}).ServeConn(ag, &http2.ServeConnOpts{Handler: h}) //nolint:staticcheck // SA1019: ServeConn поверх готового соединения
	if err := s.Attach(id, srv); err != nil {
		t.Fatal(err)
	}
	return ag
}

func newRS(t *testing.T, opts ...ReverseStreamOption) *ReverseStream {
	t.Helper()
	s := NewReverseStream(opts...)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestReverseStreamEchoAndRequestShape(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t)
	attachMT(t, s, "a1", ag.handler("c1"))
	c := open(t, s, revRef("a1"), -2)
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("%q %v", buf, err)
	}
	ag.mu.Lock()
	defer ag.mu.Unlock()
	r := ag.seen[0]
	if r.Method != http.MethodPost || r.URL.Path != MTProtoPath+"-2" || r.Header.Get(HeaderDC) != "-2" ||
		r.Host != "a1.reverse" || r.ProtoMajor != 2 || r.Header.Get(tgapi.HeaderRequestID) == "" {
		t.Fatalf("bad request: %s %s host=%s hdr=%v", r.Method, r.URL.Path, r.Host, r.Header)
	}
}

func TestReverseStreamNoConn(t *testing.T) {
	s := newRS(t)
	_, err := s.OpenMTProto(context.Background(), revRef("a1"), 2)
	var pe *PhaseError
	if !errors.Is(err, ErrNoReverseConn) || !errors.As(err, &pe) || pe.Phase != tgapi.PhaseDial {
		t.Fatalf("%v", err)
	}
	if _, err := s.OpenMTProto(context.Background(), AgentRef{}, 2); !errors.Is(err, ErrBadAgent) {
		t.Fatalf("%v", err)
	}
}

func TestReverseStreamAgentRefusal(t *testing.T) {
	s := newRS(t)
	attachMT(t, s, "a1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(tgapi.HeaderErrorPhase, tgapi.PhaseDial)
		w.WriteHeader(http.StatusBadGateway)
	}))
	_, err := s.OpenMTProto(context.Background(), revRef("a1"), 2)
	var pe *PhaseError
	var se *StreamStatusError
	if !errors.As(err, &pe) || pe.Phase != tgapi.PhaseDial || !errors.As(err, &se) || se.Status != 502 {
		t.Fatalf("%v", err)
	}
	if got := s.Streams("a1"); got != 0 {
		t.Fatalf("streams=%d после отказа", got)
	}
}

func TestReverseStreamCtxCancelBeforeOpen(t *testing.T) {
	s := newRS(t)
	attachMT(t, s, "a1", newMTAgentSide().handler("c1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.OpenMTProto(ctx, revRef("a1"), 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

func TestReverseStreamLeastLoaded(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t, WithMTProtoSignalInterval(time.Hour))
	attachMT(t, s, "a1", ag.handler("c1"))
	attachMT(t, s, "a1", ag.handler("c2"))
	for range 6 {
		open(t, s, revRef("a1"), 2)
	}
	if a, b := ag.count("c1"), ag.count("c2"); a != 3 || b != 3 {
		t.Fatalf("распределение %d/%d, ожидалось 3/3", a, b)
	}
	if s.Conns("a1") != 2 || s.Streams("a1") != 6 {
		t.Fatalf("conns=%d streams=%d", s.Conns("a1"), s.Streams("a1"))
	}
}

func TestReverseStreamClassesAreSeparate(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t)
	rp := newPool(t)
	botHits := make(chan string, 4)
	attachMT(t, s, "a1", ag.handler("mt"))
	attachAgent(t, rp, "a1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		botHits <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	for range 3 {
		open(t, s, revRef("a1"), 2)
	}
	if st, err := rtGet(t, rp, "a1", "/tg/bot1:AAA/getMe"); err != nil || st != 204 {
		t.Fatalf("%d %v", st, err)
	}
	if got := <-botHits; got != "/tg/bot1:AAA/getMe" {
		t.Fatalf("bot path %q", got)
	}
	if len(botHits) != 0 {
		t.Fatal("MTProto-стримы попали на соединение Bot API")
	}
	if ag.count("mt") != 3 {
		t.Fatalf("mt streams=%d", ag.count("mt"))
	}
	// И наоборот: Bot API-запрос не доходит до MTProto-соединения.
	rs := newRS(t)
	attachMT(t, rs, "a2", ag.handler("mt2"))
	if _, err := rtGet(t, rp, "a2", "/tg/x"); !errors.Is(err, ErrNoReverseConn) {
		t.Fatalf("Bot API по MTProto-пулу: %v", err)
	}
}

func TestReverseStreamSignalsMoreConns(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t, WithMTProtoStreamsPerConn(2), WithMTProtoMaxConns(3), WithMTProtoSignalInterval(20*time.Millisecond))
	attachMT(t, s, "a1", ag.handler("c1"))
	open(t, s, revRef("a1"), 2)
	time.Sleep(50 * time.Millisecond)
	if p := ag.poolCalls(); len(p) != 0 {
		t.Fatalf("сигнал при низкой нагрузке: %v", p)
	}
	open(t, s, revRef("a1"), 2) // 2 стрима = max_streams_per_conn × 1
	eventually(t, "PUT conns=2", func() bool { p := ag.poolCalls(); return len(p) == 1 && p[0] == 2 })

	attachMT(t, s, "a1", ag.handler("c2"))
	time.Sleep(30 * time.Millisecond)
	open(t, s, revRef("a1"), 2)
	open(t, s, revRef("a1"), 2) // 4 стрима = 2 × 2
	eventually(t, "PUT conns=3", func() bool { p := ag.poolCalls(); return len(p) == 2 && p[1] == 3 })

	attachMT(t, s, "a1", ag.handler("c3"))
	time.Sleep(30 * time.Millisecond)
	for range 6 {
		open(t, s, revRef("a1"), 2)
	}
	time.Sleep(80 * time.Millisecond)
	if p := ag.poolCalls(); len(p) != 2 {
		t.Fatalf("запрос сверх max_conns: %v", p)
	}
}

func TestReverseStreamSignalDebounced(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t, WithMTProtoStreamsPerConn(1), WithMTProtoMaxConns(10), WithMTProtoSignalInterval(time.Hour))
	attachMT(t, s, "a1", ag.handler("c1"))
	for range 5 {
		open(t, s, revRef("a1"), 2)
	}
	eventually(t, "один PUT", func() bool { return len(ag.poolCalls()) == 1 })
	time.Sleep(50 * time.Millisecond)
	if p := ag.poolCalls(); len(p) != 1 {
		t.Fatalf("дебаунс не сработал: %v", p)
	}
}

func TestReverseStreamShrinksWithHysteresis(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t, WithMTProtoStreamsPerConn(2), WithMTProtoSignalInterval(10*time.Millisecond),
		WithMTProtoShrinkAfter(150*time.Millisecond))
	attachMT(t, s, "a1", ag.handler("c1"))
	attachMT(t, s, "a1", ag.handler("c2"))
	c := open(t, s, revRef("a1"), 2) // 1 стрим при 2 соединениях: уменьшать можно
	time.Sleep(50 * time.Millisecond)
	_ = c.Close()
	if p := ag.poolCalls(); len(p) != 0 {
		t.Fatalf("уменьшение раньше гистерезиса: %v", p)
	}
	time.Sleep(200 * time.Millisecond)
	open(t, s, revRef("a1"), 2)
	eventually(t, "PUT conns=1", func() bool { p := ag.poolCalls(); return len(p) == 1 && p[0] == 1 })
}

func TestReverseStreamConnDropKillsOnlyItsStreams(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t, WithMTProtoSignalInterval(time.Hour))
	rp := newPool(t)
	botAgent := attachAgent(t, rp, "a1", okHandler)
	c1 := attachMT(t, s, "a1", ag.handler("c1"))
	var streams []net.Conn
	for range 2 {
		streams = append(streams, open(t, s, revRef("a1"), 2))
	}
	attachMT(t, s, "a1", ag.handler("c2"))
	live := open(t, s, revRef("a1"), 2)
	_ = c1.Close() // агент оборвал первое MTProto-соединение

	for _, st := range streams {
		_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := st.Read(make([]byte, 1)); err == nil {
			t.Fatal("стрим оборванного соединения жив")
		}
	}
	eventually(t, "conns=1", func() bool { return s.Conns("a1") == 1 })
	if _, err := live.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(live, b); err != nil || b[0] != 'x' {
		t.Fatalf("%q %v", b, err)
	}
	if rp.Conns("a1") != 1 {
		t.Fatal("соединение Bot API затронуто")
	}
	if st, err := rtGet(t, rp, "a1", "/tg/x"); err != nil || st != 200 {
		t.Fatalf("Bot API после обрыва MTProto: %d %v", st, err)
	}
	_ = botAgent
}

func TestReverseStreamFailsOverToLiveConn(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t, WithMTProtoSignalInterval(time.Hour))
	c1 := attachMT(t, s, "a1", ag.handler("c1"))
	attachMT(t, s, "a1", ag.handler("c2"))
	_ = c1.Close()
	for range 5 {
		open(t, s, revRef("a1"), 2)
	}
	if ag.count("c2") != 5 {
		t.Fatalf("c2=%d", ag.count("c2"))
	}
}

func TestReverseStreamEvictsOldestKeepsItsStreams(t *testing.T) {
	ag := newMTAgentSide()
	var detached sync.WaitGroup
	detached.Add(1)
	var once sync.Once
	s := newRS(t, WithMTProtoMaxConns(1), WithMTProtoSignalInterval(time.Hour),
		WithMTProtoOnDetach(func(string, int) { once.Do(detached.Done) }))
	attachMT(t, s, "a1", ag.handler("c1"))
	old := open(t, s, revRef("a1"), 2)
	attachMT(t, s, "a1", ag.handler("c2"))
	detached.Wait()
	if s.Conns("a1") != 1 {
		t.Fatalf("conns=%d", s.Conns("a1"))
	}
	if _, err := old.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(old, b); err != nil || b[0] != 'z' {
		t.Fatalf("стрим вытесненного соединения должен дожить: %q %v", b, err)
	}
	open(t, s, revRef("a1"), 2)
	if ag.count("c2") != 1 {
		t.Fatalf("новый стрим не на новом соединении: c2=%d", ag.count("c2"))
	}
}

func TestReverseStreamCloseClosesStreams(t *testing.T) {
	ag := newMTAgentSide()
	s := NewReverseStream()
	attachMT(t, s, "a1", ag.handler("c1"))
	c, err := s.OpenMTProto(context.Background(), revRef("a1"), 2)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("стрим жив после Close")
	}
	_ = c.Close()
	srv, _ := tcpPair(t)
	if err := s.Attach("a1", srv); !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
}

func TestRegistryReverseStream(t *testing.T) {
	ag := newMTAgentSide()
	s := newRS(t)
	attachMT(t, s, "a1", ag.handler("c1"))
	r := NewRegistry(nil)
	r.RegisterStream(config.AgentModeReverse, s)
	c, err := r.OpenMTProto(context.Background(), revRef("a1"), 4)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	// both: dial недоступен -> стрим по reverse
	b := Both{DialStream: &fakeStream{err: &PhaseError{Phase: tgapi.PhaseDial, Source: SourceServerAgent, Err: errors.New("x")}}, ReverseStream: s}
	c2, err := b.OpenMTProto(context.Background(), AgentRef{ID: "a1", Mode: config.AgentModeBoth}, 2)
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()
}
