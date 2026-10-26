package agents

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

type fakeSink struct {
	mu       sync.Mutex
	cands    []balancer.Candidate
	healthy  map[string]bool
	draining map[string]bool
	updates  int
}

func newSink() *fakeSink {
	return &fakeSink{healthy: map[string]bool{}, draining: map[string]bool{}}
}
func (s *fakeSink) Update(c []balancer.Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cands = append([]balancer.Candidate(nil), c...)
	s.updates++
	keep := map[string]bool{}
	for _, x := range c {
		keep[x.ID] = true
		if _, ok := s.healthy[x.ID]; !ok {
			s.healthy[x.ID] = true // как настоящий Balancer
		}
	}
	for id := range s.healthy {
		if !keep[id] {
			delete(s.healthy, id)
			delete(s.draining, id)
		}
	}
}
func (s *fakeSink) SetHealthy(id string, h bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy[id] = h
}
func (s *fakeSink) SetDraining(id string, d bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.draining[id] = d
}
func (s *fakeSink) isHealthy(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthy[id]
}
func (s *fakeSink) isDraining(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.draining[id]
}
func (s *fakeSink) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.cands {
		out = append(out, c.ID)
	}
	return out
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// statusScript — управляемый StatusFunc.
type statusScript struct {
	mu    sync.Mutex
	err   error
	drain bool
	calls int
	seen  []transport.AgentRef
	block bool
}

func (s *statusScript) fn(ctx context.Context, ref transport.AgentRef) (*transport.AgentStatus, error) {
	s.mu.Lock()
	s.calls++
	s.seen = append(s.seen, ref)
	err, drain, block := s.err, s.drain, s.block
	s.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return &transport.AgentStatus{Version: "v1", Draining: drain}, nil
}
func (s *statusScript) set(err error, drain bool) {
	s.mu.Lock()
	s.err, s.drain = err, drain
	s.mu.Unlock()
}
func (s *statusScript) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// manualTimers — таймеры, срабатывающие вручную.
type manualTimers struct {
	mu      sync.Mutex
	pending []*mt
	created atomic.Int32
}
type mt struct {
	d  time.Duration
	ch chan time.Time
}

func (m *manualTimers) fn(d time.Duration) (<-chan time.Time, func() bool) {
	t := &mt{d: d, ch: make(chan time.Time, 1)}
	m.mu.Lock()
	m.pending = append(m.pending, t)
	m.mu.Unlock()
	m.created.Add(1)
	return t.ch, func() bool { return true }
}

// fireAll срабатывает на всех ожидающих таймерах.
func (m *manualTimers) fireAll() int {
	m.mu.Lock()
	p := m.pending
	m.pending = nil
	m.mu.Unlock()
	for _, t := range p {
		t.ch <- time.Time{}
	}
	return len(p)
}
func (m *manualTimers) durations() []time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []time.Duration
	for _, t := range m.pending {
		out = append(out, t.d)
	}
	return out
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached")
}

type env struct {
	reg   *Registry
	repo  store.AgentRepo
	sink  *fakeSink
	st    *statusScript
	clock *fakeClock
	tm    *manualTimers
}

func newEnv(t *testing.T, ids ...string) *env {
	t.Helper()
	repo := memtest.New().Agents()
	for _, id := range ids {
		if _, err := repo.Create(context.Background(), store.Agent{ID: id, Name: id, URL: "https://" + id + ":8443", Mode: store.ModeDial, Weight: 1}); err != nil {
			t.Fatal(err)
		}
	}
	e := &env{repo: repo, sink: newSink(), st: &statusScript{}, clock: &fakeClock{t: time.Unix(1000, 0)}, tm: &manualTimers{}}
	e.reg = New(repo, nil, e.sink,
		WithClock(e.clock.Now), WithTicker(e.tm.fn), WithStatusFunc(e.st.fn),
		WithRand(func() float64 { return 0.5 }), WithReloadInterval(0))
	if err := e.reg.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) poll(id string) { e.reg.pollOnce(context.Background(), id) }

func drain(ch <-chan Event) []Event {
	var out []Event
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func types(evs []Event) []EventType {
	var out []EventType
	for _, e := range evs {
		out = append(out, e.Type)
	}
	return out
}

func TestRefreshInitialAndNewAgentDownUntilConfirmed(t *testing.T) {
	e := newEnv(t, "a1", "a2")
	if got := e.sink.ids(); len(got) != 2 {
		t.Fatalf("candidates=%v", got)
	}
	s, ok := e.reg.Get("a1")
	if !ok || s.Up {
		t.Fatalf("new agent must be down until first poll: %+v", s)
	}
	if e.sink.isHealthy("a1") {
		t.Fatal("sink must see new agent as unhealthy")
	}
	e.poll("a1")
	if s, _ := e.reg.Get("a1"); !s.Up || s.LastStatus == nil || !s.LastSeen.Equal(e.clock.Now()) {
		t.Fatalf("after success: %+v", s)
	}
	if !e.sink.isHealthy("a1") || e.sink.isHealthy("a2") {
		t.Fatal("health sync")
	}
	if l := e.reg.List(); len(l) != 2 || l[0].Agent.ID != "a1" {
		t.Fatalf("list=%+v", l)
	}
	if _, ok := e.reg.Get("zzz"); ok {
		t.Fatal("unknown agent")
	}
}

func TestDownAfterThreeFailuresOneEvent(t *testing.T) {
	e := newEnv(t, "a1")
	ch, cancel := e.reg.Subscribe()
	defer cancel()
	e.poll("a1") // up
	drain(ch)
	e.st.set(errors.New("boom"), false)
	e.poll("a1")
	e.poll("a1")
	if s, _ := e.reg.Get("a1"); !s.Up || s.ConsecutiveFails != 2 {
		t.Fatalf("2 fails must not down: %+v", s)
	}
	if !e.sink.isHealthy("a1") {
		t.Fatal("still healthy")
	}
	e.poll("a1")
	e.poll("a1")
	e.poll("a1")
	s, _ := e.reg.Get("a1")
	if s.Up || e.sink.isHealthy("a1") {
		t.Fatal("must be down")
	}
	if got := types(drain(ch)); len(got) != 1 || got[0] != AgentDown {
		t.Fatalf("events=%v", got)
	}
}

func TestUpAfterSingleSuccessOneEvent(t *testing.T) {
	e := newEnv(t, "a1")
	ch, cancel := e.reg.Subscribe()
	defer cancel()
	e.st.set(errors.New("x"), false)
	for range 3 {
		e.poll("a1")
	}
	// агент никогда не был up: down-события нет
	if got := types(drain(ch)); len(got) != 0 {
		t.Fatalf("events=%v", got)
	}
	e.st.set(nil, false)
	e.poll("a1")
	e.poll("a1")
	if got := types(drain(ch)); len(got) != 1 || got[0] != AgentUp {
		t.Fatalf("events=%v", got)
	}
	if s, _ := e.reg.Get("a1"); s.ConsecutiveFails != 0 || !e.sink.isHealthy("a1") {
		t.Fatal("up state")
	}
	// down -> один успех -> up
	e.st.set(errors.New("x"), false)
	for range 3 {
		e.poll("a1")
	}
	e.st.set(nil, false)
	e.poll("a1")
	if got := types(drain(ch)); len(got) != 2 || got[0] != AgentDown || got[1] != AgentUp {
		t.Fatalf("events=%v", got)
	}
}

func TestNilStatusIsFailure(t *testing.T) {
	e := newEnv(t, "a1")
	e.reg.status = func(context.Context, transport.AgentRef) (*transport.AgentStatus, error) { return nil, nil }
	e.poll("a1")
	if s, _ := e.reg.Get("a1"); s.Up || s.ConsecutiveFails != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestDrainingFromAgentStatusImmediate(t *testing.T) {
	e := newEnv(t, "a1")
	ch, cancel := e.reg.Subscribe()
	defer cancel()
	e.poll("a1")
	drain(ch)
	e.st.set(nil, true)
	e.poll("a1")
	e.poll("a1")
	if !e.sink.isDraining("a1") {
		t.Fatal("sink draining")
	}
	evs := drain(ch)
	if len(evs) != 1 || evs[0].Type != AgentDraining || !evs[0].Draining {
		t.Fatalf("events=%+v", evs)
	}
	e.st.set(nil, false)
	e.poll("a1")
	if e.sink.isDraining("a1") {
		t.Fatal("draining must clear")
	}
}

func TestSetDrainingWritesDBAndSink(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "a1")
	e.poll("a1")
	ch, cancel := e.reg.Subscribe()
	defer cancel()
	if err := e.reg.SetDraining(ctx, "a1", true); err != nil {
		t.Fatal(err)
	}
	a, _ := e.repo.Get(ctx, "a1")
	if !a.Draining || !e.sink.isDraining("a1") {
		t.Fatal("db+sink")
	}
	if s, _ := e.reg.Get("a1"); !s.Draining {
		t.Fatal("state")
	}
	if evs := drain(ch); len(evs) != 1 || evs[0].Type != AgentDraining {
		t.Fatalf("%+v", evs)
	}
	// статус агента draining=false не снимает draining из БД
	e.poll("a1")
	if !e.sink.isDraining("a1") {
		t.Fatal("db draining must persist")
	}
	if err := e.reg.SetDraining(ctx, "a1", false); err != nil {
		t.Fatal(err)
	}
	if e.sink.isDraining("a1") {
		t.Fatal("cleared")
	}
	if err := e.reg.SetDraining(ctx, "nope", true); err == nil {
		t.Fatal("expected error")
	}
}

func TestSetWeight(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "a1", "a2")
	e.poll("a1")
	if err := e.reg.SetWeight(ctx, "a1", 5); err != nil {
		t.Fatal(err)
	}
	e.sink.mu.Lock()
	var w int
	for _, c := range e.sink.cands {
		if c.ID == "a1" {
			w = c.Weight
		}
	}
	e.sink.mu.Unlock()
	if w != 5 {
		t.Fatalf("weight=%d", w)
	}
	if !e.sink.isHealthy("a1") {
		t.Fatal("health must survive Update")
	}
	// вес 0 — агент вне кандидатов
	if err := e.reg.SetWeight(ctx, "a2", 0); err != nil {
		t.Fatal(err)
	}
	if ids := e.sink.ids(); len(ids) != 1 || ids[0] != "a1" {
		t.Fatalf("ids=%v", ids)
	}
	if err := e.reg.SetWeight(ctx, "nope", 1); err == nil {
		t.Fatal("expected error")
	}
}

func TestRefreshAddRemove(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "a1")
	ch, cancel := e.reg.Subscribe()
	defer cancel()
	if _, err := e.repo.Create(ctx, store.Agent{ID: "a2", Name: "a2", URL: "https://a2:8443", Mode: store.ModeDial, Weight: 2}); err != nil {
		t.Fatal(err)
	}
	if err := e.reg.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if ids := e.sink.ids(); len(ids) != 2 {
		t.Fatalf("ids=%v", ids)
	}
	if err := e.repo.Delete(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := e.reg.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if ids := e.sink.ids(); len(ids) != 1 || ids[0] != "a2" {
		t.Fatalf("ids=%v", ids)
	}
	if _, ok := e.reg.Ref("a1"); ok {
		t.Fatal("removed")
	}
	got := types(drain(ch))
	if len(got) != 2 || got[0] != AgentAdded || got[1] != AgentRemoved {
		t.Fatalf("events=%v", got)
	}
	// без изменений Update не вызывается
	before := e.sink.updates
	if err := e.reg.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if e.sink.updates != before {
		t.Fatal("no-op refresh must not Update")
	}
}

func TestRef(t *testing.T) {
	e := newEnv(t, "a1")
	ref, ok := e.reg.Ref("a1")
	if !ok || ref.ID != "a1" || ref.URL == nil || ref.URL.Host != "a1:8443" || ref.Mode != config.AgentModeDial {
		t.Fatalf("%+v", ref)
	}
	if _, err := e.repo.Create(context.Background(), store.Agent{ID: "r1", Name: "r1", Mode: store.ModeReverse, Weight: 1}); err != nil {
		t.Fatal(err)
	}
	_ = e.reg.Refresh(context.Background())
	ref, _ = e.reg.Ref("r1")
	if ref.URL != nil || ref.Mode != config.AgentModeReverse {
		t.Fatalf("%+v", ref)
	}
}

func TestPassiveErrorsDown(t *testing.T) {
	e := newEnv(t, "a1")
	e.poll("a1")
	ch, cancel := e.reg.Subscribe()
	defer cancel()
	e.reg.ReportResult("a1", true)
	e.reg.ReportResult("a1", true)
	e.reg.ReportResult("a1", false) // сброс
	e.reg.ReportResult("a1", true)
	e.reg.ReportResult("a1", true)
	if s, _ := e.reg.Get("a1"); !s.Up {
		t.Fatal("must stay up")
	}
	e.reg.ReportResult("a1", true)
	e.reg.ReportResult("a1", true)
	if s, _ := e.reg.Get("a1"); s.Up || e.sink.isHealthy("a1") {
		t.Fatal("must be down")
	}
	if got := types(drain(ch)); len(got) != 1 || got[0] != AgentDown {
		t.Fatalf("events=%v", got)
	}
	// трафик из down не поднимает; опрос поднимает
	e.reg.ReportResult("a1", false)
	if s, _ := e.reg.Get("a1"); s.Up {
		t.Fatal("traffic success must not bring up")
	}
	e.poll("a1")
	if s, _ := e.reg.Get("a1"); !s.Up {
		t.Fatal("poll success brings up")
	}
	e.reg.ReportResult("ghost", true) // неизвестный — no-op
}

func TestPassiveSuccessUpdatesLastSeen(t *testing.T) {
	e := newEnv(t, "a1")
	e.poll("a1")
	e.clock.Advance(time.Minute)
	e.reg.ReportResult("a1", false)
	if s, _ := e.reg.Get("a1"); !s.LastSeen.Equal(e.clock.Now()) {
		t.Fatal("LastSeen")
	}
}

func TestSeedFromConfig(t *testing.T) {
	ctx := context.Background()
	repo := memtest.New().Agents()
	eps := []config.AgentEndpoint{
		{ID: "a1", URL: "https://a1:8443", Mode: config.AgentModeDial},
		{ID: "a2", URL: "https://a2:8443", Mode: config.AgentModeDial, Weight: 3},
	}
	n, err := SeedFromConfig(ctx, repo, eps)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	a, _ := repo.Get(ctx, "a1")
	if a.Weight != 1 || a.Mode != store.ModeDial {
		t.Fatalf("%+v", a)
	}
	n, err = SeedFromConfig(ctx, repo, eps)
	if err != nil || n != 0 {
		t.Fatalf("second: n=%d err=%v", n, err)
	}
	bad := memtest.New().Agents()
	if _, err := SeedFromConfig(ctx, bad, []config.AgentEndpoint{{ID: "", URL: "x"}}); err == nil {
		t.Fatal("expected invalid")
	}
}

func TestSubscribeCancelAndOverflow(t *testing.T) {
	e := newEnv(t, "a1")
	ch, cancel := e.reg.Subscribe()
	cancel()
	cancel() // идемпотентно
	if _, ok := <-ch; ok {
		t.Fatal("channel must be closed")
	}
	// переполнение не блокирует
	ch2, cancel2 := e.reg.Subscribe()
	defer cancel2()
	for range eventBuffer + 10 {
		e.reg.mu.Lock()
		e.reg.publishLocked(AgentUp, "a1", false)
		e.reg.mu.Unlock()
	}
	if len(ch2) != eventBuffer {
		t.Fatalf("len=%d", len(ch2))
	}
}

func TestJitterBounds(t *testing.T) {
	r := New(memtest.New().Agents(), nil, newSink(), WithRand(func() float64 { return 0 }))
	if d := r.jittered(); d != 4500*time.Millisecond {
		t.Fatalf("min=%v", d)
	}
	r2 := New(memtest.New().Agents(), nil, newSink(), WithRand(func() float64 { return 0.999999 }))
	if d := r2.jittered(); d < 5400*time.Millisecond || d > 5500*time.Millisecond {
		t.Fatalf("max=%v", d)
	}
}

func goroutinesSettle(t *testing.T, base int) {
	t.Helper()
	eventually(t, func() bool { return runtime.NumGoroutine() <= base+1 })
}

func TestRunPollsAndStopsOnContext(t *testing.T) {
	base := runtime.NumGoroutine()
	e := newEnv(t, "a1", "a2")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.reg.Run(ctx) }()

	eventually(t, func() bool { return e.st.count() >= 2 })
	eventually(t, func() bool { return e.sink.isHealthy("a1") && e.sink.isHealthy("a2") })
	for _, d := range e.tm.durations() {
		if d < 4500*time.Millisecond || d > 5500*time.Millisecond {
			t.Fatalf("interval %v out of ±10%%", d)
		}
	}
	before := e.st.count()
	eventually(t, func() bool { return e.tm.fireAll() >= 2 })
	eventually(t, func() bool { return e.st.count() >= before+2 })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
	goroutinesSettle(t, base)
}

func TestRunStartsAndStopsPollersOnRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := newEnv(t, "a1")
	done := make(chan struct{})
	go func() { _ = e.reg.Run(ctx); close(done) }()
	eventually(t, func() bool { return e.sink.isHealthy("a1") })

	if _, err := e.repo.Create(ctx, store.Agent{ID: "a2", Name: "a2", URL: "https://a2:8443", Mode: store.ModeDial, Weight: 1}); err != nil {
		t.Fatal(err)
	}
	if err := e.reg.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return e.sink.isHealthy("a2") })

	if err := e.repo.Delete(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := e.reg.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// после удаления a1 опросов a1 больше нет
	e.st.mu.Lock()
	e.st.seen = nil
	e.st.mu.Unlock()
	for range 3 {
		e.tm.fireAll()
		time.Sleep(5 * time.Millisecond)
	}
	e.st.mu.Lock()
	for _, ref := range e.st.seen {
		if ref.ID == "a1" {
			e.st.mu.Unlock()
			t.Fatal("removed agent still polled")
		}
	}
	e.st.mu.Unlock()
	cancel()
	<-done
}

func TestRunReloadsByVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repo := memtest.New().Agents()
	sink := newSink()
	st := &statusScript{}
	tm := &manualTimers{}
	reg := New(repo, nil, sink, WithTicker(tm.fn), WithStatusFunc(st.fn), WithReloadInterval(time.Hour))
	done := make(chan struct{})
	go func() { _ = reg.Run(ctx); close(done) }()
	eventually(t, func() bool { return tm.created.Load() >= 1 })
	if _, err := repo.Create(ctx, store.Agent{ID: "n1", Name: "n1", URL: "https://n1:8443", Mode: store.ModeDial, Weight: 1}); err != nil {
		t.Fatal(err)
	}
	// тот же Version -> ничего; после Create версия новая
	tm.fireAll()
	eventually(t, func() bool { _, ok := reg.Get("n1"); return ok })
	tm.fireAll() // версия не изменилась — Refresh не нужен
	cancel()
	<-done
}

func TestPollTimeoutIsFailure(t *testing.T) {
	e := newEnv(t, "a1")
	e.reg.pollTimeout = 10 * time.Millisecond
	e.st.mu.Lock()
	e.st.block = true
	e.st.mu.Unlock()
	e.poll("a1")
	if s, _ := e.reg.Get("a1"); s.ConsecutiveFails != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestRefreshErrors(t *testing.T) {
	e := newEnv(t, "a1")
	r := New(failRepo{e.repo}, nil, e.sink)
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	r2 := New(failListRepo{e.repo}, nil, e.sink)
	if err := r2.Refresh(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("Run must return refresh error")
	}
	if _, err := SeedFromConfig(context.Background(), failListRepo{e.repo}, nil); err == nil {
		t.Fatal("seed list error")
	}
	// без транспорта и StatusFunc опрос — неудача
	r3 := New(e.repo, nil, e.sink)
	_ = r3.Refresh(context.Background())
	r3.pollOnce(context.Background(), "a1")
	if s, _ := r3.Get("a1"); s.ConsecutiveFails != 1 {
		t.Fatal("no transport must fail")
	}
}

type failRepo struct{ store.AgentRepo }

func (failRepo) Version(context.Context) (int64, error) { return 0, errors.New("db") }

type failListRepo struct{ store.AgentRepo }

func (failListRepo) List(context.Context) ([]store.Agent, error) { return nil, errors.New("db") }

type fakeTransport struct{ st *statusScript }

func (f fakeTransport) RoundTrip(context.Context, transport.AgentRef, *httpReq) (*httpResp, error) {
	return nil, errors.New("unused")
}
func (f fakeTransport) Status(ctx context.Context, ref transport.AgentRef) (*transport.AgentStatus, error) {
	return f.st.fn(ctx, ref)
}

func TestNewWithTransport(t *testing.T) {
	st := &statusScript{}
	repo := memtest.New().Agents()
	_, _ = repo.Create(context.Background(), store.Agent{ID: "a1", Name: "a1", URL: "https://a1:1", Mode: store.ModeDial, Weight: 1})
	r := New(repo, fakeTransport{st}, newSink(), WithLogger(nil), WithPollInterval(time.Second), WithPollTimeout(time.Second), WithFailThreshold(2), WithClock(nil), WithTicker(nil), WithStatusFunc(nil), WithRand(nil))
	_ = r.Refresh(context.Background())
	r.pollOnce(context.Background(), "a1")
	if s, _ := r.Get("a1"); !s.Up || r.failThreshold != 2 {
		t.Fatal("transport status must be used")
	}
	r.pollOnce(context.Background(), "ghost") // no-op
}

func TestRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := newEnv(t, "a1", "a2")
	done := make(chan struct{})
	go func() { _ = e.reg.Run(ctx); close(done) }()
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 200 {
				e.reg.ReportResult("a1", j%3 == 0)
				_ = e.reg.List()
				_, _ = e.reg.Get("a2")
				if j%50 == 0 {
					_ = e.reg.SetWeight(ctx, "a2", 1+i)
					_ = e.reg.SetDraining(ctx, "a2", j%100 == 0)
					e.tm.fireAll()
				}
			}
		}()
	}
	ch, c := e.reg.Subscribe()
	go func() {
		for range ch {
		}
	}()
	wg.Wait()
	c()
	cancel()
	<-done
}
