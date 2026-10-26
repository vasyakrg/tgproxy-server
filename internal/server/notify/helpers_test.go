package notify

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

const testToken = "123456789:AAEhBOweik6ad9r_QXMENQjcrwNTYoOaVTQ"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeMetrics struct {
	mu sync.Mutex
	n  int
}

func (m *fakeMetrics) AlertUndeliverable() { m.mu.Lock(); m.n++; m.mu.Unlock() }
func (m *fakeMetrics) count() int          { m.mu.Lock(); defer m.mu.Unlock(); return m.n }

type call struct {
	ctx   context.Context
	body  string
	route tgapi.Route
}

type fakeSender struct {
	mu     sync.Mutex
	calls  []call
	status int    // 0 → 200
	body   string // "" → {"ok":true}
	err    error
	perID  map[string]int // chat_id substring → status
}

func (f *fakeSender) Do(ctx context.Context, req *http.Request, route tgapi.Route) (*http.Response, error) {
	b, _ := io.ReadAll(req.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{ctx: ctx, body: string(b), route: route})
	if f.err != nil {
		return nil, f.err
	}
	st := f.status
	for sub, s := range f.perID {
		if strings.Contains(string(b), sub) {
			st = s
		}
	}
	if st == 0 {
		st = 200
	}
	body := f.body
	if body == "" {
		body = `{"ok":true,"result":{}}`
		if st != 200 {
			body = `{"ok":false,"error_code":1,"description":"boom"}`
		}
	}
	return &http.Response{StatusCode: st, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func (f *fakeSender) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

func pending(t *testing.T, s *memtest.Store) []store.OutboxItem {
	t.Helper()
	items, err := s.Outbox().Pending(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func all(t *testing.T, s *memtest.Store, key string) store.OutboxItem {
	t.Helper()
	it, err := s.Outbox().LastByKey(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

// fakeAlerter записывает вызовы Evaluator-а.
type fakeAlerter struct {
	mu       sync.Mutex
	fired    []Alert
	resolved []string
	flushes  int
}

func (f *fakeAlerter) Fire(_ context.Context, a Alert) error {
	f.mu.Lock()
	f.fired = append(f.fired, a)
	f.mu.Unlock()
	return nil
}
func (f *fakeAlerter) Resolve(_ context.Context, k string) error {
	f.mu.Lock()
	f.resolved = append(f.resolved, k)
	f.mu.Unlock()
	return nil
}
func (f *fakeAlerter) Flush(context.Context) error {
	f.mu.Lock()
	f.flushes++
	f.mu.Unlock()
	return nil
}
func (f *fakeAlerter) firedTypes() []AlertType {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []AlertType
	for _, a := range f.fired {
		out = append(out, a.Type)
	}
	return out
}
func (f *fakeAlerter) reset() { f.mu.Lock(); f.fired, f.resolved = nil, nil; f.mu.Unlock() }

type fakeRegistry struct {
	mu     sync.Mutex
	states []agents.State
	ch     chan agents.Event
}

func newFakeRegistry(s ...agents.State) *fakeRegistry {
	return &fakeRegistry{states: s, ch: make(chan agents.Event, 8)}
}
func (r *fakeRegistry) List() []agents.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]agents.State(nil), r.states...)
}
func (r *fakeRegistry) Subscribe() (<-chan agents.Event, func()) { return r.ch, func() {} }
func (r *fakeRegistry) set(s ...agents.State)                    { r.mu.Lock(); r.states = s; r.mu.Unlock() }

type fakeErrRates struct {
	rate float64
	n    int64
}

func (f fakeErrRates) AgentErrorRate(string, time.Duration) (float64, int64) { return f.rate, f.n }
