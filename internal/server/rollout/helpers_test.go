package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Сценарии поведения фейкового агента на POST /_agent/update.
const (
	modeOK       = ""         // принял и «перезапустился» на новой версии
	modeReject   = "reject"   // 422 (агент отверг релиз)
	modeRollback = "rollback" // принял, но apply откатил: версия прежняя, state=failed
	modeHang     = "hang"     // принял, но не вернулся на версию
)

type fakeAgent struct {
	mu       sync.Mutex
	version  string
	inflight int
	down     bool
	mode     string
	gate     chan struct{} // не nil: «перезапуск» ждёт закрытия канала
	started  chan struct{} // закрывается при получении POST (если не nil)
	posts    int
	failedV  string
	gwURL    string
	statusN  int
	reverse  bool
	target   string // версия из последней принятой команды
	sentGW   bool   // команда содержала gateway_url
}

type fakes struct {
	t      *testing.T
	mu     sync.Mutex
	agents map[string]*fakeAgent
	drain  map[string]bool
	up     map[string]bool
	drains []string // порядок SetDraining(id,true)
}

func newFakes(t *testing.T, version string, ids ...string) *fakes {
	f := &fakes{t: t, agents: map[string]*fakeAgent{}, drain: map[string]bool{}, up: map[string]bool{}}
	for _, id := range ids {
		f.agents[id] = &fakeAgent{version: version}
		f.up[id] = true
	}
	return f
}

func (f *fakes) agent(id string) *fakeAgent { return f.agents[id] }

// ---- Registry ----

func (f *fakes) List() []agents.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []agents.State
	for id, a := range f.agents {
		a.mu.Lock()
		st := agents.State{Agent: store.Agent{ID: id, Name: id}, Up: f.up[id], Draining: f.drain[id],
			LastStatus: &transport.AgentStatus{Version: a.version}}
		a.mu.Unlock()
		out = append(out, st)
	}
	slices.SortFunc(out, func(a, b agents.State) int {
		if a.Agent.ID < b.Agent.ID {
			return -1
		}
		return 1
	})
	return out
}

func (f *fakes) Get(id string) (agents.State, bool) {
	for _, s := range f.List() {
		if s.Agent.ID == id {
			return s, true
		}
	}
	return agents.State{}, false
}

func (f *fakes) Ref(id string) (transport.AgentRef, bool) {
	a, ok := f.agents[id]
	if !ok {
		return transport.AgentRef{}, false
	}
	mode := config.AgentModeDial
	if a.reverse {
		mode = config.AgentModeReverse
	}
	return transport.AgentRef{ID: id, Mode: mode}, true
}

func (f *fakes) SetDraining(_ context.Context, id string, v bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drain[id] = v
	if v {
		f.drains = append(f.drains, id)
	}
	return nil
}

func (f *fakes) isDraining(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.drain[id]
}

// ---- AgentTransport ----

func (f *fakes) Status(_ context.Context, ref transport.AgentRef) (*transport.AgentStatus, error) {
	a := f.agents[ref.ID]
	a.mu.Lock()
	defer a.mu.Unlock()
	a.statusN++
	if a.down {
		return nil, errors.New("dial: connection refused")
	}
	return &transport.AgentStatus{Version: a.version, Inflight: a.inflight}, nil
}

func (f *fakes) RoundTrip(_ context.Context, ref transport.AgentRef, req *http.Request) (*http.Response, error) {
	a := f.agents[ref.ID]
	a.mu.Lock()
	defer a.mu.Unlock()
	reply := func(code int, v any) (*http.Response, error) {
		b, _ := json.Marshal(v)
		return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}}, nil
	}
	if a.down {
		return nil, errors.New("dial: connection refused")
	}
	if req.URL.Path != "/_agent/update" {
		return reply(404, nil)
	}
	if req.Method == http.MethodGet {
		if a.failedV != "" {
			return reply(200, map[string]string{"state": "failed", "version": a.failedV, "error": "health check failed, rolled back"})
		}
		if a.target != "" && a.version == a.target {
			return reply(200, map[string]string{"state": "applied", "version": a.target})
		}
		return reply(200, map[string]string{"state": "idle"})
	}
	var body struct{ Version, GatewayURL string }
	var raw map[string]string
	b, _ := io.ReadAll(req.Body)
	_ = json.Unmarshal(b, &raw)
	body.Version, body.GatewayURL = raw["version"], raw["gateway_url"]
	_, a.sentGW = raw["gateway_url"]
	a.posts++
	a.target = body.Version
	a.gwURL = body.GatewayURL
	if a.started != nil {
		select {
		case <-a.started:
		default:
			close(a.started)
		}
	}
	switch a.mode {
	case modeReject:
		return reply(422, map[string]string{"state": "failed", "error": "verify: bad signature"})
	case modeRollback:
		a.failedV = body.Version
		return reply(202, map[string]string{"state": "staged"})
	case modeHang:
		return reply(202, map[string]string{"state": "staged"})
	}
	gate := a.gate
	go func() {
		if gate != nil {
			<-gate
		}
		time.Sleep(5 * time.Millisecond)
		a.mu.Lock()
		a.version = body.Version
		a.mu.Unlock()
	}()
	return reply(202, map[string]string{"state": "staged", "version": body.Version})
}

// ---- прочее ----

type pkgs map[string]bool

func (p pkgs) Has(v string) bool { return p[v] }

type alerts struct {
	mu   sync.Mutex
	list []string
}

func (a *alerts) RolloutFailed(_ context.Context, agentID, version, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.list = append(a.list, agentID+"|"+version+"|"+reason)
}

func (a *alerts) all() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.list)
}

func newManager(t *testing.T, f *fakes, st store.Store, al Alerter) *Manager {
	t.Helper()
	if st == nil {
		st = memtest.New()
	}
	m, err := New(Config{
		Store: st, Registry: f, Transport: f, Packages: pkgs{"1.2.0": true}, Alerter: al,
		GatewayURL:    "https://gw.example:8444",
		DrainTimeout:  200 * time.Millisecond,
		DrainInterval: 5 * time.Millisecond,
		PollInterval:  5 * time.Millisecond,
		WaitTimeout:   400 * time.Millisecond,
		UpdateTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func waitDone(t *testing.T, m *Manager, id string) Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Wait(ctx, id); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	st, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func stepStates(st Status) map[string]string {
	out := map[string]string{}
	for _, s := range st.Steps {
		out[s.AgentID] = s.State
	}
	return out
}

func (a *fakeAgent) postCount() int   { a.mu.Lock(); defer a.mu.Unlock(); return a.posts }
func (a *fakeAgent) statusCount() int { a.mu.Lock(); defer a.mu.Unlock(); return a.statusN }
func (a *fakeAgent) ver() string      { a.mu.Lock(); defer a.mu.Unlock(); return a.version }
func (a *fakeAgent) gateway() string  { a.mu.Lock(); defer a.mu.Unlock(); return a.gwURL }

func (f *fakes) drainCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.drains) }
func (f *fakes) drainOrder() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.drains)
}
