package agents

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// handlerCaller — фейковый AgentTransport: запрос обслуживает http.Handler
// через httptest.
type handlerCaller struct {
	h http.Handler
	n atomic.Int32
}

func (c *handlerCaller) RoundTrip(ctx context.Context, _ transport.AgentRef, req *http.Request) (*http.Response, error) {
	c.n.Add(1)
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req.WithContext(ctx))
	return rec.Result(), nil
}

// fakeRotAgent — агентская сторона контракта ротации.
type fakeRotAgent struct {
	t        *testing.T
	id       string
	mu       sync.Mutex
	csrCalls int
	putCalls int
	csrCode  int // 0 → 200
	putCode  int // 0 → 204
	csrBody  string
	block    chan struct{}
	gotCert  string
}

func (a *fakeRotAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	block := a.block
	a.mu.Unlock()
	if block != nil {
		<-block
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == CSRPath:
		a.mu.Lock()
		a.csrCalls++
		code, body := a.csrCode, a.csrBody
		a.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		if body != "" {
			_, _ = io.WriteString(w, body)
			return
		}
		csr, _, err := pki.NewAgentCSR(a.id)
		if err != nil {
			a.t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"csr": string(csr)})
	case r.Method == http.MethodPut && r.URL.Path == CertPath:
		var b struct {
			Cert string `json:"cert"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			a.t.Error(err)
		}
		a.mu.Lock()
		a.putCalls++
		code := a.putCode
		a.gotCert = b.Cert
		a.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (a *fakeRotAgent) calls() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.csrCalls, a.putCalls
}

func (a *fakeRotAgent) set(f func(*fakeRotAgent)) {
	a.mu.Lock()
	f(a)
	a.mu.Unlock()
}

// fakeSource — управляемый AgentSource.
type fakeSource struct {
	mu     sync.Mutex
	states map[string]State
}

func (s *fakeSource) List() []State {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []State
	for _, st := range s.states {
		out = append(out, st)
	}
	return out
}
func (s *fakeSource) Get(id string) (State, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[id]
	return st, ok
}
func (s *fakeSource) Ref(id string) (transport.AgentRef, bool) {
	if _, ok := s.Get(id); !ok {
		return transport.AgentRef{}, false
	}
	return transport.AgentRef{ID: id, Mode: config.AgentMode("dial")}, true
}
func (s *fakeSource) put(id string, up bool, notAfter time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		s.states = map[string]State{}
	}
	st := State{Agent: store.Agent{ID: id}, Up: up}
	if !notAfter.IsZero() {
		st.LastStatus = &transport.AgentStatus{CertNotAfter: notAfter}
	}
	s.states[id] = st
}

type rotEnv struct {
	clock  *fakeClock
	auth   *pki.Authority
	certs  store.CertRepo
	deny   *pki.Denylist
	src    *fakeSource
	agent  *fakeRotAgent
	caller *handlerCaller
	rot    *Rotator
	oldRec store.CertRecord
	events []RotationEvent
	evMu   sync.Mutex
}

func newAuthority(t *testing.T) (*pki.Authority, store.CertRepo, *pki.Denylist) {
	t.Helper()
	repo := memtest.New().Certs()
	p := filepath.Join(t.TempDir(), "kek")
	if err := pki.GenerateKEK(p); err != nil {
		t.Fatal(err)
	}
	kek, err := pki.LoadKEK(p)
	if err != nil {
		t.Fatal(err)
	}
	a, err := pki.LoadOrInit(context.Background(), repo, kek, pki.Options{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := pki.NewDenylist(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	return a, repo, d
}

// newRotEnv: сертификат агента a1 прожил 59 суток из 90 на момент t0.
func newRotEnv(t *testing.T, mutate func(*RotatorConfig)) *rotEnv {
	t.Helper()
	return newRotEnvAge(t, 59, mutate)
}

func newRotEnvAge(t *testing.T, ageDays int, mutate func(*RotatorConfig)) *rotEnv {
	t.Helper()
	e := &rotEnv{clock: &fakeClock{t: time.Now().Truncate(time.Second)}}
	e.auth, e.certs, e.deny = newAuthority(t)
	e.oldRec = store.CertRecord{
		Serial: "aa01", AgentID: "a1", CertPEM: []byte("x"),
		NotBefore: e.clock.Now().Add(-time.Duration(ageDays) * 24 * time.Hour),
		NotAfter:  e.clock.Now().Add(time.Duration(90-ageDays) * 24 * time.Hour),
		CreatedAt: e.clock.Now().Add(-time.Duration(ageDays) * 24 * time.Hour),
	}
	if err := e.certs.Put(context.Background(), e.oldRec); err != nil {
		t.Fatal(err)
	}
	e.src = &fakeSource{}
	e.src.put("a1", true, e.oldRec.NotAfter)
	e.agent = &fakeRotAgent{t: t, id: "a1"}
	e.caller = &handlerCaller{h: e.agent}
	cfg := RotatorConfig{
		Source: e.src, Caller: e.caller, Signer: e.auth, Revoker: e.deny, Certs: e.certs,
		Now: e.clock.Now, Log: nil,
		OnEvent: func(ev RotationEvent) {
			e.evMu.Lock()
			e.events = append(e.events, ev)
			e.evMu.Unlock()
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	rot, err := NewRotator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.rot = rot
	return e
}

// reportNew: агент отчитался сертификатом, выданным в последней ротации.
func (e *rotEnv) reportNew(t *testing.T) {
	t.Helper()
	rec, err := e.certs.Get(context.Background(), e.lastEvent().NewSerial)
	if err != nil {
		t.Fatal(err)
	}
	e.src.put("a1", true, rec.NotAfter)
}

func (e *rotEnv) lastEvent() RotationEvent {
	e.evMu.Lock()
	defer e.evMu.Unlock()
	return e.events[len(e.events)-1]
}

func TestRotatorTwoThirdsOnceAndGrace(t *testing.T) {
	ctx := context.Background()
	early := newRotEnv(t, nil)
	early.rot.Tick(ctx) // 59 суток из 90 — рано
	if c, p := early.agent.calls(); c != 0 || p != 0 {
		t.Fatalf("rotated early: %d %d", c, p)
	}

	e := newRotEnvAge(t, 61, nil) // 61 сутки ≥ 2/3
	e.rot.Tick(ctx)
	if c, p := e.agent.calls(); c != 1 || p != 1 {
		t.Fatalf("calls csr=%d put=%d", c, p)
	}
	ev := e.lastEvent()
	if !ev.OK || ev.AgentID != "a1" || ev.NewSerial == "" {
		t.Fatalf("event: %+v", ev)
	}
	// агент получил валидный сертификат своего id
	blk, _ := pem.Decode([]byte(e.agent.gotCert))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := pki.AgentIDFromCert(cert); id != "a1" {
		t.Fatalf("agent id %q", id)
	}
	// грейс: старый серийник ещё не в denylist
	if e.deny.IsDenied("aa01") || e.rot.PendingRevokes() != 1 {
		t.Fatal("old serial revoked before grace")
	}

	// статус ещё старый (опрос не успел) — повторной ротации нет
	e.rot.Tick(ctx)
	e.clock.Advance(4 * time.Minute)
	e.rot.Tick(ctx)
	// агент отчитался новым сертификатом
	e.src.put("a1", true, cert.NotAfter)
	e.clock.Advance(time.Minute) // 5m после ротации; грейс 10m
	e.rot.Tick(ctx)
	if e.deny.IsDenied("aa01") {
		t.Fatal("revoked before 10m grace")
	}
	e.clock.Advance(6 * time.Minute)
	e.rot.Tick(ctx)
	if !e.deny.IsDenied("aa01") {
		t.Fatal("old serial not revoked after grace")
	}
	if e.deny.IsDenied(pki.SerialString(cert)) {
		t.Fatal("new serial revoked")
	}
	list, _ := e.certs.ListDenied(ctx)
	if len(list) != 1 || list[0].Reason != ReasonRotated || list[0].AgentID != "a1" {
		t.Fatalf("denied: %+v", list)
	}
	// после успеха ротация не повторяется
	e.clock.Advance(24 * time.Hour)
	e.rot.Tick(ctx)
	if c, p := e.agent.calls(); c != 1 || p != 1 {
		t.Fatalf("repeated: csr=%d put=%d", c, p)
	}
	if e.rot.PendingRevokes() != 0 {
		t.Fatal("pending left")
	}
}

func TestRotatorBackoffOnAgentError(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil)
	e.clock.Advance(2 * 24 * time.Hour)
	e.agent.set(func(a *fakeRotAgent) { a.csrCode = http.StatusInternalServerError })

	e.rot.Tick(ctx) // 1-я ошибка → пауза 1m
	if c, _ := e.agent.calls(); c != 1 {
		t.Fatalf("csr=%d", c)
	}
	if ev := e.lastEvent(); ev.OK || ev.Err == nil {
		t.Fatalf("event: %+v", ev)
	}
	e.rot.Tick(ctx)
	if c, _ := e.agent.calls(); c != 1 {
		t.Fatalf("retried without backoff: %d", c)
	}
	e.clock.Advance(time.Minute)
	e.rot.Tick(ctx) // 2-я ошибка → пауза 2m
	if c, _ := e.agent.calls(); c != 2 {
		t.Fatalf("csr=%d", c)
	}
	e.clock.Advance(time.Minute)
	e.rot.Tick(ctx)
	if c, _ := e.agent.calls(); c != 2 {
		t.Fatalf("backoff not doubled: %d", c)
	}
	e.agent.set(func(a *fakeRotAgent) { a.csrCode = 0 })
	e.clock.Advance(time.Minute)
	e.rot.Tick(ctx)
	if c, p := e.agent.calls(); c != 3 || p != 1 {
		t.Fatalf("csr=%d put=%d", c, p)
	}
	if !e.lastEvent().OK {
		t.Fatal("not recovered")
	}
}

func TestRotatorBackoffCap(t *testing.T) {
	e := newRotEnv(t, func(c *RotatorConfig) { c.BackoffBase, c.BackoffMax = time.Minute, 5*time.Minute })
	for fails, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 4: 5 * time.Minute, 9: 5 * time.Minute} {
		if got := e.rot.backoff(fails); got != want {
			t.Errorf("backoff(%d)=%s want %s", fails, got, want)
		}
	}
}

func TestRotatorPutFailureRevokesNewCert(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil)
	e.agent.set(func(a *fakeRotAgent) { a.putCode = http.StatusBadRequest })
	err := e.rot.RotateNow(ctx, "a1")
	if err == nil {
		t.Fatal("want error")
	}
	if e.rot.PendingRevokes() != 0 || e.deny.IsDenied("aa01") {
		t.Fatal("old cert must stay valid")
	}
	denied, _ := e.certs.ListDenied(ctx)
	if len(denied) != 1 || denied[0].Reason != reasonRotationFailed {
		t.Fatalf("denied: %+v", denied)
	}
}

func TestRotateNowIgnoresSchedule(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil) // 59 суток — не пора, но кнопка работает
	if err := e.rot.RotateNow(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if c, p := e.agent.calls(); c != 1 || p != 1 {
		t.Fatalf("csr=%d put=%d", c, p)
	}
	// ручной запуск не зависит от cooldown/backoff
	e.agent.set(func(a *fakeRotAgent) { a.csrCode = 500 })
	if err := e.rot.RotateNow(ctx, "a1"); err == nil {
		t.Fatal("want error")
	}
	e.agent.set(func(a *fakeRotAgent) { a.csrCode = 0 })
	if err := e.rot.RotateNow(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := e.rot.RotateNow(ctx, "nope"); !errors.Is(err, ErrAgentUnknown) {
		t.Fatalf("got %v", err)
	}
}

func TestRotatorOneAtATimePerAgent(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil)
	block := make(chan struct{})
	e.agent.set(func(a *fakeRotAgent) { a.block = block })
	done := make(chan error, 1)
	go func() { done <- e.rot.RotateNow(ctx, "a1") }()
	eventually(t, func() bool { return e.caller.n.Load() == 1 })
	if err := e.rot.RotateNow(ctx, "a1"); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("got %v", err)
	}
	e.clock.Advance(2 * 24 * time.Hour)
	e.rot.Tick(ctx) // занятый агент пропускается
	if e.caller.n.Load() != 1 {
		t.Fatal("tick rotated busy agent")
	}
	e.agent.set(func(a *fakeRotAgent) { a.block = nil })
	close(block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRotatorSkipsDownAndNoStatus(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil)
	e.clock.Advance(2 * 24 * time.Hour)
	e.src.put("a1", false, e.oldRec.NotAfter)
	e.src.put("a2", true, time.Time{})
	e.rot.Tick(ctx)
	if e.caller.n.Load() != 0 {
		t.Fatal("rotated unavailable agents")
	}
}

func TestRotatorDueFallbackWithoutRecord(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil)
	// серта нет в CertRepo: NotBefore = NotAfter-90d
	e.src.put("a1", true, e.clock.Now().Add(29*24*time.Hour)) // прожито 61 из 90
	e.rot.Tick(ctx)
	if c, _ := e.agent.calls(); c != 1 {
		t.Fatalf("csr=%d", c)
	}
}

func TestRotatorBadAgentResponses(t *testing.T) {
	for name, f := range map[string]func(*fakeRotAgent){
		"garbage csr json": func(a *fakeRotAgent) { a.csrBody = "{" },
		"empty csr":        func(a *fakeRotAgent) { a.csrBody = `{"csr":""}` },
		"bad csr pem":      func(a *fakeRotAgent) { a.csrBody = `{"csr":"nope"}` },
		"put 200":          func(a *fakeRotAgent) { a.putCode = http.StatusOK },
	} {
		t.Run(name, func(t *testing.T) {
			e := newRotEnv(t, nil)
			e.agent.set(f)
			if err := e.rot.RotateNow(context.Background(), "a1"); err == nil {
				t.Fatal("want error")
			}
			if e.deny.IsDenied("aa01") {
				t.Fatal("old revoked")
			}
		})
	}
}

type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(context.Context, transport.AgentRef, *http.Request) (*http.Response, error) {
	return nil, &transport.PhaseError{Phase: "dial", Err: errors.New("down")}
}

func TestRotatorTransportError(t *testing.T) {
	e := newRotEnv(t, func(c *RotatorConfig) { c.Caller = errRoundTripper{} })
	if err := e.rot.RotateNow(context.Background(), "a1"); err == nil {
		t.Fatal("want error")
	}
}

type flakyRevoker struct {
	mu    sync.Mutex
	fail  bool
	calls []string
}

func (f *flakyRevoker) Revoke(_ context.Context, serial, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("db down")
	}
	f.calls = append(f.calls, serial)
	return nil
}

func TestRotatorRevokeRetriedAfterFailure(t *testing.T) {
	ctx := context.Background()
	fr := &flakyRevoker{}
	e := newRotEnv(t, func(c *RotatorConfig) { c.Revoker = fr; c.Grace = time.Minute })
	if err := e.rot.RotateNow(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	e.reportNew(t)
	fr.fail = true
	e.clock.Advance(2 * time.Minute)
	e.rot.Tick(ctx)
	if e.rot.PendingRevokes() != 1 || len(fr.calls) != 0 {
		t.Fatal("failed revoke must stay pending")
	}
	fr.fail = false
	e.rot.Tick(ctx)
	if len(fr.calls) == 0 || fr.calls[0] != "aa01" {
		t.Fatalf("calls %v", fr.calls)
	}
}

func TestRotatorZeroGraceDefaultsAndNegativeImmediate(t *testing.T) {
	e := newRotEnv(t, nil)
	if e.rot.cfg.Grace != DefaultRotateGrace {
		t.Fatalf("grace %s", e.rot.cfg.Grace)
	}
	e2 := newRotEnv(t, func(c *RotatorConfig) { c.Grace = -1 })
	if err := e2.rot.RotateNow(context.Background(), "a1"); err != nil {
		t.Fatal(err)
	}
	e2.reportNew(t)
	e2.clock.Advance(time.Second)
	e2.rot.Tick(context.Background())
	if !e2.deny.IsDenied("aa01") {
		t.Fatal("negative grace must revoke immediately")
	}
}

func TestNewRotatorValidation(t *testing.T) {
	if _, err := NewRotator(RotatorConfig{}); err == nil {
		t.Fatal("want error")
	}
}

func TestRotatorRunTicksAndStops(t *testing.T) {
	e := newRotEnv(t, nil)
	e.clock.Advance(2 * 24 * time.Hour)
	mt := &manualTimers{}
	e.rot.cfg.NewTimer = mt.fn
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.rot.Run(ctx); close(done) }()
	eventually(t, func() bool { c, _ := e.agent.calls(); return c == 1 })
	eventually(t, func() bool { return mt.created.Load() >= 1 })
	if d := mt.durations(); len(d) != 1 || d[0] != DefaultRotateInterval {
		t.Fatalf("timers %v", d)
	}
	mt.fireAll() // следующий Tick: cooldown — повтора нет
	eventually(t, func() bool { return mt.created.Load() >= 2 })
	if c, _ := e.agent.calls(); c != 1 {
		t.Fatalf("csr=%d", c)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRotatorRestartInGraceRevokesAfterGrace(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil)
	if err := e.rot.RotateNow(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	e.reportNew(t)
	// рестарт: новый Rotator на тех же CertRepo/Denylist
	cfg := e.rot.cfg
	rot2, err := NewRotator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rot2.PendingRevokes() != 1 {
		t.Fatalf("pending %d", rot2.PendingRevokes())
	}
	e.clock.Advance(5 * time.Minute)
	rot2.Tick(ctx)
	if e.deny.IsDenied("aa01") {
		t.Fatal("revoked before grace")
	}
	e.clock.Advance(6 * time.Minute)
	rot2.Tick(ctx)
	if !e.deny.IsDenied("aa01") || rot2.PendingRevokes() != 0 {
		t.Fatal("not revoked after grace")
	}
}

func TestRotatorFailedRotationDoesNotBecomeNewest(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil)
	e.agent.set(func(a *fakeRotAgent) { a.putCode = http.StatusBadRequest })
	if err := e.rot.RotateNow(ctx, "a1"); err == nil {
		t.Fatal("want error")
	}
	e.clock.Advance(time.Hour)
	e.rot.Tick(ctx)
	if e.deny.IsDenied("aa01") {
		t.Fatal("live cert revoked because of failed rotation")
	}
	if e.rot.PendingRevokes() != 0 {
		t.Fatal("pending after failed rotation")
	}
}

func TestRotatorKeepsOldWhileAgentNotOnNewCert(t *testing.T) {
	ctx := context.Background()
	e := newRotEnv(t, nil)
	if err := e.rot.RotateNow(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Hour) // статус всё ещё со старым сроком
	e.rot.Tick(ctx)
	if e.deny.IsDenied("aa01") {
		t.Fatal("old revoked while agent reports old cert")
	}
}
