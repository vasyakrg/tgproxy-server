package agents

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

type removeEnv struct {
	repo   store.AgentRepo
	reg    *Registry
	auth   *pki.Authority
	deny   *pki.Denylist
	certs  store.CertRepo
	certA  []byte
	inflgt atomic.Int32
	stErr  atomic.Bool
	rm     *Remover
}

func newRemoveEnv(t *testing.T, mutate func(*RemoverConfig)) *removeEnv {
	t.Helper()
	ctx := context.Background()
	e := &removeEnv{}
	e.auth, e.certs, e.deny = newAuthority(t)
	e.repo = memtest.New().Agents()
	if _, err := e.repo.Create(ctx, store.Agent{ID: "a1", Name: "a1", URL: "https://a1:8443", Mode: store.ModeDial, Weight: 1}); err != nil {
		t.Fatal(err)
	}
	status := func(context.Context, transport.AgentRef) (*transport.AgentStatus, error) {
		if e.stErr.Load() {
			return nil, errors.New("unreachable")
		}
		return &transport.AgentStatus{Inflight: int(e.inflgt.Load())}, nil
	}
	e.reg = New(e.repo, nil, newSink(), WithStatusFunc(status))
	if err := e.reg.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 { // два выпущенных сертификата
		csr, _, _ := pki.NewAgentCSR("a1")
		pemb, _, err := e.auth.SignAgentCSR(ctx, csr, "a1", 0)
		if err != nil {
			t.Fatal(err)
		}
		e.certA = pemb
	}
	cfg := RemoverConfig{
		Registry: e.reg, Repo: e.repo, Revoker: e.deny, Status: status,
		DrainTimeout: 200 * time.Millisecond, DrainInterval: 5 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	rm, err := NewRemover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.rm = rm
	return e
}

func TestRemoveRevokesDeletesAndRejectsCert(t *testing.T) {
	ctx := context.Background()
	e := newRemoveEnv(t, nil)
	events, cancel := e.reg.Subscribe()
	defer cancel()
	e.inflgt.Store(2)
	go func() { // inflight завершается позже
		time.Sleep(30 * time.Millisecond)
		e.inflgt.Store(0)
	}()

	res, err := e.rm.Remove(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Revoked != 2 || res.DrainTimedOut {
		t.Fatalf("res: %+v", res)
	}
	if _, err := e.repo.Get(ctx, "a1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("agent still in repo: %v", err)
	}
	if _, ok := e.reg.Get("a1"); ok {
		t.Fatal("agent still in registry")
	}
	var removed, draining bool
	for len(events) > 0 {
		switch ev := <-events; ev.Type {
		case AgentRemoved:
			removed = ev.AgentID == "a1"
		case AgentDraining:
			draining = ev.Draining
		}
	}
	if !removed || !draining {
		t.Fatalf("events removed=%v draining=%v", removed, draining)
	}
	// транспорт/gateway: сертификат из denylist отклоняется
	cs := stateOf(t, e.certA)
	verify := pki.VerifyAgentPeer(e.auth.Pool(), "a1", e.deny.Check)
	if err := verify(cs); !errors.Is(err, pki.ErrRevoked) {
		t.Fatalf("revoked agent accepted: %v", err)
	}
	denied, _ := e.certs.ListDenied(ctx)
	if len(denied) != 2 || denied[0].Reason != ReasonRemoved {
		t.Fatalf("denied: %+v", denied)
	}
}

func TestRemoveDrainTimeoutStillRemoves(t *testing.T) {
	e := newRemoveEnv(t, func(c *RemoverConfig) { c.DrainTimeout = 30 * time.Millisecond })
	e.inflgt.Store(5)
	res, err := e.rm.Remove(context.Background(), "a1")
	if err != nil || !res.DrainTimedOut || res.Revoked != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRemoveUnreachableAgent(t *testing.T) {
	e := newRemoveEnv(t, nil)
	e.stErr.Store(true)
	res, err := e.rm.Remove(context.Background(), "a1")
	if err != nil || !res.DrainUnchecked || res.Revoked != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRemoveUnknownAgent(t *testing.T) {
	e := newRemoveEnv(t, nil)
	if _, err := e.rm.Remove(context.Background(), "zzz"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

type failAgentRevoker struct{}

func (failAgentRevoker) RevokeAgent(context.Context, string, string) (int, error) {
	return 0, errors.New("db down")
}

func TestRemoveRevokeFailureKeepsAgent(t *testing.T) {
	ctx := context.Background()
	e := newRemoveEnv(t, func(c *RemoverConfig) { c.Revoker = failAgentRevoker{} })
	if _, err := e.rm.Remove(ctx, "a1"); err == nil {
		t.Fatal("want error")
	}
	if _, err := e.repo.Get(ctx, "a1"); err != nil {
		t.Fatalf("agent deleted despite revoke failure: %v", err)
	}
}

func TestRemoveCanceledContext(t *testing.T) {
	e := newRemoveEnv(t, func(c *RemoverConfig) { c.DrainTimeout = time.Hour })
	e.inflgt.Store(1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := e.rm.Remove(ctx, "a1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.repo.Get(context.Background(), "a1"); err != nil {
		t.Fatal("agent must remain after cancel")
	}
}

func TestRemoveAgentMissingFromRegistry(t *testing.T) {
	ctx := context.Background()
	e := newRemoveEnv(t, nil)
	// агент в БД, но реестр о нём ещё не знает
	if _, err := e.repo.Create(ctx, store.Agent{ID: "a2", Name: "a2", URL: "https://a2:8443", Mode: store.ModeDial, Weight: 1}); err != nil {
		t.Fatal(err)
	}
	e.rm.cfg.Registry = refless{e.reg}
	res, err := e.rm.Remove(ctx, "a2")
	if err != nil || !res.DrainUnchecked {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// refless не знает ни одного агента в Ref.
type refless struct{ *Registry }

func (refless) Ref(string) (transport.AgentRef, bool) { return transport.AgentRef{}, false }

func TestNewRemoverValidation(t *testing.T) {
	if _, err := NewRemover(RemoverConfig{}); err == nil {
		t.Fatal("want error")
	}
}

func stateOf(t *testing.T, certPEM []byte) tls.ConnectionState {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
}
