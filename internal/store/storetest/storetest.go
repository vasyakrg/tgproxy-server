// Package storetest — общий contract-набор для реализаций store.Store
// (sqlite, memtest, sqlite+redis).
package storetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Factory создаёт чистое хранилище; закрытие регистрируется через t.Cleanup.
type Factory func(t *testing.T) store.Store

// Run прогоняет весь набор против хранилища из factory.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	groups := []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"Agents", testAgents},
		{"AccessRules", testAccessRules},
		{"Sessions", testSessions},
		{"RateState", testRateState},
		{"Outbox", testOutbox},
		{"History", testHistory},
		{"Audit", testAudit},
		{"HostKeys", testHostKeys},
		{"Certs", testCerts},
		{"Enrollments", testEnrollments},
		{"ErrorEvents", testErrorEvents},
		{"InstallJobs", testInstallJobs},
		{"Settings", testSettings},
		{"Rollouts", testRollouts},
		{"Bans", testBans},
		{"DeniedSamples", testDeniedSamples},
		{"AccessDenials", testAccessDenials},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			g.fn(t, factory(t))
		})
	}
}

func hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func is(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func sameTime(t *testing.T, got, want time.Time) {
	t.Helper()
	if got.UnixMilli() != want.UnixMilli() {
		t.Fatalf("time = %v, want %v", got, want)
	}
}

func testAgents(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Agents()
	v0, err := r.Version(ctx)
	ok(t, err)

	a, err := r.Create(ctx, store.Agent{ID: "a1", Name: "msk-1", URL: "https://10.0.0.1:8443", Mode: store.ModeDial, Weight: 100})
	ok(t, err)
	if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
		t.Fatal("timestamps not set")
	}
	_, err = r.Create(ctx, store.Agent{ID: "a1", Name: "other", URL: "https://x", Mode: store.ModeDial})
	is(t, err, store.ErrConflict)
	_, err = r.Create(ctx, store.Agent{ID: "a2", Name: "msk-1", URL: "https://x", Mode: store.ModeDial})
	is(t, err, store.ErrConflict)
	_, err = r.Create(ctx, store.Agent{ID: "a3", Name: "bad", Mode: "weird"})
	is(t, err, store.ErrInvalid)
	_, err = r.Create(ctx, store.Agent{ID: "a3", Name: "nourl", Mode: store.ModeDial})
	is(t, err, store.ErrInvalid)
	_, err = r.Create(ctx, store.Agent{ID: "n1", Name: "nat-1", Mode: store.ModeReverse, Weight: 50})
	ok(t, err)
	_, err = r.Create(ctx, store.Agent{ID: "b0", Name: "both-nourl", Mode: store.ModeBoth})
	is(t, err, store.ErrInvalid)
	_, err = r.Create(ctx, store.Agent{ID: "b1", Name: "both-1", URL: "https://10.0.0.2:8443", Mode: store.ModeBoth, Weight: 10})
	ok(t, err)
	gotB, err := r.Get(ctx, "b1")
	ok(t, err)
	if gotB.Mode != store.ModeBoth || gotB.URL != "https://10.0.0.2:8443" {
		t.Fatalf("both agent roundtrip: %+v", gotB)
	}
	ok(t, r.Delete(ctx, "b1"))

	v1, err := r.Version(ctx)
	ok(t, err)
	if v1 <= v0 {
		t.Fatalf("version did not grow: %d -> %d", v0, v1)
	}

	got, err := r.Get(ctx, "a1")
	ok(t, err)
	if got.Name != "msk-1" || got.Mode != store.ModeDial || got.Weight != 100 || got.Draining {
		t.Fatalf("got %+v", got)
	}
	sameTime(t, got.CreatedAt, a.CreatedAt)
	_, err = r.Get(ctx, "nope")
	is(t, err, store.ErrNotFound)

	list, err := r.List(ctx)
	ok(t, err)
	if len(list) != 2 {
		t.Fatalf("list len %d", len(list))
	}

	ok(t, r.SetWeight(ctx, "a1", 0))
	ok(t, r.SetDraining(ctx, "a1", true))
	is(t, r.SetWeight(ctx, "a1", -1), store.ErrInvalid)
	is(t, r.SetWeight(ctx, "nope", 1), store.ErrNotFound)
	is(t, r.SetDraining(ctx, "nope", true), store.ErrNotFound)
	got, _ = r.Get(ctx, "a1")
	if got.Weight != 0 || !got.Draining {
		t.Fatalf("got %+v", got)
	}

	got.Name = "msk-renamed"
	got.URL = "https://10.0.0.9:8443"
	up, err := r.Update(ctx, got)
	ok(t, err)
	if up.Name != "msk-renamed" || up.URL != "https://10.0.0.9:8443" {
		t.Fatalf("update %+v", up)
	}
	sameTime(t, up.CreatedAt, a.CreatedAt)
	_, err = r.Update(ctx, store.Agent{ID: "ghost", Name: "g", URL: "https://x", Mode: store.ModeDial})
	is(t, err, store.ErrNotFound)
	up.Name = "nat-1"
	_, err = r.Update(ctx, up)
	is(t, err, store.ErrConflict)

	testAgentSSHTarget(ctx, t, r)

	v2, _ := r.Version(ctx)
	ok(t, r.Delete(ctx, "a1"))
	is(t, r.Delete(ctx, "a1"), store.ErrNotFound)
	if v3, _ := r.Version(ctx); v3 <= v2 {
		t.Fatal("version did not grow on delete")
	}
	list, _ = r.List(ctx)
	if len(list) != 1 || list[0].ID != "n1" {
		t.Fatalf("list %+v", list)
	}
}

// testAgentSSHTarget: SSH-цель сохраняется при Create, не затирается Update, меняется SetSSHTarget.
func testAgentSSHTarget(ctx context.Context, t *testing.T, r store.AgentRepo) {
	t.Helper()
	got, err := r.Get(ctx, "a1")
	ok(t, err)
	if got.SSHHost != "" || got.SSHPort != 0 {
		t.Fatalf("ssh target must be empty by default: %+v", got)
	}
	_, err = r.Create(ctx, store.Agent{ID: "s1", Name: "ssh-1", URL: "https://10.0.0.3:8443", Mode: store.ModeDial, Weight: 1, SSHHost: "10.0.0.3", SSHPort: 2222})
	ok(t, err)
	got, err = r.Get(ctx, "s1")
	ok(t, err)
	if got.SSHHost != "10.0.0.3" || got.SSHPort != 2222 {
		t.Fatalf("ssh target roundtrip: %+v", got)
	}
	got.Weight = 5
	up, err := r.Update(ctx, got)
	ok(t, err)
	if up.SSHHost != "10.0.0.3" || up.SSHPort != 2222 {
		t.Fatalf("update dropped ssh target: %+v", up)
	}
	noSSH := up
	noSSH.SSHHost, noSSH.SSHPort = "", 0
	up, err = r.Update(ctx, noSSH)
	ok(t, err)
	if up.SSHHost != "10.0.0.3" || up.SSHPort != 2222 {
		t.Fatalf("update must not change ssh target: %+v", up)
	}
	v0, _ := r.Version(ctx)
	ok(t, r.SetSSHTarget(ctx, "s1", "agent.example", 22))
	got, _ = r.Get(ctx, "s1")
	if got.SSHHost != "agent.example" || got.SSHPort != 22 {
		t.Fatalf("SetSSHTarget: %+v", got)
	}
	if v1, _ := r.Version(ctx); v1 <= v0 {
		t.Fatal("version did not grow on SetSSHTarget")
	}
	ok(t, r.SetSSHTarget(ctx, "s1", "", 0))
	got, _ = r.Get(ctx, "s1")
	if got.SSHHost != "" || got.SSHPort != 0 {
		t.Fatalf("SetSSHTarget clear: %+v", got)
	}
	is(t, r.SetSSHTarget(ctx, "nope", "h", 22), store.ErrNotFound)
	is(t, r.SetSSHTarget(ctx, "s1", "h", 0), store.ErrInvalid)
	is(t, r.SetSSHTarget(ctx, "s1", "h", 70000), store.ErrInvalid)
	is(t, r.SetSSHTarget(ctx, "s1", "", 22), store.ErrInvalid)
	is(t, r.SetSSHTarget(ctx, "s1", "bad host", 22), store.ErrInvalid)
	_, err = r.Create(ctx, store.Agent{ID: "s2", Name: "ssh-2", URL: "https://x", Mode: store.ModeDial, SSHHost: "h"})
	is(t, err, store.ErrInvalid)
	ok(t, r.Delete(ctx, "s1"))
}

func testAccessRules(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.AccessRules()
	v0, err := r.Version(ctx)
	ok(t, err)

	nets := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")}
	net, err := r.Create(ctx, store.AccessRule{Name: "office", CIDRs: nets, RPS: 30, Enabled: true})
	ok(t, err)
	if net.ID == 0 || net.CreatedAt.IsZero() {
		t.Fatalf("created %+v", net)
	}
	key, err := r.Create(ctx, store.AccessRule{Name: "ci", KeyHash: hash("k1"), KeyPrefix: "tgp_ab", Enabled: true})
	ok(t, err)
	both, err := r.Create(ctx, store.AccessRule{Name: "both", CIDRs: nets[:1], KeyHash: hash("k2"), Enabled: true})
	ok(t, err)

	// правило без сети и без ключа запрещено
	_, err = r.Create(ctx, store.AccessRule{Name: "open-relay", Enabled: true})
	is(t, err, store.ErrInvalid)
	_, err = r.Create(ctx, store.AccessRule{Name: "", CIDRs: nets})
	is(t, err, store.ErrInvalid)
	_, err = r.Create(ctx, store.AccessRule{Name: "badhash", KeyHash: []byte{1, 2, 3}})
	is(t, err, store.ErrInvalid)
	_, err = r.Create(ctx, store.AccessRule{Name: "neg", CIDRs: nets, RPS: -1})
	is(t, err, store.ErrInvalid)
	// уникальность имени и хеша ключа
	_, err = r.Create(ctx, store.AccessRule{Name: "office", CIDRs: nets})
	is(t, err, store.ErrConflict)
	_, err = r.Create(ctx, store.AccessRule{Name: "dup-key", KeyHash: hash("k1")})
	is(t, err, store.ErrConflict)

	v1, _ := r.Version(ctx)
	if v1 <= v0 {
		t.Fatalf("version did not grow: %d -> %d", v0, v1)
	}

	got, err := r.Get(ctx, net.ID)
	ok(t, err)
	if len(got.CIDRs) != 2 || got.CIDRs[0] != nets[0] || got.CIDRs[1] != nets[1] || got.KeyHash != nil || got.RPS != 30 || !got.Enabled {
		t.Fatalf("got %+v", got)
	}
	got, err = r.Get(ctx, key.ID)
	ok(t, err)
	if len(got.CIDRs) != 0 || !bytes.Equal(got.KeyHash, hash("k1")) || got.KeyPrefix != "tgp_ab" {
		t.Fatalf("got %+v", got)
	}
	byName, err := r.GetByName(ctx, "both")
	ok(t, err)
	if byName.ID != both.ID {
		t.Fatalf("by name %+v", byName)
	}
	_, err = r.Get(ctx, 9999)
	is(t, err, store.ErrNotFound)
	_, err = r.GetByName(ctx, "nope")
	is(t, err, store.ErrNotFound)

	list, err := r.List(ctx)
	ok(t, err)
	if len(list) != 3 || list[0].ID != net.ID || list[2].ID != both.ID {
		t.Fatalf("list %+v", list)
	}

	// Update: ключ неизменяем, сеть/rps/enabled меняются
	upd := got
	upd.Name = "ci-renamed"
	upd.RPS = 5
	upd.Enabled = false
	upd.KeyHash = hash("hijack")
	up, err := r.Update(ctx, upd)
	ok(t, err)
	if up.Name != "ci-renamed" || up.RPS != 5 || up.Enabled || !bytes.Equal(up.KeyHash, hash("k1")) {
		t.Fatalf("update %+v", up)
	}
	// обнуление сетей у правила без ключа нарушает инвариант
	nn := net
	nn.CIDRs = nil
	_, err = r.Update(ctx, nn)
	is(t, err, store.ErrInvalid)
	// у правила с ключом сети можно убрать
	bb := both
	bb.CIDRs = nil
	_, err = r.Update(ctx, bb)
	ok(t, err)
	_, err = r.Update(ctx, store.AccessRule{ID: 9999, Name: "x", CIDRs: nets})
	is(t, err, store.ErrNotFound)
	dup := net
	dup.Name = "ci-renamed"
	_, err = r.Update(ctx, dup)
	is(t, err, store.ErrConflict)

	// Revoke
	v2, _ := r.Version(ctx)
	ok(t, r.Revoke(ctx, both.ID))
	rev, _ := r.Get(ctx, both.ID)
	if rev.Enabled || rev.RevokedAt == nil || !bytes.Equal(rev.KeyHash, hash("k2")) {
		t.Fatalf("revoked %+v", rev)
	}
	first := *rev.RevokedAt
	ok(t, r.Revoke(ctx, both.ID))
	rev, _ = r.Get(ctx, both.ID)
	sameTime(t, *rev.RevokedAt, first)
	is(t, r.Revoke(ctx, 9999), store.ErrNotFound)
	if v3, _ := r.Version(ctx); v3 <= v2 {
		t.Fatal("version did not grow on revoke")
	}

	v3, _ := r.Version(ctx)
	ok(t, r.Delete(ctx, net.ID))
	is(t, r.Delete(ctx, net.ID), store.ErrNotFound)
	if v4, _ := r.Version(ctx); v4 <= v3 {
		t.Fatal("version did not grow on delete")
	}
}

func testSessions(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Sessions()
	now := time.Now()
	mk := func(id, user string) store.Session {
		return store.Session{ID: id, User: user, Kind: "full", IP: "10.0.0.1",
			IdleExpiresAt: now.Add(30 * time.Minute), ExpiresAt: now.Add(12 * time.Hour)}
	}
	ok(t, r.Create(ctx, mk("s1", "alice")))
	ok(t, r.Create(ctx, mk("s2", "alice")))
	ok(t, r.Create(ctx, mk("s3", "bob")))
	is(t, r.Create(ctx, mk("s1", "alice")), store.ErrConflict)
	is(t, r.Create(ctx, store.Session{ID: "x", User: "u", Kind: "bogus"}), store.ErrInvalid)

	got, err := r.Get(ctx, "s1")
	ok(t, err)
	if got.User != "alice" || got.Kind != "full" || got.IP != "10.0.0.1" || got.CreatedAt.IsZero() {
		t.Fatalf("got %+v", got)
	}
	_, err = r.Get(ctx, "nope")
	is(t, err, store.ErrNotFound)

	// Touch продлевает idle, но не дальше абсолютного дедлайна
	ok(t, r.Touch(ctx, "s1", now.Add(40*time.Minute)))
	got, _ = r.Get(ctx, "s1")
	sameTime(t, got.IdleExpiresAt, now.Add(40*time.Minute))
	ok(t, r.Touch(ctx, "s1", now.Add(100*time.Hour)))
	got, _ = r.Get(ctx, "s1")
	sameTime(t, got.IdleExpiresAt, now.Add(12*time.Hour))
	is(t, r.Touch(ctx, "nope", now), store.ErrNotFound)

	// истёкшие невидимы
	expired := mk("old-idle", "carol")
	expired.IdleExpiresAt = now.Add(-time.Second)
	ok(t, r.Create(ctx, expired))
	abs := mk("old-abs", "carol")
	abs.ExpiresAt = now.Add(-time.Second)
	ok(t, r.Create(ctx, abs))
	for _, id := range []string{"old-idle", "old-abs"} {
		_, err = r.Get(ctx, id)
		is(t, err, store.ErrNotFound)
		is(t, r.Touch(ctx, id, now.Add(time.Hour)), store.ErrNotFound)
	}
	_ = n(r.DeleteExpired(ctx))

	ok(t, r.Delete(ctx, "s3"))
	ok(t, r.Delete(ctx, "s3")) // идемпотентно
	_, err = r.Get(ctx, "s3")
	is(t, err, store.ErrNotFound)

	cnt, err := r.DeleteByUser(ctx, "alice")
	ok(t, err)
	if cnt != 2 {
		t.Fatalf("DeleteByUser = %d", cnt)
	}
	_, err = r.Get(ctx, "s1")
	is(t, err, store.ErrNotFound)
	cnt, err = r.DeleteByUser(ctx, "alice")
	ok(t, err)
	if cnt != 0 {
		t.Fatalf("second DeleteByUser = %d", cnt)
	}
}

func n(v int, err error) int {
	if err != nil {
		panic(err)
	}
	return v
}

func testRateState(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.RateState()

	_, err := r.Get(ctx, "k")
	is(t, err, store.ErrNotFound)
	ok(t, r.Set(ctx, "k", []byte("v1"), time.Minute))
	w, err := r.Get(ctx, "k")
	ok(t, err)
	if string(w.Value) != "v1" || w.Key != "k" || !w.ExpiresAt.After(time.Now()) {
		t.Fatalf("got %+v", w)
	}
	ok(t, r.Set(ctx, "k", []byte("v2"), time.Minute))
	w, _ = r.Get(ctx, "k")
	if string(w.Value) != "v2" {
		t.Fatalf("overwrite: %q", w.Value)
	}
	ok(t, r.Delete(ctx, "k"))
	ok(t, r.Delete(ctx, "k"))
	_, err = r.Get(ctx, "k")
	is(t, err, store.ErrNotFound)

	// TTL
	ok(t, r.Set(ctx, "short", []byte("x"), 40*time.Millisecond))
	time.Sleep(120 * time.Millisecond)
	_, err = r.Get(ctx, "short")
	is(t, err, store.ErrNotFound)

	// SetNX
	set, err := r.SetNX(ctx, "nx", []byte("a"), time.Minute)
	ok(t, err)
	if !set {
		t.Fatal("first SetNX must succeed")
	}
	set, err = r.SetNX(ctx, "nx", []byte("b"), time.Minute)
	ok(t, err)
	if set {
		t.Fatal("second SetNX must fail")
	}
	w, _ = r.Get(ctx, "nx")
	if string(w.Value) != "a" {
		t.Fatalf("nx value %q", w.Value)
	}
	ok(t, r.Set(ctx, "nx-short", []byte("a"), 40*time.Millisecond))
	time.Sleep(120 * time.Millisecond)
	set, err = r.SetNX(ctx, "nx-short", []byte("b"), time.Minute)
	ok(t, err)
	if !set {
		t.Fatal("SetNX over expired key must succeed")
	}

	// Incr: счётчик, TTL фиксируется при создании окна
	for i := int64(1); i <= 3; i++ {
		v, err := r.Incr(ctx, "cnt", time.Minute)
		ok(t, err)
		if v != i {
			t.Fatalf("Incr = %d, want %d", v, i)
		}
	}
	w, _ = r.Get(ctx, "cnt")
	if string(w.Value) != "3" {
		t.Fatalf("cnt value %q", w.Value)
	}
	if _, err := r.Incr(ctx, "cnt-short", 60*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	v, err := r.Incr(ctx, "cnt-short", time.Minute)
	ok(t, err)
	if v != 1 {
		t.Fatalf("Incr after expiry = %d, want 1", v)
	}

	// конкурентный Incr без потерь
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _, _ = r.Incr(ctx, "par", time.Minute) })
	}
	wg.Wait()
	w, err = r.Get(ctx, "par")
	ok(t, err)
	if string(w.Value) != "20" {
		t.Fatalf("par = %q, want 20", w.Value)
	}

	_ = n(r.DeleteExpired(ctx))
}

func testOutbox(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Outbox()
	_, err := r.LastByKey(ctx, "a1|agent_down")
	is(t, err, store.ErrNotFound)
	_, err = r.Enqueue(ctx, store.OutboxItem{DedupKey: "k", Type: "t", State: "weird"})
	is(t, err, store.ErrInvalid)

	i1, err := r.Enqueue(ctx, store.OutboxItem{DedupKey: "a1|agent_down", AgentID: "a1", Type: "agent_down", State: store.OutboxFiring, Text: "down"})
	ok(t, err)
	i2, err := r.Enqueue(ctx, store.OutboxItem{DedupKey: "a1|agent_down", AgentID: "a1", Type: "agent_down", State: store.OutboxResolved, Text: "up"})
	ok(t, err)
	i3, err := r.Enqueue(ctx, store.OutboxItem{DedupKey: "a2|overload", AgentID: "a2", Type: "overload", State: store.OutboxFiring})
	ok(t, err)
	if i1.ID >= i2.ID || i2.ID >= i3.ID {
		t.Fatalf("ids %d %d %d", i1.ID, i2.ID, i3.ID)
	}

	p, err := r.Pending(ctx, 2)
	ok(t, err)
	if len(p) != 2 || p[0].ID != i1.ID || p[1].ID != i2.ID {
		t.Fatalf("pending %+v", p)
	}
	if c, _ := r.CountPending(ctx); c != 3 {
		t.Fatalf("count %d", c)
	}
	rec, err := r.Recent(ctx, 2)
	ok(t, err)
	if len(rec) != 2 || rec[0].ID != i3.ID || rec[1].ID != i2.ID {
		t.Fatalf("recent %+v", rec)
	}
	last, err := r.LastByKey(ctx, "a1|agent_down")
	ok(t, err)
	if last.ID != i2.ID || last.State != store.OutboxResolved {
		t.Fatalf("last %+v", last)
	}

	ok(t, r.RecordAttempt(ctx, i1.ID, "tg 502"))
	p, _ = r.Pending(ctx, 10)
	if p[0].Attempts != 1 || p[0].LastError != "tg 502" {
		t.Fatalf("attempt %+v", p[0])
	}
	sent := time.Now().Add(-time.Hour)
	ok(t, r.MarkSent(ctx, i1.ID, sent))
	is(t, r.MarkSent(ctx, 9999, sent), store.ErrNotFound)
	is(t, r.RecordAttempt(ctx, 9999, "x"), store.ErrNotFound)
	if c, _ := r.CountPending(ctx); c != 2 {
		t.Fatalf("count after send %d", c)
	}
	last, _ = r.LastByKey(ctx, "a1|agent_down")
	if last.ID != i2.ID {
		t.Fatalf("last %+v", last)
	}
	if d := n(r.DeleteSentBefore(ctx, sent.Add(-time.Minute))); d != 0 {
		t.Fatalf("deleted %d, want 0", d)
	}
	if d := n(r.DeleteSentBefore(ctx, time.Now())); d != 1 {
		t.Fatalf("deleted %d, want 1", d)
	}
}

func testHistory(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.History()
	base := time.Now().Truncate(time.Hour)
	at := func(i int) time.Time { return base.Add(time.Duration(i) * 10 * time.Second) }

	var in []store.Sample
	for i := range 6 {
		in = append(in,
			store.Sample{At: at(i), AgentID: "a1", OK: int64(i), Err: 1, RateLimited: 2, P95Ms: 12.5, Inflight: 3, Buckets: []int64{1, 2, 3}},
			store.Sample{At: at(i), AgentID: "a2", OK: 100},
		)
	}
	ok(t, r.Append(ctx, store.Res10s, in))
	ok(t, r.Append(ctx, store.Res10s, nil))
	is(t, r.Append(ctx, "bogus", in), store.ErrInvalid)

	got, err := r.Range(ctx, store.Res10s, "a1", at(1), at(4))
	ok(t, err)
	if len(got) != 3 || got[0].OK != 1 || got[2].OK != 3 {
		t.Fatalf("range a1: %+v", got)
	}
	if got[0].P95Ms != 12.5 || got[0].Inflight != 3 || got[0].RateLimited != 2 || len(got[0].Buckets) != 3 || got[0].Buckets[2] != 3 {
		t.Fatalf("fields: %+v", got[0])
	}
	all, err := r.Range(ctx, store.Res10s, "", at(0), at(6))
	ok(t, err)
	if len(all) != 12 {
		t.Fatalf("all %d", len(all))
	}
	if all[0].At.After(all[len(all)-1].At) {
		t.Fatal("not ascending")
	}

	// upsert по (agent, at)
	ok(t, r.Append(ctx, store.Res10s, []store.Sample{{At: at(0), AgentID: "a1", OK: 999}}))
	got, _ = r.Range(ctx, store.Res10s, "a1", at(0), at(1))
	if len(got) != 1 || got[0].OK != 999 {
		t.Fatalf("upsert %+v", got)
	}

	// разрешения изолированы
	ok(t, r.Append(ctx, store.Res5m, []store.Sample{{At: at(0), AgentID: "a1", OK: 7}}))
	got, _ = r.Range(ctx, store.Res5m, "", at(0), at(6))
	if len(got) != 1 {
		t.Fatalf("5m %+v", got)
	}
	_, err = r.Range(ctx, "bogus", "", at(0), at(1))
	is(t, err, store.ErrInvalid)
	_, err = r.Prune(ctx, "bogus", at(0))
	is(t, err, store.ErrInvalid)

	pr, err := r.Prune(ctx, store.Res10s, at(3))
	ok(t, err)
	if pr != 6 {
		t.Fatalf("pruned %d", pr)
	}
	all, _ = r.Range(ctx, store.Res10s, "", at(0), at(6))
	if len(all) != 6 {
		t.Fatalf("after prune %d", len(all))
	}
}

func testAudit(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Audit()
	_, err := r.Append(ctx, store.AuditEntry{Action: "login"})
	is(t, err, store.ErrInvalid)
	for i := range 5 {
		actor := "alice"
		if i%2 == 1 {
			actor = "bob"
		}
		e, err := r.Append(ctx, store.AuditEntry{Actor: actor, Action: "act" + strconv.Itoa(i), Target: "t", IP: "1.2.3.4", Detail: "d"})
		ok(t, err)
		if e.ID == 0 || e.At.IsZero() {
			t.Fatalf("entry %+v", e)
		}
	}
	all, err := r.List(ctx, store.AuditQuery{})
	ok(t, err)
	if len(all) != 5 || all[0].Action != "act4" || all[4].Action != "act0" {
		t.Fatalf("all %+v", all)
	}
	page1, _ := r.List(ctx, store.AuditQuery{Limit: 2})
	page2, _ := r.List(ctx, store.AuditQuery{Limit: 2, BeforeID: page1[1].ID})
	if len(page1) != 2 || len(page2) != 2 || page2[0].ID >= page1[1].ID {
		t.Fatalf("pages %+v / %+v", page1, page2)
	}
	// вставка между запросами не ломает курсор
	_, _ = r.Append(ctx, store.AuditEntry{Actor: "alice", Action: "late"})
	page2b, _ := r.List(ctx, store.AuditQuery{Limit: 2, BeforeID: page1[1].ID})
	if fmt.Sprint(page2) != fmt.Sprint(page2b) {
		t.Fatalf("cursor unstable: %+v vs %+v", page2, page2b)
	}
	bob, _ := r.List(ctx, store.AuditQuery{Actor: "bob"})
	if len(bob) != 2 {
		t.Fatalf("bob %+v", bob)
	}
}

func testHostKeys(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.HostKeys()
	_, err := r.Get(ctx, "10.0.0.1:22")
	is(t, err, store.ErrNotFound)
	is(t, r.Put(ctx, store.HostKey{Host: "10.0.0.1:22"}), store.ErrInvalid)
	k := store.HostKey{Host: "10.0.0.1:22", Algo: "ssh-ed25519", Fingerprint: "SHA256:abc", PublicKey: []byte{1, 2, 3}}
	ok(t, r.Put(ctx, k))
	got, err := r.Get(ctx, "10.0.0.1:22")
	ok(t, err)
	if got.Fingerprint != "SHA256:abc" || !bytes.Equal(got.PublicKey, k.PublicKey) || got.Algo != "ssh-ed25519" || got.CreatedAt.IsZero() {
		t.Fatalf("got %+v", got)
	}
	k.AgentID = "a1"
	k.Fingerprint = "SHA256:def"
	ok(t, r.Put(ctx, k))
	got, _ = r.Get(ctx, "10.0.0.1:22")
	if got.AgentID != "a1" || got.Fingerprint != "SHA256:def" {
		t.Fatalf("upsert %+v", got)
	}
	k2 := store.HostKey{Host: "10.0.0.0:22", Algo: "ssh-rsa", Fingerprint: "SHA256:zzz", PublicKey: []byte{9}}
	ok(t, r.Put(ctx, k2))
	list, err := r.List(ctx)
	ok(t, err)
	if len(list) != 2 || list[0].Host != "10.0.0.0:22" || list[1].Host != "10.0.0.1:22" || list[1].Fingerprint != "SHA256:def" {
		t.Fatalf("list %+v", list)
	}
	ok(t, r.Delete(ctx, "10.0.0.1:22"))
	is(t, r.Delete(ctx, "10.0.0.1:22"), store.ErrNotFound)
	ok(t, r.Delete(ctx, "10.0.0.0:22"))
	list, err = r.List(ctx)
	ok(t, err)
	if len(list) != 0 {
		t.Fatalf("list after delete %+v", list)
	}
}

func testCerts(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Certs()
	now := time.Now()
	mk := func(serial, agent string, days int) store.CertRecord {
		return store.CertRecord{Serial: serial, AgentID: agent, Subject: "spiffe://tgproxy/agent/" + agent,
			NotBefore: now, NotAfter: now.Add(time.Duration(days) * 24 * time.Hour), CertPEM: []byte("PEM-" + serial)}
	}
	is(t, r.Put(ctx, store.CertRecord{Serial: "x"}), store.ErrInvalid)
	ok(t, r.Put(ctx, mk("01", "a1", 90)))
	ok(t, r.Put(ctx, mk("02", "a1", 10)))
	ok(t, r.Put(ctx, mk("03", "a2", 5)))
	is(t, r.Put(ctx, mk("01", "a1", 90)), store.ErrConflict)

	got, err := r.Get(ctx, "02")
	ok(t, err)
	if got.AgentID != "a1" || string(got.CertPEM) != "PEM-02" {
		t.Fatalf("got %+v", got)
	}
	_, err = r.Get(ctx, "99")
	is(t, err, store.ErrNotFound)
	byAgent, _ := r.ListByAgent(ctx, "a1")
	if len(byAgent) != 2 || byAgent[0].Serial != "02" {
		t.Fatalf("by agent %+v", byAgent)
	}
	exp, _ := r.ListExpiring(ctx, now.Add(14*24*time.Hour))
	if len(exp) != 2 || exp[0].Serial != "03" || exp[1].Serial != "02" {
		t.Fatalf("expiring %+v", exp)
	}

	// denylist
	d, err := r.IsDenied(ctx, "02")
	ok(t, err)
	if d {
		t.Fatal("not denied yet")
	}
	ok(t, r.Deny(ctx, store.DeniedCert{Serial: "02", AgentID: "a1", Reason: "removed", NotAfter: now.Add(time.Hour)}))
	ok(t, r.Deny(ctx, store.DeniedCert{Serial: "02", AgentID: "a1", Reason: "again"})) // идемпотентно
	ok(t, r.Deny(ctx, store.DeniedCert{Serial: "old", NotAfter: now.Add(-time.Hour)}))
	is(t, r.Deny(ctx, store.DeniedCert{}), store.ErrInvalid)
	d, _ = r.IsDenied(ctx, "02")
	if !d {
		t.Fatal("must be denied")
	}
	list, _ := r.ListDenied(ctx)
	if len(list) != 2 {
		t.Fatalf("denied %+v", list)
	}
	if pr := n(r.PruneDenied(ctx, now)); pr != 1 {
		t.Fatalf("pruned %d", pr)
	}
	if d, _ := r.IsDenied(ctx, "old"); d {
		t.Fatal("old must be pruned")
	}

	// CA
	_, err = r.LoadCA(ctx)
	is(t, err, store.ErrNotFound)
	is(t, r.SaveCA(ctx, store.CARecord{CertPEM: []byte("c")}), store.ErrInvalid)
	ok(t, r.SaveCA(ctx, store.CARecord{CertPEM: []byte("cert"), SealedKey: []byte("sealed")}))
	is(t, r.SaveCA(ctx, store.CARecord{CertPEM: []byte("cert2"), SealedKey: []byte("sealed2")}), store.ErrConflict)
	ca, err := r.LoadCA(ctx)
	ok(t, err)
	if string(ca.CertPEM) != "cert" || string(ca.SealedKey) != "sealed" {
		t.Fatalf("ca %+v", ca)
	}
}

func testEnrollments(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Enrollments()
	now := time.Now()
	mk := func(id, tok string, ttl time.Duration) store.Enrollment {
		return store.Enrollment{ID: id, TokenHash: hash(tok), Name: "nat-" + id, Weight: 50, CreatedBy: "admin", ExpiresAt: now.Add(ttl)}
	}
	is(t, r.Create(ctx, store.Enrollment{ID: "bad"}), store.ErrInvalid)
	ok(t, r.Create(ctx, mk("e1", "t1", time.Hour)))
	ok(t, r.Create(ctx, mk("e2", "t2", -time.Minute)))
	is(t, r.Create(ctx, mk("e3", "t1", time.Hour)), store.ErrConflict)

	pend, _ := r.ListPending(ctx, now)
	if len(pend) != 1 || pend[0].ID != "e1" {
		t.Fatalf("pending %+v", pend)
	}

	e, err := r.Consume(ctx, hash("t1"), now)
	ok(t, err)
	if e.ID != "e1" || e.Name != "nat-e1" || e.Weight != 50 || e.UsedAt == nil {
		t.Fatalf("consumed %+v", e)
	}
	// повторное использование, просроченный и неизвестный токены неразличимы
	for _, tok := range []string{"t1", "t2", "unknown"} {
		_, err = r.Consume(ctx, hash(tok), now)
		is(t, err, store.ErrNotFound)
	}
	if p, _ := r.ListPending(ctx, now); len(p) != 0 {
		t.Fatalf("pending after consume %+v", p)
	}

	// гонка: токен гасится ровно один раз
	ok(t, r.Create(ctx, mk("e4", "race", time.Hour)))
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 10 {
		wg.Go(func() {
			if _, err := r.Consume(ctx, hash("race"), now); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("token consumed %d times", wins)
	}
	// отзыв: неиспользованный удаляется, повтор/использованный/неизвестный — ErrNotFound
	ok(t, r.Create(ctx, mk("e5", "revoke", time.Hour)))
	ok(t, r.Delete(ctx, "e5"))
	is(t, r.Delete(ctx, "e5"), store.ErrNotFound)
	is(t, r.Delete(ctx, "e1"), store.ErrNotFound) // уже использован
	is(t, r.Delete(ctx, "nope"), store.ErrNotFound)
	if _, err := r.Consume(ctx, hash("revoke"), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked token consumed: %v", err)
	}

	if d := n(r.DeleteExpired(ctx, now)); d != 1 {
		t.Fatalf("deleted %d", d)
	}
}

func testErrorEvents(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Errors()
	_, err := r.Append(ctx, store.ErrorEvent{Outcome: "weird"})
	is(t, err, store.ErrInvalid)

	base := time.Now().Add(-time.Hour)
	for i := range 10 {
		agent, outcome := "a1", store.OutcomeRetried
		if i%2 == 1 {
			agent, outcome = "a2", store.OutcomeFailedToBot
		}
		e, err := r.Append(ctx, store.ErrorEvent{At: base.Add(time.Duration(i) * time.Minute), RequestID: "r" + strconv.Itoa(i),
			BotID: "123", AgentID: agent, Method: "sendMessage", Phase: "write", Code: 502, Outcome: outcome, Description: "boom"})
		ok(t, err)
		if e.ID == 0 {
			t.Fatal("no id")
		}
	}
	page1, err := r.List(ctx, store.ErrorQuery{Limit: 4})
	ok(t, err)
	if len(page1) != 4 || page1[0].RequestID != "r9" {
		t.Fatalf("page1 %+v", page1)
	}
	page2, _ := r.List(ctx, store.ErrorQuery{Limit: 4, BeforeID: page1[3].ID})
	if len(page2) != 4 || page2[0].RequestID != "r5" {
		t.Fatalf("page2 %+v", page2)
	}
	_, _ = r.Append(ctx, store.ErrorEvent{Outcome: store.OutcomePassedToBot, Method: "getMe"})
	page2b, _ := r.List(ctx, store.ErrorQuery{Limit: 4, BeforeID: page1[3].ID})
	if fmt.Sprint(page2) != fmt.Sprint(page2b) {
		t.Fatal("cursor unstable under insert")
	}
	f, _ := r.List(ctx, store.ErrorQuery{AgentID: "a2"})
	if len(f) != 5 {
		t.Fatalf("agent filter %d", len(f))
	}
	f, _ = r.List(ctx, store.ErrorQuery{Outcome: store.OutcomePassedToBot, Method: "getMe", BotID: ""})
	if len(f) != 1 {
		t.Fatalf("outcome filter %d", len(f))
	}
	f, _ = r.List(ctx, store.ErrorQuery{BotID: "123"})
	if len(f) != 10 {
		t.Fatalf("bot filter %d", len(f))
	}

	f, _ = r.List(ctx, store.ErrorQuery{Phase: "write", Code: 502, RequestID: "r3"})
	if len(f) != 1 || f[0].RequestID != "r3" {
		t.Fatalf("phase/code/request filter %+v", f)
	}
	if f, _ = r.List(ctx, store.ErrorQuery{Phase: "dial"}); len(f) != 0 {
		t.Fatalf("phase filter %d", len(f))
	}
	if f, _ = r.List(ctx, store.ErrorQuery{Code: 429}); len(f) != 0 {
		t.Fatalf("code filter %d", len(f))
	}

	// Trim: по возрасту, затем по количеству
	if d, err := r.Trim(ctx, 0, base.Add(2*time.Minute+time.Second)); err != nil || d != 3 {
		t.Fatalf("trim by time = %d, %v", d, err)
	}
	if d, err := r.Trim(ctx, 5, time.Time{}); err != nil || d != 3 {
		t.Fatalf("trim by keep = %d, %v", d, err)
	}
	all, _ := r.List(ctx, store.ErrorQuery{Limit: 100})
	if len(all) != 5 {
		t.Fatalf("after trim %d", len(all))
	}
}

func testInstallJobs(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.InstallJobs()
	_, err := r.Get(ctx, "j1")
	is(t, err, store.ErrNotFound)
	is(t, r.Create(ctx, store.InstallJob{ID: "j1"}), store.ErrInvalid)
	j := store.InstallJob{ID: "j1", Host: "10.0.0.1:22", Kind: "install", State: store.InstallRunning}
	ok(t, r.Create(ctx, j))
	is(t, r.Create(ctx, j), store.ErrConflict)
	got, err := r.Get(ctx, "j1")
	ok(t, err)
	if got.State != store.InstallRunning || got.FinishedAt != nil || got.CreatedAt.IsZero() || got.Host != j.Host {
		t.Fatalf("got %+v", got)
	}
	ok(t, r.SetAgent(ctx, "j1", "ams-2"))
	is(t, r.SetAgent(ctx, "nope", "x"), store.ErrNotFound)
	ok(t, r.SetState(ctx, "j1", store.InstallFailed, "boom"))
	is(t, r.SetState(ctx, "nope", store.InstallDone, ""), store.ErrNotFound)
	is(t, r.SetState(ctx, "j1", "", ""), store.ErrInvalid)
	got, _ = r.Get(ctx, "j1")
	if got.State != store.InstallFailed || got.Error != "boom" || got.FinishedAt == nil || got.AgentID != "ams-2" {
		t.Fatalf("after state %+v", got)
	}

	_, err = r.AppendEvent(ctx, store.InstallJobEvent{JobID: "j1"})
	is(t, err, store.ErrInvalid)
	_, err = r.AppendEvent(ctx, store.InstallJobEvent{JobID: "ghost", Kind: "log"})
	if err == nil {
		t.Fatal("event for unknown job accepted")
	}
	var last int64
	for i := 0; i < 3; i++ {
		e, err := r.AppendEvent(ctx, store.InstallJobEvent{JobID: "j1", Kind: "log", Step: "ssh", Message: fmt.Sprint("m", i)})
		ok(t, err)
		if e.ID <= last || e.Level != "info" || e.At.IsZero() {
			t.Fatalf("event %+v after %d", e, last)
		}
		last = e.ID
	}
	all, err := r.Events(ctx, "j1", 0)
	ok(t, err)
	if len(all) != 3 || all[0].Message != "m0" || all[2].Kind != "log" || all[1].Step != "ssh" {
		t.Fatalf("events %+v", all)
	}
	tail, _ := r.Events(ctx, "j1", all[0].ID)
	if len(tail) != 2 || tail[0].Message != "m1" {
		t.Fatalf("tail %+v", tail)
	}
	none, _ := r.Events(ctx, "other", 0)
	if len(none) != 0 {
		t.Fatalf("other %+v", none)
	}
}

func testSettings(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Settings()
	_, err := r.Get(ctx, "notify.events")
	is(t, err, store.ErrNotFound)
	ok(t, r.Set(ctx, "notify.events", "a"))
	ok(t, r.Set(ctx, "other", "x"))
	ok(t, r.Set(ctx, "notify.events", "b"))
	v, err := r.Get(ctx, "notify.events")
	ok(t, err)
	if v != "b" {
		t.Fatalf("value = %q, want b", v)
	}
	all, err := r.List(ctx)
	ok(t, err)
	if len(all) != 2 || all["other"] != "x" || all["notify.events"] != "b" {
		t.Fatalf("list = %v", all)
	}
	is(t, r.Set(ctx, "", "v"), store.ErrInvalid)
}

func testRollouts(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Rollouts()
	_, err := r.Active(ctx)
	is(t, err, store.ErrNotFound)
	_, err = r.Latest(ctx)
	is(t, err, store.ErrNotFound)
	_, err = r.Get(ctx, "r1")
	is(t, err, store.ErrNotFound)
	is(t, r.Create(ctx, store.Rollout{ID: "r1"}, nil), store.ErrInvalid)

	o := store.Rollout{ID: "r1", Version: "1.2.0", BatchSize: 2, Canary: 1, State: store.RolloutRunning, Actor: "admin"}
	steps := []store.RolloutStep{
		{AgentID: "b", Seq: 2, Phase: store.PhaseBatch, State: store.StepPending},
		{AgentID: "a", Seq: 1, Phase: store.PhaseCanary, State: store.StepPending},
	}
	is(t, r.Create(ctx, o, []store.RolloutStep{{AgentID: "a", State: store.StepPending}}), store.ErrInvalid)
	ok(t, r.Create(ctx, o, steps))
	is(t, r.Create(ctx, o, nil), store.ErrConflict)
	other := o
	other.ID = "r2"
	is(t, r.Create(ctx, other, nil), store.ErrConflict) // уже есть активная

	got, err := r.Active(ctx)
	ok(t, err)
	if got.ID != "r1" || got.Version != "1.2.0" || got.BatchSize != 2 || got.Canary != 1 || got.CreatedAt.IsZero() || got.FinishedAt != nil || got.Actor != "admin" {
		t.Fatalf("active %+v", got)
	}
	st, err := r.Steps(ctx, "r1")
	ok(t, err)
	if len(st) != 2 || st[0].AgentID != "a" || st[1].AgentID != "b" || st[0].Phase != store.PhaseCanary {
		t.Fatalf("steps %+v", st)
	}
	ok(t, r.SetStep(ctx, "r1", "a", store.StepRunning, "1.1.0", ""))
	ok(t, r.SetStep(ctx, "r1", "a", store.StepFailed, "", "boom"))
	is(t, r.SetStep(ctx, "r1", "ghost", store.StepDone, "", ""), store.ErrNotFound)
	is(t, r.SetStep(ctx, "r1", "a", "", "", ""), store.ErrInvalid)
	st, _ = r.Steps(ctx, "r1")
	if st[0].State != store.StepFailed || st[0].FromVersion != "1.1.0" || st[0].Error != "boom" || st[1].State != store.StepPending {
		t.Fatalf("steps after update %+v", st)
	}

	ok(t, r.SetState(ctx, "r1", store.RolloutStopping, ""))
	got, _ = r.Active(ctx)
	if got.State != store.RolloutStopping || got.FinishedAt != nil {
		t.Fatalf("stopping %+v", got)
	}
	ok(t, r.SetState(ctx, "r1", store.RolloutFailed, "canary a"))
	is(t, r.SetState(ctx, "nope", store.RolloutDone, ""), store.ErrNotFound)
	is(t, r.SetState(ctx, "r1", "", ""), store.ErrInvalid)
	_, err = r.Active(ctx)
	is(t, err, store.ErrNotFound)
	got, _ = r.Get(ctx, "r1")
	if got.State != store.RolloutFailed || got.Error != "canary a" || got.FinishedAt == nil {
		t.Fatalf("failed %+v", got)
	}

	ok(t, r.Create(ctx, other, nil)) // после завершения можно новую
	latest, err := r.Latest(ctx)
	ok(t, err)
	if latest.ID != "r2" {
		t.Fatalf("latest %+v", latest)
	}
}

func testBans(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Bans()
	v0, err := r.Version(ctx)
	ok(t, err)
	_, err = r.Get(ctx, 1)
	is(t, err, store.ErrNotFound)
	_, err = r.GetByPrefix(ctx, netip.MustParsePrefix("1.2.3.4/32"))
	is(t, err, store.ErrNotFound)
	is(t, r.Delete(ctx, 1), store.ErrNotFound)

	for _, bad := range []store.Ban{
		{Prefix: netip.MustParsePrefix("1.2.3.0/24"), Source: store.BanManual},
		{Prefix: netip.MustParsePrefix("2001:db8::1/128"), Source: store.BanManual},
		{Prefix: netip.MustParsePrefix("2001:db8::/48"), Source: store.BanManual},
		{Prefix: netip.MustParsePrefix("1.2.3.4/32"), Source: "weird"},
		{Source: store.BanManual},
	} {
		_, err := r.Upsert(ctx, bad)
		is(t, err, store.ErrInvalid)
	}

	now := time.Now()
	exp := now.Add(time.Hour)
	b, err := r.Upsert(ctx, store.Ban{Prefix: netip.MustParsePrefix("1.2.3.4/32"), Source: store.BanAuto, Actor: "auto",
		Comment: "x", CreatedAt: now, ExpiresAt: &exp, Level: 1})
	ok(t, err)
	if b.ID == 0 || b.Level != 1 || b.ExpiresAt == nil || b.Source != store.BanAuto || b.Hits != 0 {
		t.Fatalf("ban %+v", b)
	}
	perm, err := r.Upsert(ctx, store.Ban{Prefix: netip.MustParsePrefix("2001:db8:0:1::/64"), Source: store.BanManual, Actor: "admin"})
	ok(t, err)
	if perm.ExpiresAt != nil {
		t.Fatal("permanent expected")
	}
	past := now.Add(-time.Hour)
	expired, err := r.Upsert(ctx, store.Ban{Prefix: netip.MustParsePrefix("5.6.7.8/32"), Source: store.BanAuto, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: &past})
	ok(t, err)
	v1, _ := r.Version(ctx)
	if v1 <= v0 {
		t.Fatalf("version did not grow: %d -> %d", v0, v1)
	}

	act, err := r.ListActive(ctx, now)
	ok(t, err)
	if len(act) != 2 || act[0].ID != perm.ID || act[1].ID != b.ID {
		t.Fatalf("active %+v", act)
	}
	got, err := r.GetByPrefix(ctx, expired.Prefix)
	ok(t, err)
	if got.ID != expired.ID {
		t.Fatalf("expired still stored: %+v", got)
	}

	// hits не двигают версию
	ok(t, r.AddHits(ctx, b.ID, 5, now.Add(time.Minute)))
	ok(t, r.AddHits(ctx, b.ID, 0, now))
	ok(t, r.AddHits(ctx, 9999, 3, now))
	v2, _ := r.Version(ctx)
	if v2 != v1 {
		t.Fatalf("hits changed version %d -> %d", v1, v2)
	}
	got, _ = r.Get(ctx, b.ID)
	if got.Hits != 5 || !got.LastHitAt.After(b.CreatedAt) {
		t.Fatalf("hits %+v", got)
	}

	// повторный бан того же префикса: тот же id, hits обнулены, level новый
	again, err := r.Upsert(ctx, store.Ban{Prefix: b.Prefix, Source: store.BanManual, Actor: "admin", Level: 2, CreatedAt: now.Add(2 * time.Minute)})
	ok(t, err)
	if again.ID != b.ID || again.Hits != 0 || again.Level != 2 || again.Source != store.BanManual || again.ExpiresAt != nil {
		t.Fatalf("re-ban %+v", again)
	}
	v3, _ := r.Version(ctx)
	if v3 <= v2 {
		t.Fatal("re-ban must change version")
	}

	// prune: только истёкшие без недавней активности
	n, err := r.Prune(ctx, now.Add(-30*time.Minute))
	ok(t, err)
	if n != 1 {
		t.Fatalf("pruned %d", n)
	}
	_, err = r.Get(ctx, expired.ID)
	is(t, err, store.ErrNotFound)

	ok(t, r.Delete(ctx, perm.ID))
	act, _ = r.ListActive(ctx, now)
	if len(act) != 1 || act[0].ID != b.ID {
		t.Fatalf("after delete %+v", act)
	}
}

func testDeniedSamples(t *testing.T, s store.Store) {
	ctx := context.Background()
	h := s.History()
	at := time.Now().Truncate(10 * time.Second)
	ok(t, h.Append(ctx, store.Res10s, []store.Sample{
		{At: at, AgentID: "*", OK: 1, Denied: map[string]int64{"no_rule": 3, "banned": 7}},
		{At: at, AgentID: "a1", OK: 1},
	}))
	got, err := h.Range(ctx, store.Res10s, "", at, at.Add(time.Second))
	ok(t, err)
	if len(got) != 2 {
		t.Fatalf("rows %+v", got)
	}
	for _, g := range got {
		switch g.AgentID {
		case "*":
			if g.Denied["no_rule"] != 3 || g.Denied["banned"] != 7 || len(g.Denied) != 2 {
				t.Fatalf("denied %+v", g.Denied)
			}
		default:
			if len(g.Denied) != 0 {
				t.Fatalf("unexpected denied %+v", g.Denied)
			}
		}
	}
}

func testAccessDenials(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := s.Errors()
	for i, reason := range []string{"no_rule", "key_required", "bad_key"} {
		_, err := r.Append(ctx, store.ErrorEvent{RequestID: "d" + strconv.Itoa(i), Phase: "access", Code: 403,
			Outcome: store.OutcomeFailedToBot, ClientIP: "203.0.113." + strconv.Itoa(i%2+1), Reason: reason})
		ok(t, err)
	}
	got, err := r.List(ctx, store.ErrorQuery{Reason: "key_required"})
	ok(t, err)
	if len(got) != 1 || got[0].ClientIP != "203.0.113.2" || got[0].Reason != "key_required" {
		t.Fatalf("reason filter %+v", got)
	}
	got, err = r.List(ctx, store.ErrorQuery{ClientIP: "203.0.113.1"})
	ok(t, err)
	if len(got) != 2 {
		t.Fatalf("ip filter %+v", got)
	}
}
