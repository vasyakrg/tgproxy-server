package access

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func newRepo(t *testing.T) (store.AccessRuleRepo, *memtest.Store) {
	t.Helper()
	s := memtest.New()
	t.Cleanup(func() { _ = s.Close() })
	return s.AccessRules(), s
}

func mk(t *testing.T, repo store.AccessRuleRepo, r store.AccessRule) store.AccessRule {
	t.Helper()
	r.Enabled = true
	out, err := repo.Create(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fromStore(t *testing.T, repo store.AccessRuleRepo, trusted []netip.Prefix, opts ...Option) *Checker {
	t.Helper()
	c, err := NewFromStore(context.Background(), repo, trusted, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func denied(t *testing.T, c *Checker, remote, key string) {
	t.Helper()
	if _, err := c.Check(req(remote, "", ""), tgapi.Route{ClientKey: key}); !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestStoreRevokedKeyDenied(t *testing.T) {
	repo, _ := newRepo(t)
	r := mk(t, repo, store.AccessRule{Name: "k", KeyHash: h("secret")})
	c := fromStore(t, repo, nil)
	if info, err := c.Check(req("8.8.8.8:1", "", ""), tgapi.Route{ClientKey: "secret"}); err != nil || info.ID != r.ID {
		t.Fatal(info, err)
	}
	if err := repo.Revoke(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	denied(t, c, "8.8.8.8:1", "secret")
}

func TestStoreDisabledSkipped(t *testing.T) {
	repo, _ := newRepo(t)
	r := mk(t, repo, store.AccessRule{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}})
	c := fromStore(t, repo, nil)
	r.Enabled = false
	if _, err := repo.Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	_ = c.Refresh(context.Background())
	denied(t, c, "10.1.1.1:1", "")
}

func TestStoreCIDRAndBoth(t *testing.T) {
	repo, _ := newRepo(t)
	mk(t, repo, store.AccessRule{Name: "both", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}, KeyHash: h("k")})
	c := fromStore(t, repo, nil)
	denied(t, c, "8.8.8.8:1", "k")      // ключ верный, сеть чужая
	denied(t, c, "10.1.1.1:1", "")      // сеть своя, ключа нет
	denied(t, c, "10.1.1.1:1", "wrong") // неверный ключ
	if _, err := c.Check(req("10.1.1.1:1", "", ""), tgapi.Route{ClientKey: "k"}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreSpecificity(t *testing.T) {
	repo, _ := newRepo(t)
	mk(t, repo, store.AccessRule{Name: "net", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}})
	mk(t, repo, store.AccessRule{Name: "key", KeyHash: h("k2")})
	mk(t, repo, store.AccessRule{Name: "both", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}, KeyHash: h("k")})
	c := fromStore(t, repo, nil)
	info, err := c.Check(req("10.1.1.1:1", "", ""), tgapi.Route{ClientKey: "k"})
	if err != nil || info.Name != "both" {
		t.Fatal(info, err)
	}
	info, err = c.Check(req("8.8.8.8:1", "", ""), tgapi.Route{ClientKey: "k2"})
	if err != nil || info.Name != "key" {
		t.Fatal(info, err)
	}
	info, err = c.Check(req("10.1.1.1:1", "", ""), tgapi.Route{})
	if err != nil || info.Name != "net" {
		t.Fatal(info, err)
	}
}

func TestStoreXFFIgnoredWithoutTrusted(t *testing.T) {
	repo, _ := newRepo(t)
	mk(t, repo, store.AccessRule{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}})
	c := fromStore(t, repo, nil)
	if _, err := c.Check(req("8.8.8.8:1", "10.1.1.1", ""), tgapi.Route{}); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}

func TestRefreshOnTick(t *testing.T) {
	repo, _ := newRepo(t)
	tick := make(chan time.Time)
	c := fromStore(t, repo, nil, WithTickChannel(tick))
	denied(t, c, "10.1.1.1:1", "")
	mk(t, repo, store.AccessRule{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}})
	tick <- time.Now()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := c.Check(req("10.1.1.1:1", "", ""), tgapi.Route{}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rule not picked up after tick")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRefreshNoChangeKeepsSnapshot(t *testing.T) {
	repo, _ := newRepo(t)
	mk(t, repo, store.AccessRule{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}})
	c := fromStore(t, repo, nil)
	before := c.snap.Load()
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.snap.Load() != before {
		t.Fatal("snapshot rebuilt without version change")
	}
}

type failRepo struct {
	store.AccessRuleRepo
	verErr, listErr error
}

func (f failRepo) Version(ctx context.Context) (int64, error) {
	if f.verErr != nil {
		return 0, f.verErr
	}
	return f.AccessRuleRepo.Version(ctx)
}

func (f failRepo) List(ctx context.Context) ([]store.AccessRule, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.AccessRuleRepo.List(ctx)
}

func TestRefreshErrors(t *testing.T) {
	repo, _ := newRepo(t)
	boom := errors.New("boom")
	if _, err := NewFromStore(context.Background(), failRepo{repo, boom, nil}, nil); err == nil {
		t.Fatal("want version error")
	}
	if _, err := NewFromStore(context.Background(), failRepo{repo, nil, boom}, nil); err == nil {
		t.Fatal("want list error")
	}
}

func TestBackgroundErrorKeepsSnapshot(t *testing.T) {
	repo, _ := newRepo(t)
	mk(t, repo, store.AccessRule{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}})
	tick := make(chan time.Time)
	fr := &toggleRepo{AccessRuleRepo: repo}
	c := fromStore(t, fr, nil, WithTickChannel(tick))
	fr.fail.Store(true)
	tick <- time.Now()
	tick <- time.Now() // второй приём гарантирует, что первый Refresh завершён
	if _, err := c.Check(req("10.1.1.1:1", "", ""), tgapi.Route{}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshNilRepo(t *testing.T) {
	c, _ := NewStatic(nil, nil)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestParentCtxStopsLoop(t *testing.T) {
	repo, _ := newRepo(t)
	ctx, cancel := context.WithCancel(context.Background())
	c, err := NewFromStore(ctx, repo, nil, WithRefreshInterval(time.Hour), WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	<-c.done
	c.Close()
	c.Close()
}

func TestSkipsInvalidStoredRule(t *testing.T) {
	repo, _ := newRepo(t)
	fr := fixedRepo{AccessRuleRepo: repo, rules: []store.AccessRule{{ID: 1, Name: "bad", Enabled: true}}}
	c := fromStore(t, fr, nil)
	denied(t, c, "10.1.1.1:1", "")
}

func TestSeed(t *testing.T) {
	repo, _ := newRepo(t)
	ctx := context.Background()
	cfg := []config.AccessRule{
		{Name: "a", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}, RPS: 3},
		{Name: "b", KeySHA256: "x", KeyHash: h("k")},
		{Name: "a", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}},
	}
	n, err := SeedFromConfig(ctx, repo, cfg)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	n, err = SeedFromConfig(ctx, repo, cfg)
	if err != nil || n != 0 {
		t.Fatal(n, err)
	}
	l, _ := repo.List(ctx)
	if len(l) != 2 || !l[0].Enabled || l[0].RPS != 3 || !bytes.Equal(l[1].KeyHash, h("k")) {
		t.Fatalf("%+v", l)
	}
	c := fromStore(t, repo, nil)
	if _, err := c.Check(req("8.8.8.8:1", "", ""), tgapi.Route{ClientKey: "k"}); err != nil {
		t.Fatal(err)
	}
}

func TestSeedErrors(t *testing.T) {
	repo, _ := newRepo(t)
	ctx := context.Background()
	if _, err := SeedFromConfig(ctx, failRepo{repo, nil, errors.New("x")}, nil); err == nil {
		t.Fatal("want list error")
	}
	if _, err := SeedFromConfig(ctx, repo, []config.AccessRule{{Name: "open"}}); err == nil {
		t.Fatal("want invalid error")
	}
}

func TestNewKey(t *testing.T) {
	re := regexp.MustCompile(`^tgp_[0-9A-Za-z]{24}$`)
	seen := make(map[string]struct{}, 10000)
	for range 10000 {
		plain, hash, prefix, err := NewKey()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(plain) || prefix != plain[:8] || len(prefix) != 8 || !bytes.Equal(hash, HashKey(plain)) {
			t.Fatalf("bad key %q %q", plain, prefix)
		}
		if _, dup := seen[plain]; dup {
			t.Fatal("duplicate key")
		}
		seen[plain] = struct{}{}
	}
}

func TestPlainKeyNotStored(t *testing.T) {
	repo, _ := newRepo(t)
	plain, hash, prefix, _ := NewKey()
	mk(t, repo, store.AccessRule{Name: "k", KeyHash: hash, KeyPrefix: prefix})
	l, _ := repo.List(context.Background())
	r := l[0]
	if len(r.KeyHash) != 32 || bytes.Contains(r.KeyHash, []byte(plain)) || r.KeyPrefix == plain || len(r.KeyPrefix) != 8 {
		t.Fatalf("%+v", r)
	}
	c := fromStore(t, repo, nil)
	if info, err := c.Check(req("8.8.8.8:1", "", plain), tgapi.Route{}); err != nil || info.Name != "k" {
		t.Fatal(info, err)
	}
}
