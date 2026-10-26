package access

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

type toggleRepo struct {
	store.AccessRuleRepo
	fail atomic.Bool
}

func (f *toggleRepo) Version(ctx context.Context) (int64, error) {
	if f.fail.Load() {
		return 0, errors.New("down")
	}
	return f.AccessRuleRepo.Version(ctx)
}

type fixedRepo struct {
	store.AccessRuleRepo
	rules []store.AccessRule
}

func (f fixedRepo) List(context.Context) ([]store.AccessRule, error) { return f.rules, nil }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func rlRules(rps float64) []config.AccessRule {
	return []config.AccessRule{{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}, RPS: rps}}
}

func checkN(c *Checker) error {
	_, err := c.Check(req("10.1.1.1:1", "", ""), tgapi.Route{})
	return err
}

func TestRateLimit(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c, _ := NewStatic(rlRules(2), nil, WithClock(clk.now))
	for range 2 { // burst = 2
		if err := checkN(c); err != nil {
			t.Fatal(err)
		}
	}
	err := checkN(c)
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter < time.Second || rl.RetryAfter%time.Second != 0 {
		t.Fatalf("got %v", err)
	}
	if rl.Error() == "" {
		t.Fatal("empty message")
	}
	clk.add(600 * time.Millisecond) // восстановился 1 токен (rps=2)
	if err := checkN(c); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimitFractionalRPS(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c, _ := NewStatic(rlRules(0.1), nil, WithClock(clk.now))
	if err := checkN(c); err != nil {
		t.Fatal(err)
	}
	var rl *RateLimitedError
	if err := checkN(c); !errors.As(err, &rl) || rl.RetryAfter != 10*time.Second {
		t.Fatalf("got %v", err)
	}
	// отклонённый запрос не съедает токен
	clk.add(10 * time.Second)
	if err := checkN(c); err != nil {
		t.Fatal(err)
	}
}

func TestRateUnlimited(t *testing.T) {
	c, _ := NewStatic(rlRules(0), nil)
	for range 100 {
		if err := checkN(c); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRateChangeViaRefresh(t *testing.T) {
	repo, _ := newRepo(t)
	clk := &clock{t: time.Unix(1000, 0)}
	r := mk(t, repo, store.AccessRule{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}, RPS: 1})
	c := fromStore(t, repo, nil, WithClock(clk.now))
	_ = checkN(c)
	if err := checkN(c); err == nil {
		t.Fatal("want limited")
	}
	r.RPS = 5
	if _, err := repo.Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	_ = c.Refresh(context.Background())
	clk.add(time.Second)
	for range 5 {
		if err := checkN(c); err != nil {
			t.Fatal(err)
		}
	}
	// удаление правила чистит лимитер
	_ = repo.Delete(context.Background(), r.ID)
	_ = c.Refresh(context.Background())
	c.limMu.Lock()
	n := len(c.limiters)
	c.limMu.Unlock()
	if n != 0 {
		t.Fatalf("limiters left: %d", n)
	}
}

type failRate struct{ store.RateStateRepo }

func (failRate) Incr(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("redis down")
}

func TestDistributedLimit(t *testing.T) {
	s := memtest.New()
	defer func() { _ = s.Close() }()
	clk := &clock{t: time.Unix(1000, 0)}
	c, _ := NewStatic(rlRules(2), nil, WithClock(clk.now), WithDistributedLimit(s.RateState()))
	c2, _ := NewStatic(rlRules(2), nil, WithClock(clk.now), WithDistributedLimit(s.RateState()))
	// два «инстанса» делят одно окно: burst = 2
	if checkN(c) != nil || checkN(c2) != nil {
		t.Fatal("first two must pass")
	}
	var rl *RateLimitedError
	if err := checkN(c); !errors.As(err, &rl) || rl.RetryAfter != time.Second {
		t.Fatal(err)
	}
	clk.add(time.Second) // новое окно
	if err := checkN(c2); err != nil {
		t.Fatal(err)
	}
}

func TestDistributedFallbackToLocal(t *testing.T) {
	s := memtest.New()
	defer func() { _ = s.Close() }()
	clk := &clock{t: time.Unix(1000, 0)}
	c, _ := NewStatic(rlRules(1), nil, WithClock(clk.now), WithDistributedLimit(failRate{s.RateState()}))
	if err := checkN(c); err != nil {
		t.Fatal(err)
	}
	if err := checkN(c); err == nil {
		t.Fatal("local limiter must apply on fallback")
	}
}

func TestConcurrentCheck(t *testing.T) {
	repo, _ := newRepo(t)
	mk(t, repo, store.AccessRule{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}, RPS: 100})
	tick := make(chan time.Time)
	c := fromStore(t, repo, nil, WithTickChannel(tick))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				_ = checkN(c)
			}
		})
	}
	for range 5 {
		mk(t, repo, store.AccessRule{Name: time.Now().String(), CIDRs: []netip.Prefix{pf("192.168.0.0/16")}})
		tick <- time.Now()
	}
	wg.Wait()
}
