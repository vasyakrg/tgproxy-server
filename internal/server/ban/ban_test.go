package ban

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func cfg() config.BanConfig {
	return config.BanConfig{
		Enabled: true, Threshold: 5, Window: 10 * time.Minute, Duration: time.Hour,
		Escalation: []time.Duration{24 * time.Hour, 7 * 24 * time.Hour}, ResetAfter: 30 * 24 * time.Hour, MaxTracked: 1000,
	}
}

type rig struct {
	m    *Manager
	st   *memtest.Store
	clk  *clock
	auto chan store.Ban
}

func newRig(t *testing.T, c config.BanConfig, p Protector) *rig {
	t.Helper()
	r := &rig{st: memtest.New(), clk: &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}, auto: make(chan store.Ban, 16)}
	m, err := New(context.Background(), r.st.Bans(), Options{
		Config: c, Protect: p, Now: r.clk.Now,
		OnAutoBan: func(b store.Ban, _ int) { r.auto <- b },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Wait)
	r.m = m
	return r
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func (r *rig) deny(a string, n int, reason access.Reason) {
	for range n {
		r.m.Record(ip(a), reason)
	}
}

func (r *rig) waitBan(t *testing.T) store.Ban {
	t.Helper()
	select {
	case b := <-r.auto:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("autoban did not happen")
		return store.Ban{}
	}
}

func TestPrefixOf(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":             "1.2.3.4/32",
		"::ffff:1.2.3.4":      "1.2.3.4/32",
		"2001:db8:1:2:3::9":   "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::": "2001:db8:1:2::/64",
	}
	for in, want := range cases {
		if got := PrefixOf(ip(in)).String(); got != want {
			t.Errorf("%s: %s want %s", in, got, want)
		}
	}
	if PrefixOf(netip.Addr{}).IsValid() {
		t.Fatal("invalid addr")
	}
}

func TestAutoBanThresholdAndWindow(t *testing.T) {
	r := newRig(t, cfg(), nil)
	// ниже порога — нет бана
	r.deny("203.0.113.5", 4, access.ReasonNoRule)
	if r.m.Banned(ip("203.0.113.5")) {
		t.Fatal("banned below threshold")
	}
	// не учитываются: rate_limited и banned
	r.deny("203.0.113.5", 50, access.ReasonRateLimited)
	r.deny("203.0.113.5", 50, access.ReasonBanned)
	if r.m.Banned(ip("203.0.113.5")) {
		t.Fatal("uncounted reasons must not ban")
	}
	// пятый учитываемый отказ -> бан (ключ+сеть: key_required и bad_key тоже считаются)
	r.m.Record(ip("203.0.113.5"), access.ReasonKeyRequired)
	b := r.waitBan(t)
	if b.Source != store.BanAuto || b.Level != 0 || b.ExpiresAt == nil || !b.ExpiresAt.Equal(r.clk.Now().Add(time.Hour)) {
		t.Fatalf("ban %+v", b)
	}
	if !r.m.Banned(ip("203.0.113.5")) || r.m.Banned(ip("203.0.113.6")) {
		t.Fatal("ban must affect only that ip")
	}

	// окно: отказы, растянутые дольше окна, бан не вызывают
	r.deny("198.51.100.7", 4, access.ReasonBadKey)
	r.clk.Add(11 * time.Minute)
	r.deny("198.51.100.7", 1, access.ReasonBadKey)
	if r.m.Banned(ip("198.51.100.7")) {
		t.Fatal("window not sliding")
	}
	r.deny("198.51.100.7", 3, access.ReasonBadKey) // 5 штук в пределах окна от самого раннего из пяти последних
	r.m.Record(ip("198.51.100.7"), access.ReasonBadKey)
	r.waitBan(t)
}

func TestAutoBanDisabled(t *testing.T) {
	c := cfg()
	c.Enabled = false
	r := newRig(t, c, nil)
	r.deny("203.0.113.5", 100, access.ReasonNoRule)
	r.m.Wait()
	if r.m.Banned(ip("203.0.113.5")) || r.m.Tracked() != 0 {
		t.Fatal("disabled autoban must not track")
	}
	// ручной бан при выключенном автобане работает
	if _, err := r.m.Add(context.Background(), AddRequest{Addr: ip("203.0.113.9"), Duration: time.Hour, Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if !r.m.Banned(ip("203.0.113.9")) {
		t.Fatal("manual ban ignored")
	}
}

func TestEscalationAndReset(t *testing.T) {
	r := newRig(t, cfg(), nil)
	a := "203.0.113.5"
	want := []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 7 * 24 * time.Hour}
	for i, d := range want {
		r.deny(a, 5, access.ReasonNoRule)
		b := r.waitBan(t)
		if got := b.ExpiresAt.Sub(b.CreatedAt); got != d {
			t.Fatalf("step %d: duration %s want %s (level %d)", i, got, d, b.Level)
		}
		r.clk.Add(d + time.Minute) // бан истёк
		if r.m.Banned(ip(a)) {
			t.Fatalf("step %d: still banned after expiry", i)
		}
	}
	// без нарушений 30д — уровень сбрасывается
	r.clk.Add(31 * 24 * time.Hour)
	r.deny(a, 5, access.ReasonNoRule)
	b := r.waitBan(t)
	if b.Level != 0 || b.ExpiresAt.Sub(b.CreatedAt) != time.Hour {
		t.Fatalf("level not reset: %+v", b)
	}
}

func TestExpiryLifts(t *testing.T) {
	r := newRig(t, cfg(), nil)
	r.deny("203.0.113.5", 5, access.ReasonNoRule)
	r.waitBan(t)
	r.clk.Add(30 * time.Minute)
	if !r.m.Banned(ip("203.0.113.5")) {
		t.Fatal("must still be banned")
	}
	r.clk.Add(31 * time.Minute)
	if r.m.Banned(ip("203.0.113.5")) {
		t.Fatal("must be unbanned after expiry")
	}
}

func TestProtectedNeverAutobanned(t *testing.T) {
	p := StaticProtector{
		Trusted: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/28")},
		Networks: func(context.Context) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("0.0.0.0/0")}, nil
		},
		Agents: func(context.Context) ([]store.Agent, error) {
			return []store.Agent{{ID: "a1", URL: "https://192.0.2.10:8443"}, {ID: "a2", URL: "https://agent.example:8443"}, {ID: "rev"}}, nil
		},
		Resolve: func(_ context.Context, h string) ([]netip.Addr, error) {
			if h == "agent.example" {
				return []netip.Addr{ip("192.0.2.77")}, nil
			}
			return nil, errors.New("nxdomain")
		},
	}
	r := newRig(t, cfg(), p)
	for _, a := range []string{"203.0.113.3", "198.51.100.9", "192.0.2.10", "192.0.2.77", "10.1.2.3", "127.0.0.1", "fd00::1", "::1", "169.254.1.1"} {
		r.deny(a, 40, access.ReasonNoRule)
	}
	r.m.Wait()
	select {
	case b := <-r.auto:
		t.Fatalf("protected address banned: %+v", b)
	default:
	}
	for _, a := range []string{"203.0.113.3", "198.51.100.9", "192.0.2.10", "192.0.2.77", "10.1.2.3", "127.0.0.1", "fd00::1"} {
		if r.m.Banned(ip(a)) {
			t.Fatalf("%s banned", a)
		}
		_, err := r.m.Add(context.Background(), AddRequest{Addr: ip(a), Permanent: true})
		var pe *ProtectedError
		if !errors.As(err, &pe) || pe.Reason == "" {
			t.Fatalf("%s: manual ban must be rejected, got %v", a, err)
		}
	}
	// сеть /0 в правилах не защищает всех: обычный адрес банится
	r.deny("8.8.8.8", 5, access.ReasonNoRule)
	r.waitBan(t)
}

func TestManualAddRemove(t *testing.T) {
	r := newRig(t, cfg(), nil)
	ctx := context.Background()
	for _, bad := range []AddRequest{
		{Addr: netip.Addr{}, Duration: time.Hour},
		{Addr: ip("8.8.8.8")},
		{Addr: ip("8.8.8.8"), Duration: -time.Second},
		{Addr: ip("8.8.8.8"), Duration: 2 * MaxManualDuration},
	} {
		if _, err := r.m.Add(ctx, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := r.m.Add(ctx, AddRequest{Addr: ip("8.8.8.8"), Duration: time.Hour, Comment: string(make([]rune, 300))}); !errors.Is(err, ErrComment) {
		t.Fatalf("comment: %v", err)
	}
	b, err := r.m.Add(ctx, AddRequest{Addr: ip("2001:db8:5:6:7::1"), Permanent: true, Comment: "scanner", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if b.Source != store.BanManual || b.ExpiresAt != nil || b.Prefix.String() != "2001:db8:5:6::/64" || b.Actor != "admin" {
		t.Fatalf("%+v", b)
	}
	if !r.m.Banned(ip("2001:db8:5:6:aaaa::2")) || r.m.Active() != 1 {
		t.Fatal("whole /64 must be banned")
	}
	list, _ := r.m.List(ctx)
	if len(list) != 1 || list[0].Hits != 1 {
		t.Fatalf("list %+v", list)
	}
	if _, err := r.m.Remove(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if r.m.Banned(ip("2001:db8:5:6::1")) {
		t.Fatal("unban ignored")
	}
	if _, err := r.m.Remove(ctx, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("remove twice: %v", err)
	}
}

func TestRefreshPicksExternalChangesAndFlushHits(t *testing.T) {
	r := newRig(t, cfg(), nil)
	ctx := context.Background()
	exp := r.clk.Now().Add(time.Hour)
	// «CLI» пишет напрямую в БД
	b, err := r.st.Bans().Upsert(ctx, store.Ban{Prefix: netip.MustParsePrefix("8.8.4.4/32"), Source: store.BanManual, Actor: "cli", CreatedAt: r.clk.Now(), ExpiresAt: &exp})
	if err != nil {
		t.Fatal(err)
	}
	if r.m.Banned(ip("8.8.4.4")) {
		t.Fatal("not refreshed yet")
	}
	if err := r.m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if !r.m.Banned(ip("8.8.4.4")) {
			t.Fatal("ban not applied after refresh")
		}
	}
	r.m.Flush(ctx)
	got, _ := r.st.Bans().Get(ctx, b.ID)
	if got.Hits != 3 {
		t.Fatalf("hits %d", got.Hits)
	}
	// снятие снаружи
	_ = r.st.Bans().Delete(ctx, b.ID)
	_ = r.m.Refresh(ctx)
	if r.m.Banned(ip("8.8.4.4")) {
		t.Fatal("external delete ignored")
	}
}

func TestTrackerBounded(t *testing.T) {
	c := cfg()
	c.MaxTracked = 100
	r := newRig(t, c, nil)
	for i := range 1000 {
		r.m.Record(netip.AddrFrom4([4]byte{45, 1, byte(i / 256), byte(i)}), access.ReasonNoRule)
	}
	if n := r.m.Tracked(); n != 100 {
		t.Fatalf("tracked %d, want capped at 100", n)
	}
}

func TestDigest(t *testing.T) {
	var got [][]store.Ban
	d := NewDigest(func(_ context.Context, b []store.Ban) { got = append(got, b) })
	d.Flush(context.Background())
	if len(got) != 0 {
		t.Fatal("empty batch must not flush")
	}
	d.Add(store.Ban{ID: 1})
	d.Add(store.Ban{ID: 2})
	d.Flush(context.Background())
	d.Flush(context.Background())
	if len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestMTProtoReplayAutobans(t *testing.T) {
	r := newRig(t, cfg(), nil)
	r.deny("198.51.100.20", 5, access.ReasonMTProtoReplay)
	b := r.waitBan(t)
	if b.Prefix != PrefixOf(ip("198.51.100.20")) || !r.m.Banned(ip("198.51.100.20")) {
		t.Fatalf("ban: %+v", b)
	}
}

func TestMTProtoConnLimitBadSecretNotCounted(t *testing.T) {
	r := newRig(t, cfg(), nil)
	r.deny("198.51.100.21", 50, access.ReasonMTProtoConnLimit)
	r.deny("198.51.100.21", 50, access.ReasonMTProtoBadSecret)
	r.m.Wait()
	select {
	case b := <-r.auto:
		t.Fatalf("unexpected ban: %+v", b)
	default:
	}
	if r.m.Banned(ip("198.51.100.21")) {
		t.Fatal("banned")
	}
}

func TestMTProtoReplayProtectedNotBanned(t *testing.T) {
	r := newRig(t, cfg(), StaticProtector{Trusted: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/28")}})
	for _, a := range []string{"203.0.113.3", "10.1.2.3", "127.0.0.1"} {
		r.deny(a, 40, access.ReasonMTProtoReplay)
	}
	r.m.Wait()
	select {
	case b := <-r.auto:
		t.Fatalf("protected banned: %+v", b)
	default:
	}
}
