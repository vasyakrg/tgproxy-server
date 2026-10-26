package access

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// DefaultRefreshInterval — период проверки версии правил в БД.
const DefaultRefreshInterval = 2 * time.Second

type snapshot struct {
	rules   []rule
	version int64
}

// Option настраивает Checker.
type Option func(*Checker)

// WithRefreshInterval задаёт период фонового обновления (<=0 — по умолчанию 2s).
func WithRefreshInterval(d time.Duration) Option {
	return func(c *Checker) {
		if d > 0 {
			c.interval = d
		}
	}
}

// WithTickChannel заменяет внутренний тикер внешним каналом (для тестов).
func WithTickChannel(ch <-chan time.Time) Option {
	return func(c *Checker) { c.tick = ch }
}

// WithClock подменяет источник времени rate-limit (для тестов).
func WithClock(now func() time.Time) Option {
	return func(c *Checker) { c.now = now }
}

// WithLogger задаёт логгер фонового обновления.
func WithLogger(l *slog.Logger) Option {
	return func(c *Checker) {
		if l != nil {
			c.log = l
		}
	}
}

// Checker проверяет доступ по правилам и применяет rate-limit.
type Checker struct {
	trusted  []netip.Prefix
	snap     atomic.Pointer[snapshot]
	repo     store.AccessRuleRepo
	interval time.Duration
	tick     <-chan time.Time
	now      func() time.Time
	log      *slog.Logger

	limMu    sync.Mutex
	limiters map[string]*limiter
	dist     store.RateStateRepo

	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func newChecker(trusted []netip.Prefix, opts []Option) *Checker {
	c := &Checker{
		trusted:  trusted,
		interval: DefaultRefreshInterval,
		now:      time.Now,
		log:      slog.Default(),
		limiters: map[string]*limiter{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// NewFromStore строит Checker поверх БД: правила кэшируются в памяти и
// перечитываются, когда меняется repo.Version() (фоново раз в interval и по
// Refresh). Фон останавливается по ctx или Close.
func NewFromStore(ctx context.Context, repo store.AccessRuleRepo, trusted []netip.Prefix, opts ...Option) (*Checker, error) {
	c := newChecker(trusted, opts)
	c.repo = repo
	c.install(&snapshot{version: -1})
	if err := c.Refresh(ctx); err != nil {
		return nil, err
	}
	bg, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c.cancel = cancel
	c.done = make(chan struct{})
	go c.loop(bg, ctx)
	return c, nil
}

func (c *Checker) loop(bg context.Context, parent context.Context) {
	defer close(c.done)
	tick := c.tick
	if tick == nil {
		t := time.NewTicker(c.interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-bg.Done():
			return
		case <-parent.Done():
			return
		case <-tick:
			if err := c.Refresh(bg); err != nil {
				c.log.Warn("access: refresh rules failed", "err", err)
			}
		}
	}
}

// Close останавливает фоновое обновление.
func (c *Checker) Close() {
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
			<-c.done
		}
	})
}

// Refresh перечитывает правила, если версия в БД изменилась. Ошибка оставляет
// прежний снимок.
func (c *Checker) Refresh(ctx context.Context) error {
	if c.repo == nil {
		return nil
	}
	// версия читается до List: параллельное изменение будет подхвачено в следующий раз
	ver, err := c.repo.Version(ctx)
	if err != nil {
		return err
	}
	if ver == c.snap.Load().version {
		return nil
	}
	list, err := c.repo.List(ctx)
	if err != nil {
		return err
	}
	rs := make([]rule, 0, len(list))
	for _, r := range list {
		if !r.Enabled || r.RevokedAt != nil {
			continue
		}
		if len(r.CIDRs) == 0 && len(r.KeyHash) == 0 {
			c.log.Warn("access: skip rule without cidrs and key", "rule", r.Name)
			continue
		}
		rs = append(rs, newRule(r.ID, r.Name, r.CIDRs, r.KeyHash, r.RPS))
	}
	c.install(&snapshot{rules: rs, version: ver})
	return nil
}

// install публикует снимок и синхронизирует лимитеры.
func (c *Checker) install(s *snapshot) {
	c.snap.Store(s)
	c.syncLimiters(s.rules)
}

// SeedFromConfig переносит конфиговые правила в БД, если таблица пуста.
// Возвращает число созданных правил.
func SeedFromConfig(ctx context.Context, repo store.AccessRuleRepo, rules []config.AccessRule) (int, error) {
	existing, err := repo.List(ctx)
	if err != nil {
		return 0, err
	}
	if len(existing) > 0 {
		return 0, nil
	}
	n := 0
	for _, r := range rules {
		if _, err := repo.GetByName(ctx, r.Name); err == nil {
			continue
		}
		if _, err := repo.Create(ctx, store.AccessRule{
			Name: r.Name, CIDRs: r.CIDRs, KeyHash: r.KeyHash, RPS: r.RPS, Enabled: true,
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
