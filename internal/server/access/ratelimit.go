package access

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"

	"golang.org/x/time/rate"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// RateLimitedError — превышен rps правила. RetryAfter >= 1s, целое число секунд.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("access: rate limited, retry after %s", e.RetryAfter)
}

type limiter struct {
	rps float64
	lim *rate.Limiter
}

func burstFor(rps float64) int { return max(1, int(math.Ceil(rps))) }

// WithDistributedLimit включает общий лимит через RateStateRepo.Incr (окно 1s,
// лимит burst запросов на окно) — для нескольких инстансов с Redis. При ошибке
// хранилища используется локальный лимитер (fail-open по доступности).
func WithDistributedLimit(repo store.RateStateRepo) Option {
	return func(c *Checker) { c.dist = repo }
}

func (c *Checker) limit(ctx context.Context, ru *rule) error {
	rps := ru.info.RPS
	if rps <= 0 {
		return nil
	}
	if c.dist != nil {
		key := "rl:" + ru.limKey + ":" + strconv.FormatInt(c.now().Unix(), 10)
		n, err := c.dist.Incr(ctx, key, 2*time.Second)
		if err == nil {
			if n > int64(burstFor(rps)) {
				return &RateLimitedError{RetryAfter: time.Second}
			}
			return nil
		}
		c.log.Warn("access: distributed limiter failed, using local", "err", err)
	}
	return c.localLimit(ru)
}

func (c *Checker) localLimit(ru *rule) error {
	rps := ru.info.RPS
	c.limMu.Lock()
	defer c.limMu.Unlock()
	l := c.limiters[ru.limKey]
	if l == nil {
		l = &limiter{rps: rps, lim: rate.NewLimiter(rate.Limit(rps), burstFor(rps))}
		c.limiters[ru.limKey] = l
	}
	now := c.now()
	res := l.lim.ReserveN(now, 1)
	d := res.DelayFrom(now)
	if d <= 0 {
		return nil
	}
	res.CancelAt(now)
	secs := time.Duration(math.Ceil(d.Seconds())) * time.Second
	return &RateLimitedError{RetryAfter: max(secs, time.Second)}
}

// syncLimiters вызывается при смене снимка: удаляет лимитеры исчезнувших
// правил и применяет новый rps к существующим (накопленные токены сохраняются).
func (c *Checker) syncLimiters(rules []rule) {
	byKey := make(map[string]float64, len(rules))
	for i := range rules {
		byKey[rules[i].limKey] = rules[i].info.RPS
	}
	now := c.now()
	c.limMu.Lock()
	defer c.limMu.Unlock()
	for k, l := range c.limiters {
		rps, ok := byKey[k]
		switch {
		case !ok || rps <= 0:
			delete(c.limiters, k)
		case l.rps != rps:
			l.rps = rps
			l.lim.SetLimitAt(now, rate.Limit(rps))
			l.lim.SetBurstAt(now, burstFor(rps))
		}
	}
}
