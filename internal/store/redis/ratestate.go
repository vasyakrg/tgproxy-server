package redis

import (
	"context"
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type rateRepo struct{ e *Ephemeral }

func (r rateRepo) k(key string) string { return r.e.prefix + "rl:" + key }

func (r rateRepo) Get(ctx context.Context, key string) (store.RateWindow, error) {
	var (
		get *goredis.StringCmd
		ttl *goredis.DurationCmd
	)
	_, err := r.e.rdb.Pipelined(ctx, func(p goredis.Pipeliner) error {
		get = p.Get(ctx, r.k(key))
		ttl = p.PTTL(ctx, r.k(key))
		return nil
	})
	if errors.Is(err, goredis.Nil) || errors.Is(get.Err(), goredis.Nil) {
		return store.RateWindow{}, store.ErrNotFound
	}
	if err != nil {
		return store.RateWindow{}, err
	}
	val, err := get.Bytes()
	if err != nil {
		return store.RateWindow{}, err
	}
	return store.RateWindow{Key: key, Value: val, ExpiresAt: time.Now().Add(ttl.Val()).UTC()}, nil
}

func (r rateRepo) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 { // уже истекло; TTL=0 в Redis означал бы «бессрочно»
		return r.Delete(ctx, key)
	}
	return r.e.rdb.Set(ctx, r.k(key), value, ttl).Err()
}

func (r rateRepo) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, nil
	}
	return r.e.rdb.SetNX(ctx, r.k(key), value, ttl).Result()
}

func (r rateRepo) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	var incr *goredis.IntCmd
	_, err := r.e.rdb.TxPipelined(ctx, func(p goredis.Pipeliner) error {
		incr = p.Incr(ctx, r.k(key))
		p.Do(ctx, "pexpire", r.k(key), max(ttl.Milliseconds(), 1), "NX") // TTL только при создании окна
		return nil
	})
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (r rateRepo) Delete(ctx context.Context, key string) error {
	return r.e.rdb.Del(ctx, r.k(key)).Err()
}

// DeleteExpired — no-op: истечение обеспечивает TTL Redis.
func (r rateRepo) DeleteExpired(context.Context) (int, error) { return 0, nil }
