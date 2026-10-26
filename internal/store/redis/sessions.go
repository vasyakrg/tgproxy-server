package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type sessionRepo struct{ e *Ephemeral }

type sessionDoc struct {
	ID         string `json:"id"`
	User       string `json:"user"`
	Kind       string `json:"kind"`
	IP         string `json:"ip"`
	CreatedAt  int64  `json:"created_at"`
	LastSeenAt int64  `json:"last_seen_at"`
	IdleUntil  int64  `json:"idle_until"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (r sessionRepo) key(id string) string    { return r.e.prefix + "sess:" + id }
func (r sessionRepo) userKey(u string) string { return r.e.prefix + "sessu:" + u }
func toDoc(s store.Session) sessionDoc {
	return sessionDoc{s.ID, s.User, s.Kind, s.IP, s.CreatedAt.UnixMilli(), s.LastSeenAt.UnixMilli(), s.IdleExpiresAt.UnixMilli(), s.ExpiresAt.UnixMilli()}
}

func (d sessionDoc) session() store.Session {
	return store.Session{
		ID: d.ID, User: d.User, Kind: d.Kind, IP: d.IP,
		CreatedAt: time.UnixMilli(d.CreatedAt).UTC(), LastSeenAt: time.UnixMilli(d.LastSeenAt).UTC(),
		IdleExpiresAt: time.UnixMilli(d.IdleUntil).UTC(), ExpiresAt: time.UnixMilli(d.ExpiresAt).UTC(),
	}
}

// ttl — время жизни ключа: ближайший из idle- и абсолютного дедлайнов.
func (d sessionDoc) ttl(now time.Time) time.Duration {
	until := min(d.IdleUntil, d.ExpiresAt)
	return time.UnixMilli(until).Sub(now)
}

func (r sessionRepo) Create(ctx context.Context, s store.Session) error {
	if err := s.Validate(); err != nil {
		return err
	}
	now := time.Now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	if s.LastSeenAt.IsZero() {
		s.LastSeenAt = s.CreatedAt
	}
	doc := toDoc(s)
	ttl := doc.ttl(now)
	if ttl <= 0 {
		return nil // уже истекла: не сохраняем, Get вернёт ErrNotFound
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	created, err := r.e.rdb.SetNX(ctx, r.key(s.ID), b, ttl).Result()
	if err != nil {
		return err
	}
	if !created {
		return store.ErrConflict
	}
	// индекс для DeleteByUser; живёт не дольше абсолютного дедлайна самой долгой сессии
	uk := r.userKey(s.User)
	ms := time.UnixMilli(doc.ExpiresAt).Sub(now).Milliseconds()
	_, err = r.e.rdb.TxPipelined(ctx, func(p goredis.Pipeliner) error {
		p.SAdd(ctx, uk, s.ID)
		p.Do(ctx, "pexpire", uk, ms, "GT") // продлевать, никогда не сокращать
		p.Do(ctx, "pexpire", uk, ms, "NX") // GT не срабатывает на ключе без TTL
		return nil
	})
	return err
}

func (r sessionRepo) load(ctx context.Context, id string) (sessionDoc, error) {
	b, err := r.e.rdb.Get(ctx, r.key(id)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return sessionDoc{}, store.ErrNotFound
	}
	if err != nil {
		return sessionDoc{}, err
	}
	var d sessionDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return sessionDoc{}, err
	}
	if d.ttl(time.Now()) <= 0 {
		return sessionDoc{}, store.ErrNotFound
	}
	return d, nil
}

func (r sessionRepo) Get(ctx context.Context, id string) (store.Session, error) {
	d, err := r.load(ctx, id)
	if err != nil {
		return store.Session{}, err
	}
	return d.session(), nil
}

func (r sessionRepo) Touch(ctx context.Context, id string, idleExpiresAt time.Time) error {
	d, err := r.load(ctx, id)
	if err != nil {
		return err
	}
	now := time.Now()
	d.LastSeenAt = now.UnixMilli()
	d.IdleUntil = min(idleExpiresAt.UnixMilli(), d.ExpiresAt)
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	// XX: если сессию удалили между GET и SET, она не воскресает.
	updated, err := r.e.rdb.SetXX(ctx, r.key(id), b, d.ttl(now)).Result()
	if err != nil {
		return err
	}
	if !updated {
		return store.ErrNotFound
	}
	return nil
}

func (r sessionRepo) Delete(ctx context.Context, id string) error {
	return r.e.rdb.Del(ctx, r.key(id)).Err()
}

func (r sessionRepo) DeleteByUser(ctx context.Context, user string) (int, error) {
	uk := r.userKey(user)
	ids, err := r.e.rdb.SMembers(ctx, uk).Result()
	if err != nil {
		return 0, err
	}
	total := 0
	for _, id := range ids {
		n, err := r.e.rdb.Del(ctx, r.key(id)).Result()
		if err != nil {
			return total, err
		}
		total += int(n)
	}
	return total, r.e.rdb.Del(ctx, uk).Err()
}

// DeleteExpired — no-op: истечение обеспечивает TTL Redis.
func (r sessionRepo) DeleteExpired(context.Context) (int, error) { return 0, nil }
