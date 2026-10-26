package sqlite

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type sessionRepo struct{ s *Store }

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
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO sessions (id, user, kind, ip, created_at, last_seen_at, idle_expires_at, expires_at)
		 VALUES (?,?,?,?,?,?,?,?)`,
		s.ID, s.User, s.Kind, s.IP, ms(s.CreatedAt), ms(s.LastSeenAt), ms(s.IdleExpiresAt), ms(s.ExpiresAt))
	return mapErr(err)
}

func (r sessionRepo) Get(ctx context.Context, id string) (store.Session, error) {
	var (
		s                store.Session
		c, l, idle, expr int64
	)
	now := ms(time.Now())
	err := r.s.r.QueryRowContext(ctx,
		`SELECT id, user, kind, ip, created_at, last_seen_at, idle_expires_at, expires_at
		 FROM sessions WHERE id = ? AND idle_expires_at > ? AND expires_at > ?`, id, now, now).
		Scan(&s.ID, &s.User, &s.Kind, &s.IP, &c, &l, &idle, &expr)
	if err != nil {
		return store.Session{}, mapErr(err)
	}
	s.CreatedAt, s.LastSeenAt, s.IdleExpiresAt, s.ExpiresAt = fromMS(c), fromMS(l), fromMS(idle), fromMS(expr)
	return s, nil
}

func (r sessionRepo) Touch(ctx context.Context, id string, idleExpiresAt time.Time) error {
	now := ms(time.Now())
	return r.s.execAffected(ctx,
		`UPDATE sessions SET last_seen_at = ?, idle_expires_at = MIN(?, expires_at)
		 WHERE id = ? AND idle_expires_at > ? AND expires_at > ?`,
		now, ms(idleExpiresAt), id, now, now)
}

func (r sessionRepo) Delete(ctx context.Context, id string) error {
	_, err := r.s.w.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return mapErr(err)
}

func (r sessionRepo) DeleteByUser(ctx context.Context, user string) (int, error) {
	return r.s.execCount(ctx, `DELETE FROM sessions WHERE user = ?`, user)
}

func (r sessionRepo) DeleteExpired(ctx context.Context) (int, error) {
	now := ms(time.Now())
	return r.s.execCount(ctx, `DELETE FROM sessions WHERE idle_expires_at <= ? OR expires_at <= ?`, now, now)
}
