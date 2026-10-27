package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type banRepo struct{ s *Store }

const banCols = `id, prefix, source, actor, comment, created_at, expires_at, hits, level, last_hit_at`

func scanBan(r scanner) (store.Ban, error) {
	var (
		b       store.Ban
		prefix  string
		source  string
		created int64
		expires sql.NullInt64
		lastHit int64
	)
	if err := r.Scan(&b.ID, &prefix, &source, &b.Actor, &b.Comment, &created, &expires, &b.Hits, &b.Level, &lastHit); err != nil {
		return store.Ban{}, mapErr(err)
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return store.Ban{}, fmt.Errorf("sqlite: decode ban prefix %q: %w", prefix, err)
	}
	b.Prefix, b.Source = p, store.BanSource(source)
	b.CreatedAt, b.ExpiresAt, b.LastHitAt = fromMS(created), ptrTime(expires), fromMS(lastHit)
	return b, nil
}

func (r banRepo) Upsert(ctx context.Context, b store.Ban) (store.Ban, error) {
	if err := b.Validate(); err != nil {
		return store.Ban{}, err
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	b.CreatedAt = fromMS(ms(b.CreatedAt))
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO bans (prefix, source, actor, comment, created_at, expires_at, hits, level, last_hit_at)
		 VALUES (?,?,?,?,?,?,0,?,?)
		 ON CONFLICT(prefix) DO UPDATE SET source=excluded.source, actor=excluded.actor, comment=excluded.comment,
		   created_at=excluded.created_at, expires_at=excluded.expires_at, hits=0, level=excluded.level,
		   last_hit_at=excluded.last_hit_at`,
		b.Prefix.String(), string(b.Source), b.Actor, b.Comment, ms(b.CreatedAt), nullMS(b.ExpiresAt), b.Level, ms(b.CreatedAt))
	if err != nil {
		return store.Ban{}, mapErr(err)
	}
	return r.GetByPrefix(ctx, b.Prefix)
}

func (r banRepo) Get(ctx context.Context, id int64) (store.Ban, error) {
	return scanBan(r.s.r.QueryRowContext(ctx, `SELECT `+banCols+` FROM bans WHERE id = ?`, id))
}

func (r banRepo) GetByPrefix(ctx context.Context, p netip.Prefix) (store.Ban, error) {
	// читаем с writer: только что записанное должно быть видно сразу
	return scanBan(r.s.w.QueryRowContext(ctx, `SELECT `+banCols+` FROM bans WHERE prefix = ?`, p.String()))
}

func (r banRepo) ListActive(ctx context.Context, now time.Time) ([]store.Ban, error) {
	rows, err := r.s.r.QueryContext(ctx,
		`SELECT `+banCols+` FROM bans WHERE expires_at IS NULL OR expires_at > ? ORDER BY id DESC`, ms(now))
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.Ban
	for rows.Next() {
		b, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, mapErr(rows.Err())
}

func (r banRepo) Delete(ctx context.Context, id int64) error {
	return r.s.execAffected(ctx, `DELETE FROM bans WHERE id = ?`, id)
}

func (r banRepo) AddHits(ctx context.Context, id, n int64, at time.Time) error {
	if n <= 0 {
		return nil
	}
	_, err := r.s.w.ExecContext(ctx,
		`UPDATE bans SET hits = hits + ?, last_hit_at = MAX(last_hit_at, ?) WHERE id = ?`, n, ms(at), id)
	return mapErr(err)
}

func (r banRepo) Prune(ctx context.Context, before time.Time) (int, error) {
	return r.s.execCount(ctx,
		`DELETE FROM bans WHERE expires_at IS NOT NULL AND expires_at < ? AND last_hit_at < ?`, ms(before), ms(before))
}

func (r banRepo) Version(ctx context.Context) (int64, error) {
	return r.s.version(ctx, "bans")
}
