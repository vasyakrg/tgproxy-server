package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type rateStateRepo struct{ s *Store }

func (r rateStateRepo) Get(ctx context.Context, key string) (store.RateWindow, error) {
	w := store.RateWindow{Key: key}
	var exp int64
	err := r.s.r.QueryRowContext(ctx,
		`SELECT value, expires_at FROM rate_windows WHERE key = ? AND expires_at > ?`, key, ms(time.Now())).
		Scan(&w.Value, &exp)
	if err != nil {
		return store.RateWindow{}, mapErr(err)
	}
	w.ExpiresAt = fromMS(exp)
	return w, nil
}

func (r rateStateRepo) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if value == nil {
		value = []byte{}
	}
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO rate_windows (key, value, expires_at) VALUES (?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`,
		key, value, ms(time.Now().Add(ttl)))
	return mapErr(err)
}

func (r rateStateRepo) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if value == nil {
		value = []byte{}
	}
	now := time.Now()
	res, err := r.s.w.ExecContext(ctx,
		`INSERT INTO rate_windows (key, value, expires_at) VALUES (?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at
		 WHERE rate_windows.expires_at <= ?`,
		key, value, ms(now.Add(ttl)), ms(now))
	if err != nil {
		return false, mapErr(err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (r rateStateRepo) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	tx, err := r.s.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	var (
		val []byte
		exp int64
	)
	err = tx.QueryRowContext(ctx, `SELECT value, expires_at FROM rate_windows WHERE key = ?`, key).Scan(&val, &exp)
	var n int64
	switch {
	case errors.Is(err, sql.ErrNoRows) || (err == nil && exp <= ms(now)):
		n = 1
		exp = ms(now.Add(ttl))
	case err != nil:
		return 0, mapErr(err)
	default:
		cur, perr := strconv.ParseInt(string(val), 10, 64)
		if perr != nil {
			cur = 0
		}
		n = cur + 1
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO rate_windows (key, value, expires_at) VALUES (?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`,
		key, []byte(strconv.FormatInt(n, 10)), exp); err != nil {
		return 0, mapErr(err)
	}
	return n, mapErr(tx.Commit())
}

func (r rateStateRepo) Delete(ctx context.Context, key string) error {
	_, err := r.s.w.ExecContext(ctx, `DELETE FROM rate_windows WHERE key = ?`, key)
	return mapErr(err)
}

func (r rateStateRepo) DeleteExpired(ctx context.Context) (int, error) {
	return r.s.execCount(ctx, `DELETE FROM rate_windows WHERE expires_at <= ?`, ms(time.Now()))
}
