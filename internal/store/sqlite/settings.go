package sqlite

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type settingsRepo struct{ s *Store }

func (r settingsRepo) Get(ctx context.Context, key string) (string, error) {
	var v string
	err := r.s.r.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err != nil {
		return "", mapErr(err)
	}
	return v, nil
}

func (r settingsRepo) Set(ctx context.Context, key, value string) error {
	if key == "" {
		return store.ErrInvalid
	}
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO settings (key, value, updated_at) VALUES (?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, ms(time.Now()))
	return mapErr(err)
}

func (r settingsRepo) List(ctx context.Context) (map[string]string, error) {
	rows, err := r.s.r.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, mapErr(err)
		}
		out[k] = v
	}
	return out, mapErr(rows.Err())
}
