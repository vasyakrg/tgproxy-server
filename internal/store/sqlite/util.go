package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func nullMS(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ms(*t)
}

func ptrTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

// execAffected выполняет запись на writer и возвращает ErrNotFound, если строк не затронуто.
func (s *Store) execAffected(ctx context.Context, q string, args ...any) error {
	res, err := s.w.ExecContext(ctx, q, args...)
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func limitOr(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

// execCount выполняет запись на writer и возвращает число затронутых строк.
func (s *Store) execCount(ctx context.Context, q string, args ...any) (int, error) {
	res, err := s.w.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
