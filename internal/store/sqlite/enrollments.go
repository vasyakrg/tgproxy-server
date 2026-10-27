package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type enrollmentRepo struct{ s *Store }

const enrollCols = `id, token_hash, name, weight, created_by, created_at, expires_at, used_at, agent_id`

func scanEnroll(r scanner) (store.Enrollment, error) {
	var (
		e      store.Enrollment
		c, exp int64
		usedAt sql.NullInt64
		agent  sql.NullString
	)
	if err := r.Scan(&e.ID, &e.TokenHash, &e.Name, &e.Weight, &e.CreatedBy, &c, &exp, &usedAt, &agent); err != nil {
		return store.Enrollment{}, mapErr(err)
	}
	e.AgentID = agent.String
	e.CreatedAt, e.ExpiresAt, e.UsedAt = fromMS(c), fromMS(exp), ptrTime(usedAt)
	return e, nil
}

func (r enrollmentRepo) Create(ctx context.Context, e store.Enrollment) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO enrollments (`+enrollCols+`) VALUES (?,?,?,?,?,?,?,NULL,?)`,
		e.ID, e.TokenHash, e.Name, e.Weight, e.CreatedBy, ms(e.CreatedAt), ms(e.ExpiresAt), nullStr(e.AgentID))
	return mapErr(err)
}

func (r enrollmentRepo) Consume(ctx context.Context, tokenHash []byte, now time.Time) (store.Enrollment, error) {
	tx, err := r.s.w.BeginTx(ctx, nil)
	if err != nil {
		return store.Enrollment{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()
	e, err := scanEnroll(tx.QueryRowContext(ctx,
		`SELECT `+enrollCols+` FROM enrollments WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		tokenHash, ms(now)))
	if err != nil {
		return store.Enrollment{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollments SET used_at = ? WHERE id = ?`, ms(now), e.ID); err != nil {
		return store.Enrollment{}, mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return store.Enrollment{}, mapErr(err)
	}
	t := fromMS(ms(now))
	e.UsedAt = &t
	return e, nil
}

func (r enrollmentRepo) ListPending(ctx context.Context, now time.Time) ([]store.Enrollment, error) {
	rows, err := r.s.r.QueryContext(ctx,
		`SELECT `+enrollCols+` FROM enrollments WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at, id`, ms(now))
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.Enrollment
	for rows.Next() {
		e, err := scanEnroll(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, mapErr(rows.Err())
}

func (r enrollmentRepo) Get(ctx context.Context, id string) (store.Enrollment, error) {
	return scanEnroll(r.s.r.QueryRowContext(ctx, `SELECT `+enrollCols+` FROM enrollments WHERE id = ?`, id))
}

func (r enrollmentRepo) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	return r.s.execCount(ctx, `DELETE FROM enrollments WHERE expires_at <= ?`, ms(now))
}

func (r enrollmentRepo) Delete(ctx context.Context, id string) error {
	return r.s.execAffected(ctx, `DELETE FROM enrollments WHERE id = ? AND used_at IS NULL`, id)
}
