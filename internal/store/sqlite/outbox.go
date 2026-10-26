package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type outboxRepo struct{ s *Store }

const outboxCols = `id, dedup_key, agent_id, type, state, text, created_at, sent_at, attempts, last_error`

func scanOutbox(r scanner) (store.OutboxItem, error) {
	var (
		o     store.OutboxItem
		state string
		c     int64
		sent  sql.NullInt64
	)
	if err := r.Scan(&o.ID, &o.DedupKey, &o.AgentID, &o.Type, &state, &o.Text, &c, &sent, &o.Attempts, &o.LastError); err != nil {
		return store.OutboxItem{}, mapErr(err)
	}
	o.State = store.OutboxState(state)
	o.CreatedAt = fromMS(c)
	o.SentAt = ptrTime(sent)
	return o, nil
}

func (r outboxRepo) Enqueue(ctx context.Context, it store.OutboxItem) (store.OutboxItem, error) {
	if err := it.Validate(); err != nil {
		return store.OutboxItem{}, err
	}
	if it.CreatedAt.IsZero() {
		it.CreatedAt = time.Now()
	}
	it.CreatedAt = fromMS(ms(it.CreatedAt))
	res, err := r.s.w.ExecContext(ctx,
		`INSERT INTO outbox (dedup_key, agent_id, type, state, text, created_at) VALUES (?,?,?,?,?,?)`,
		it.DedupKey, it.AgentID, it.Type, string(it.State), it.Text, ms(it.CreatedAt))
	if err != nil {
		return store.OutboxItem{}, mapErr(err)
	}
	it.ID, err = res.LastInsertId()
	it.SentAt, it.Attempts, it.LastError = nil, 0, ""
	return it, err
}

func (r outboxRepo) Pending(ctx context.Context, limit int) ([]store.OutboxItem, error) {
	rows, err := r.s.r.QueryContext(ctx,
		`SELECT `+outboxCols+` FROM outbox WHERE sent_at IS NULL ORDER BY id LIMIT ?`, limitOr(limit, 100))
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.OutboxItem
	for rows.Next() {
		o, err := scanOutbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, mapErr(rows.Err())
}

func (r outboxRepo) CountPending(ctx context.Context) (int, error) {
	var n int
	err := r.s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL`).Scan(&n)
	return n, mapErr(err)
}

func (r outboxRepo) LastByKey(ctx context.Context, dedupKey string) (store.OutboxItem, error) {
	return scanOutbox(r.s.r.QueryRowContext(ctx,
		`SELECT `+outboxCols+` FROM outbox WHERE dedup_key = ? ORDER BY id DESC LIMIT 1`, dedupKey))
}

func (r outboxRepo) MarkSent(ctx context.Context, id int64, at time.Time) error {
	return r.s.execAffected(ctx, `UPDATE outbox SET sent_at = ?, attempts = attempts + 1, last_error = '' WHERE id = ?`, ms(at), id)
}

func (r outboxRepo) RecordAttempt(ctx context.Context, id int64, lastError string) error {
	return r.s.execAffected(ctx, `UPDATE outbox SET attempts = attempts + 1, last_error = ? WHERE id = ?`, lastError, id)
}

func (r outboxRepo) DeleteSentBefore(ctx context.Context, t time.Time) (int, error) {
	return r.s.execCount(ctx, `DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?`, ms(t))
}

func (r outboxRepo) Recent(ctx context.Context, limit int) ([]store.OutboxItem, error) {
	rows, err := r.s.r.QueryContext(ctx,
		`SELECT `+outboxCols+` FROM outbox ORDER BY id DESC LIMIT ?`, limitOr(limit, 100))
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.OutboxItem
	for rows.Next() {
		o, err := scanOutbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, mapErr(rows.Err())
}
