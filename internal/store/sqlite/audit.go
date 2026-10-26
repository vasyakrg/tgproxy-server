package sqlite

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type auditRepo struct{ s *Store }

func (r auditRepo) Append(ctx context.Context, e store.AuditEntry) (store.AuditEntry, error) {
	if e.Actor == "" || e.Action == "" {
		return store.AuditEntry{}, store.ErrInvalid
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = fromMS(ms(e.At))
	res, err := r.s.w.ExecContext(ctx,
		`INSERT INTO audit_log (at, actor, action, target, ip, detail) VALUES (?,?,?,?,?,?)`,
		ms(e.At), e.Actor, e.Action, e.Target, e.IP, e.Detail)
	if err != nil {
		return store.AuditEntry{}, mapErr(err)
	}
	e.ID, err = res.LastInsertId()
	return e, err
}

func (r auditRepo) List(ctx context.Context, q store.AuditQuery) ([]store.AuditEntry, error) {
	query := `SELECT id, at, actor, action, target, ip, detail FROM audit_log WHERE 1=1`
	var args []any
	if q.BeforeID > 0 {
		query += ` AND id < ?`
		args = append(args, q.BeforeID)
	}
	if q.Actor != "" {
		query += ` AND actor = ?`
		args = append(args, q.Actor)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limitOr(q.Limit, 100))
	rows, err := r.s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.AuditEntry
	for rows.Next() {
		var (
			e  store.AuditEntry
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.IP, &e.Detail); err != nil {
			return nil, mapErr(err)
		}
		e.At = fromMS(at)
		out = append(out, e)
	}
	return out, mapErr(rows.Err())
}
