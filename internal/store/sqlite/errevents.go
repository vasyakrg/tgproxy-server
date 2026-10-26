package sqlite

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type errorRepo struct{ s *Store }

func (r errorRepo) Append(ctx context.Context, e store.ErrorEvent) (store.ErrorEvent, error) {
	if err := e.Validate(); err != nil {
		return store.ErrorEvent{}, err
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = fromMS(ms(e.At))
	res, err := r.s.w.ExecContext(ctx,
		`INSERT INTO error_events (at, request_id, bot_id, agent_id, method, phase, code, outcome, description)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		ms(e.At), e.RequestID, e.BotID, e.AgentID, e.Method, e.Phase, e.Code, string(e.Outcome), e.Description)
	if err != nil {
		return store.ErrorEvent{}, mapErr(err)
	}
	e.ID, err = res.LastInsertId()
	return e, err
}

func (r errorRepo) List(ctx context.Context, q store.ErrorQuery) ([]store.ErrorEvent, error) {
	query := `SELECT id, at, request_id, bot_id, agent_id, method, phase, code, outcome, description FROM error_events WHERE 1=1`
	var args []any
	add := func(cond string, v any) {
		query += ` AND ` + cond // #nosec G202 -- cond — только константные фрагменты из этой функции
		args = append(args, v)
	}
	if q.BeforeID > 0 {
		add("id < ?", q.BeforeID)
	}
	if q.AgentID != "" {
		add("agent_id = ?", q.AgentID)
	}
	if q.BotID != "" {
		add("bot_id = ?", q.BotID)
	}
	if q.Method != "" {
		add("method = ?", q.Method)
	}
	if q.Outcome != "" {
		add("outcome = ?", string(q.Outcome))
	}
	if q.Phase != "" {
		add("phase = ?", q.Phase)
	}
	if q.Code != 0 {
		add("code = ?", q.Code)
	}
	if q.RequestID != "" {
		add("request_id = ?", q.RequestID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limitOr(q.Limit, 100))
	rows, err := r.s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.ErrorEvent
	for rows.Next() {
		var (
			e       store.ErrorEvent
			at      int64
			outcome string
		)
		if err := rows.Scan(&e.ID, &at, &e.RequestID, &e.BotID, &e.AgentID, &e.Method, &e.Phase, &e.Code, &outcome, &e.Description); err != nil {
			return nil, mapErr(err)
		}
		e.At, e.Outcome = fromMS(at), store.ErrorOutcome(outcome)
		out = append(out, e)
	}
	return out, mapErr(rows.Err())
}

func (r errorRepo) Trim(ctx context.Context, keep int, before time.Time) (int64, error) {
	var total int64
	if keep > 0 {
		n, err := r.s.execCount(ctx,
			`DELETE FROM error_events WHERE id <= (SELECT id FROM error_events ORDER BY id DESC LIMIT 1 OFFSET ?)`, keep)
		if err != nil {
			return 0, err
		}
		total += int64(n)
	}
	if !before.IsZero() {
		n, err := r.s.execCount(ctx, `DELETE FROM error_events WHERE at < ?`, ms(before))
		if err != nil {
			return 0, err
		}
		total += int64(n)
	}
	return total, nil
}
