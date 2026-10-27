package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type historyRepo struct{ s *Store }

func table(res store.Resolution) (string, error) {
	switch res {
	case store.Res10s:
		return "samples_10s", nil
	case store.Res5m:
		return "samples_5m", nil
	}
	return "", fmt.Errorf("%w: resolution %q", store.ErrInvalid, res)
}

func (r historyRepo) Append(ctx context.Context, res store.Resolution, samples []store.Sample) error {
	t, err := table(res)
	if err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	tx, err := r.s.w.BeginTx(ctx, nil)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()
	upsert := `INSERT INTO ` + t + // #nosec G202 -- t — из белого списка table()
		` (agent_id, ts, ok, err, rate_limited, p95_ms, inflight, buckets, denied,
		   mtproto_conns, mtproto_bytes_in, mtproto_bytes_out) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(agent_id, ts) DO UPDATE SET ok=excluded.ok, err=excluded.err, rate_limited=excluded.rate_limited,
		   p95_ms=excluded.p95_ms, inflight=excluded.inflight, buckets=excluded.buckets, denied=excluded.denied,
		   mtproto_conns=excluded.mtproto_conns, mtproto_bytes_in=excluded.mtproto_bytes_in,
		   mtproto_bytes_out=excluded.mtproto_bytes_out`
	stmt, err := tx.PrepareContext(ctx, upsert)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = stmt.Close() }()
	for _, sm := range samples {
		b, err := json.Marshal(append([]int64{}, sm.Buckets...))
		if err != nil {
			return err
		}
		den := ""
		if len(sm.Denied) > 0 {
			db, err := json.Marshal(sm.Denied)
			if err != nil {
				return err
			}
			den = string(db)
		}
		if _, err := stmt.ExecContext(ctx, sm.AgentID, ms(sm.At), sm.OK, sm.Err, sm.RateLimited, sm.P95Ms, sm.Inflight, string(b), den,
			sm.MTConns, sm.MTBytesIn, sm.MTBytesOut); err != nil {
			return mapErr(err)
		}
	}
	return mapErr(tx.Commit())
}

func (r historyRepo) Range(ctx context.Context, res store.Resolution, agentID string, from, to time.Time) ([]store.Sample, error) {
	t, err := table(res)
	if err != nil {
		return nil, err
	}
	q := `SELECT agent_id, ts, ok, err, rate_limited, p95_ms, inflight, buckets, denied,
		mtproto_conns, mtproto_bytes_in, mtproto_bytes_out FROM ` + t + ` WHERE ts >= ? AND ts < ?` // #nosec G202 -- t — из белого списка table()
	args := []any{ms(from), ms(to)}
	if agentID != "" {
		q += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	q += ` ORDER BY ts, agent_id`
	rows, err := r.s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.Sample
	for rows.Next() {
		var (
			sm store.Sample
			ts int64
			b  string
			dn string
		)
		if err := rows.Scan(&sm.AgentID, &ts, &sm.OK, &sm.Err, &sm.RateLimited, &sm.P95Ms, &sm.Inflight, &b, &dn,
			&sm.MTConns, &sm.MTBytesIn, &sm.MTBytesOut); err != nil {
			return nil, mapErr(err)
		}
		sm.At = fromMS(ts)
		if err := json.Unmarshal([]byte(b), &sm.Buckets); err != nil {
			return nil, fmt.Errorf("sqlite: decode buckets: %w", err)
		}
		if len(sm.Buckets) == 0 {
			sm.Buckets = nil
		}
		if dn != "" {
			if err := json.Unmarshal([]byte(dn), &sm.Denied); err != nil {
				return nil, fmt.Errorf("sqlite: decode denied: %w", err)
			}
		}
		out = append(out, sm)
	}
	return out, mapErr(rows.Err())
}

func (r historyRepo) Prune(ctx context.Context, res store.Resolution, before time.Time) (int64, error) {
	t, err := table(res)
	if err != nil {
		return 0, err
	}
	n, err := r.s.execCount(ctx, `DELETE FROM `+t+` WHERE ts < ?`, ms(before))
	return int64(n), err
}
