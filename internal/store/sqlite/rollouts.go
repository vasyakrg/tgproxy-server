package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type rolloutRepo struct{ s *Store }

const rolloutCols = `id, version, batch_size, canary, allow_downtime, state, error, actor, created_at, finished_at`

func scanRollout(r scanner) (store.Rollout, error) {
	var (
		o   store.Rollout
		dt  int
		c   int64
		fin sql.NullInt64
	)
	if err := r.Scan(&o.ID, &o.Version, &o.BatchSize, &o.Canary, &dt, &o.State, &o.Error, &o.Actor, &c, &fin); err != nil {
		return store.Rollout{}, mapErr(err)
	}
	o.AllowDowntime = dt != 0
	o.CreatedAt, o.FinishedAt = fromMS(c), ptrTime(fin)
	return o, nil
}

func (r rolloutRepo) Create(ctx context.Context, o store.Rollout, steps []store.RolloutStep) (err error) {
	if err = o.Validate(); err != nil {
		return err
	}
	for _, st := range steps {
		if err = st.Validate(); err != nil {
			return err
		}
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now()
	}
	tx, err := r.s.w.BeginTx(ctx, nil) // BEGIN IMMEDIATE (_txlock=immediate): проверка «активна ли другая» без гонки
	if err != nil {
		return mapErr(err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if o.Active() {
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM rollouts WHERE state IN (?,?)`,
			store.RolloutRunning, store.RolloutStopping).Scan(&n); err != nil {
			return mapErr(err)
		}
		if n > 0 {
			return store.ErrConflict
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO rollouts (`+rolloutCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		o.ID, o.Version, o.BatchSize, o.Canary, boolInt(o.AllowDowntime), o.State, o.Error, o.Actor,
		ms(o.CreatedAt), nullMS(o.FinishedAt)); err != nil {
		return mapErr(err)
	}
	now := ms(time.Now())
	for _, st := range steps {
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO rollout_steps (rollout_id, agent_id, seq, phase, state, from_version, error, updated_at) VALUES (?,?,?,?,?,?,?,?)`,
			o.ID, st.AgentID, st.Seq, st.Phase, st.State, st.FromVersion, st.Error, now); err != nil {
			return mapErr(err)
		}
	}
	return mapErr(tx.Commit())
}

func (r rolloutRepo) one(ctx context.Context, where string, args ...any) (store.Rollout, error) {
	return scanRollout(r.s.r.QueryRowContext(ctx, `SELECT `+rolloutCols+` FROM rollouts `+where, args...))
}

func (r rolloutRepo) Get(ctx context.Context, id string) (store.Rollout, error) {
	return r.one(ctx, `WHERE id = ?`, id)
}

func (r rolloutRepo) Active(ctx context.Context) (store.Rollout, error) {
	return r.one(ctx, `WHERE state IN (?,?) ORDER BY created_at DESC LIMIT 1`, store.RolloutRunning, store.RolloutStopping)
}

func (r rolloutRepo) Latest(ctx context.Context) (store.Rollout, error) {
	return r.one(ctx, `ORDER BY created_at DESC, rowid DESC LIMIT 1`)
}

func (r rolloutRepo) SetState(ctx context.Context, id, state, errMsg string) error {
	if state == "" {
		return store.ErrInvalid
	}
	var fin any
	if state != store.RolloutRunning && state != store.RolloutStopping {
		fin = ms(time.Now())
	}
	return r.s.execAffected(ctx, `UPDATE rollouts SET state = ?, error = ?, finished_at = ? WHERE id = ?`, state, errMsg, fin, id)
}

func (r rolloutRepo) Steps(ctx context.Context, id string) ([]store.RolloutStep, error) {
	rows, err := r.s.r.QueryContext(ctx,
		`SELECT agent_id, seq, phase, state, from_version, error, updated_at FROM rollout_steps WHERE rollout_id = ? ORDER BY seq`, id)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.RolloutStep
	for rows.Next() {
		st := store.RolloutStep{RolloutID: id}
		var u int64
		if err := rows.Scan(&st.AgentID, &st.Seq, &st.Phase, &st.State, &st.FromVersion, &st.Error, &u); err != nil {
			return nil, mapErr(err)
		}
		st.UpdatedAt = fromMS(u)
		out = append(out, st)
	}
	return out, mapErr(rows.Err())
}

func (r rolloutRepo) SetStep(ctx context.Context, id, agentID, state, fromVersion, errMsg string) error {
	if state == "" {
		return store.ErrInvalid
	}
	return r.s.execAffected(ctx,
		`UPDATE rollout_steps SET state = ?, from_version = CASE WHEN ? <> '' THEN ? ELSE from_version END, error = ?, updated_at = ?
		 WHERE rollout_id = ? AND agent_id = ?`,
		state, fromVersion, fromVersion, errMsg, ms(time.Now()), id, agentID)
}
