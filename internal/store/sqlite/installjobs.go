package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type installJobRepo struct{ s *Store }

func (r installJobRepo) Create(ctx context.Context, j store.InstallJob) error {
	if err := j.Validate(); err != nil {
		return err
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now()
	}
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO install_jobs (id, agent_id, host, kind, state, error, created_at, finished_at) VALUES (?,?,?,?,?,?,?,?)`,
		j.ID, j.AgentID, j.Host, j.Kind, j.State, j.Error, ms(j.CreatedAt), nullMS(j.FinishedAt))
	return mapErr(err)
}

func (r installJobRepo) Get(ctx context.Context, id string) (store.InstallJob, error) {
	j := store.InstallJob{ID: id}
	var (
		c   int64
		fin sql.NullInt64
	)
	err := r.s.r.QueryRowContext(ctx,
		`SELECT agent_id, host, kind, state, error, created_at, finished_at FROM install_jobs WHERE id = ?`, id).
		Scan(&j.AgentID, &j.Host, &j.Kind, &j.State, &j.Error, &c, &fin)
	if err != nil {
		return store.InstallJob{}, mapErr(err)
	}
	j.CreatedAt, j.FinishedAt = fromMS(c), ptrTime(fin)
	return j, nil
}

func (r installJobRepo) SetState(ctx context.Context, id, state, errMsg string) error {
	if state == "" {
		return store.ErrInvalid
	}
	var fin any
	if state != store.InstallRunning {
		fin = ms(time.Now())
	}
	return r.s.execAffected(ctx,
		`UPDATE install_jobs SET state = ?, error = ?, finished_at = ? WHERE id = ?`, state, errMsg, fin, id)
}

func (r installJobRepo) SetAgent(ctx context.Context, id, agentID string) error {
	return r.s.execAffected(ctx, `UPDATE install_jobs SET agent_id = ? WHERE id = ?`, agentID, id)
}

func (r installJobRepo) AppendEvent(ctx context.Context, e store.InstallJobEvent) (store.InstallJobEvent, error) {
	if err := e.Validate(); err != nil {
		return store.InstallJobEvent{}, err
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = fromMS(ms(e.At))
	if e.Level == "" {
		e.Level = "info"
	}
	res, err := r.s.w.ExecContext(ctx,
		`INSERT INTO install_job_events (job_id, at, kind, step, level, message) VALUES (?,?,?,?,?,?)`,
		e.JobID, ms(e.At), e.Kind, e.Step, e.Level, e.Message)
	if err != nil {
		return store.InstallJobEvent{}, mapErr(err)
	}
	e.ID, err = res.LastInsertId()
	return e, err
}

func (r installJobRepo) Events(ctx context.Context, jobID string, afterID int64) ([]store.InstallJobEvent, error) {
	rows, err := r.s.r.QueryContext(ctx,
		`SELECT id, at, kind, step, level, message FROM install_job_events WHERE job_id = ? AND id > ? ORDER BY id`, jobID, afterID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.InstallJobEvent
	for rows.Next() {
		e := store.InstallJobEvent{JobID: jobID}
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Kind, &e.Step, &e.Level, &e.Message); err != nil {
			return nil, mapErr(err)
		}
		e.At = fromMS(at)
		out = append(out, e)
	}
	return out, mapErr(rows.Err())
}
