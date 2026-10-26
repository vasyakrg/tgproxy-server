package sqlite

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type agentRepo struct{ s *Store }

const agentCols = `id, name, url, mode, weight, draining, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanAgent(r scanner) (store.Agent, error) {
	var (
		a        store.Agent
		mode     string
		draining int
		c, u     int64
	)
	if err := r.Scan(&a.ID, &a.Name, &a.URL, &mode, &a.Weight, &draining, &c, &u); err != nil {
		return store.Agent{}, mapErr(err)
	}
	a.Mode = store.AgentMode(mode)
	a.Draining = draining != 0
	a.CreatedAt, a.UpdatedAt = fromMS(c), fromMS(u)
	return a, nil
}

func (r agentRepo) Create(ctx context.Context, a store.Agent) (store.Agent, error) {
	if err := a.Validate(); err != nil {
		return store.Agent{}, err
	}
	now := time.UnixMilli(ms(time.Now())).UTC()
	a.CreatedAt, a.UpdatedAt = now, now
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO agents (`+agentCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.URL, string(a.Mode), a.Weight, boolInt(a.Draining), ms(a.CreatedAt), ms(a.UpdatedAt))
	if err != nil {
		return store.Agent{}, mapErr(err)
	}
	return a, nil
}

func (r agentRepo) Get(ctx context.Context, id string) (store.Agent, error) {
	return scanAgent(r.s.r.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE id = ?`, id))
}

func (r agentRepo) List(ctx context.Context) ([]store.Agent, error) {
	rows, err := r.s.r.QueryContext(ctx, `SELECT `+agentCols+` FROM agents ORDER BY created_at, id`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, mapErr(rows.Err())
}

func (r agentRepo) Update(ctx context.Context, a store.Agent) (store.Agent, error) {
	if err := a.Validate(); err != nil {
		return store.Agent{}, err
	}
	err := r.s.execAffected(ctx,
		`UPDATE agents SET name=?, url=?, mode=?, weight=?, draining=?, updated_at=? WHERE id=?`,
		a.Name, a.URL, string(a.Mode), a.Weight, boolInt(a.Draining), ms(time.Now()), a.ID)
	if err != nil {
		return store.Agent{}, err
	}
	return r.Get(ctx, a.ID)
}

func (r agentRepo) SetWeight(ctx context.Context, id string, weight int) error {
	if weight < 0 {
		return store.ErrInvalid
	}
	return r.s.execAffected(ctx, `UPDATE agents SET weight=?, updated_at=? WHERE id=?`, weight, ms(time.Now()), id)
}

func (r agentRepo) SetDraining(ctx context.Context, id string, draining bool) error {
	return r.s.execAffected(ctx, `UPDATE agents SET draining=?, updated_at=? WHERE id=?`, boolInt(draining), ms(time.Now()), id)
}

func (r agentRepo) Delete(ctx context.Context, id string) error {
	return r.s.execAffected(ctx, `DELETE FROM agents WHERE id=?`, id)
}

func (r agentRepo) Version(ctx context.Context) (int64, error) {
	return r.s.version(ctx, "agents")
}

func (s *Store) version(ctx context.Context, name string) (int64, error) {
	var v int64
	err := s.r.QueryRowContext(ctx, `SELECT v FROM versions WHERE name = ?`, name).Scan(&v)
	return v, mapErr(err)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
