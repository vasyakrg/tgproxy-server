package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type accessRuleRepo struct{ s *Store }

const ruleCols = `id, name, cidrs, key_hash, key_prefix, rps, enabled, created_at, revoked_at`

func encodeCIDRs(p []netip.Prefix) (string, error) {
	ss := make([]string, len(p))
	for i, x := range p {
		ss[i] = x.String()
	}
	b, err := json.Marshal(ss)
	return string(b), err
}

func scanRule(r scanner) (store.AccessRule, error) {
	var (
		a       store.AccessRule
		cidrs   string
		enabled int
		created int64
		revoked sql.NullInt64
	)
	if err := r.Scan(&a.ID, &a.Name, &cidrs, &a.KeyHash, &a.KeyPrefix, &a.RPS, &enabled, &created, &revoked); err != nil {
		return store.AccessRule{}, mapErr(err)
	}
	var ss []string
	if err := json.Unmarshal([]byte(cidrs), &ss); err != nil {
		return store.AccessRule{}, fmt.Errorf("sqlite: decode cidrs: %w", err)
	}
	for _, x := range ss {
		p, err := netip.ParsePrefix(x)
		if err != nil {
			return store.AccessRule{}, fmt.Errorf("sqlite: decode cidr %q: %w", x, err)
		}
		a.CIDRs = append(a.CIDRs, p)
	}
	a.Enabled = enabled != 0
	a.CreatedAt = fromMS(created)
	a.RevokedAt = ptrTime(revoked)
	if len(a.KeyHash) == 0 {
		a.KeyHash = nil
	}
	return a, nil
}

func (r accessRuleRepo) Create(ctx context.Context, a store.AccessRule) (store.AccessRule, error) {
	if err := a.Validate(); err != nil {
		return store.AccessRule{}, err
	}
	cidrs, err := encodeCIDRs(a.CIDRs)
	if err != nil {
		return store.AccessRule{}, err
	}
	a.CreatedAt = time.UnixMilli(ms(time.Now())).UTC()
	var kh any
	if len(a.KeyHash) > 0 {
		kh = a.KeyHash
	}
	res, err := r.s.w.ExecContext(ctx,
		`INSERT INTO access_rules (name, cidrs, key_hash, key_prefix, rps, enabled, created_at, revoked_at)
		 VALUES (?,?,?,?,?,?,?,?)`,
		a.Name, cidrs, kh, a.KeyPrefix, a.RPS, boolInt(a.Enabled), ms(a.CreatedAt), nullMS(a.RevokedAt))
	if err != nil {
		return store.AccessRule{}, mapErr(err)
	}
	a.ID, err = res.LastInsertId()
	return a, err
}

func (r accessRuleRepo) Get(ctx context.Context, id int64) (store.AccessRule, error) {
	return scanRule(r.s.r.QueryRowContext(ctx, `SELECT `+ruleCols+` FROM access_rules WHERE id = ?`, id))
}

func (r accessRuleRepo) GetByName(ctx context.Context, name string) (store.AccessRule, error) {
	return scanRule(r.s.r.QueryRowContext(ctx, `SELECT `+ruleCols+` FROM access_rules WHERE name = ?`, name))
}

func (r accessRuleRepo) List(ctx context.Context) ([]store.AccessRule, error) {
	rows, err := r.s.r.QueryContext(ctx, `SELECT `+ruleCols+` FROM access_rules ORDER BY id`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.AccessRule
	for rows.Next() {
		a, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, mapErr(rows.Err())
}

// Update меняет name/cidrs/rps/enabled. Ключ неизменяем; итоговое правило обязано
// оставаться валидным (сеть или ключ) — это проверяет CHECK в БД.
func (r accessRuleRepo) Update(ctx context.Context, a store.AccessRule) (store.AccessRule, error) {
	if a.Name == "" || a.RPS < 0 {
		return store.AccessRule{}, store.ErrInvalid
	}
	for _, p := range a.CIDRs {
		if !p.IsValid() {
			return store.AccessRule{}, store.ErrInvalid
		}
	}
	cidrs, err := encodeCIDRs(a.CIDRs)
	if err != nil {
		return store.AccessRule{}, err
	}
	if err := r.s.execAffected(ctx,
		`UPDATE access_rules SET name=?, cidrs=?, rps=?, enabled=? WHERE id=?`,
		a.Name, cidrs, a.RPS, boolInt(a.Enabled), a.ID); err != nil {
		return store.AccessRule{}, err
	}
	return r.Get(ctx, a.ID)
}

func (r accessRuleRepo) Revoke(ctx context.Context, id int64) error {
	return r.s.execAffected(ctx,
		`UPDATE access_rules SET enabled=0, revoked_at=COALESCE(revoked_at, ?) WHERE id=?`, ms(time.Now()), id)
}

func (r accessRuleRepo) Delete(ctx context.Context, id int64) error {
	return r.s.execAffected(ctx, `DELETE FROM access_rules WHERE id=?`, id)
}

func (r accessRuleRepo) Version(ctx context.Context) (int64, error) {
	return r.s.version(ctx, "access_rules")
}
