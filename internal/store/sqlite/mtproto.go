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

type mtprotoSecretRepo struct{ s *Store }

const mtSecretCols = `id, name, secret_enc, prefix, cidrs, max_conns, enabled, created_at, revoked_at, grace_until, rotated_from`

// activeCond — условие «секрет принимается на now» (параметр один: now в мс); синхронно с MTProtoSecret.Active.
const activeCond = `enabled = 1 AND (grace_until IS NULL OR grace_until > ?) AND (revoked_at IS NULL OR grace_until IS NOT NULL)`

func encodeNullableCIDRs(p []netip.Prefix) (any, error) {
	if len(p) == 0 {
		return nil, nil
	}
	s, err := encodeCIDRs(p)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func scanMTSecret(r scanner) (store.MTProtoSecret, error) {
	var (
		m       store.MTProtoSecret
		cidrs   sql.NullString
		enabled int
		created int64
		revoked sql.NullInt64
		grace   sql.NullInt64
		rotated sql.NullInt64
	)
	if err := r.Scan(&m.ID, &m.Name, &m.SecretEnc, &m.Prefix, &cidrs, &m.MaxConns, &enabled, &created, &revoked, &grace, &rotated); err != nil {
		return store.MTProtoSecret{}, mapErr(err)
	}
	if cidrs.Valid {
		var ss []string
		if err := json.Unmarshal([]byte(cidrs.String), &ss); err != nil {
			return store.MTProtoSecret{}, fmt.Errorf("sqlite: decode mtproto cidrs: %w", err)
		}
		for _, x := range ss {
			p, err := netip.ParsePrefix(x)
			if err != nil {
				return store.MTProtoSecret{}, fmt.Errorf("sqlite: decode mtproto cidr %q: %w", x, err)
			}
			m.CIDRs = append(m.CIDRs, p)
		}
	}
	m.Enabled = enabled != 0
	m.CreatedAt, m.RevokedAt, m.GraceUntil = fromMS(created), ptrTime(revoked), ptrTime(grace)
	if rotated.Valid {
		v := rotated.Int64
		m.RotatedFrom = &v
	}
	return m, nil
}

func (r mtprotoSecretRepo) Create(ctx context.Context, name string, sealed []byte, prefix string, cidrs []netip.Prefix, maxConns int) (store.MTProtoSecret, error) {
	m := store.MTProtoSecret{Name: name, SecretEnc: sealed, Prefix: prefix, CIDRs: cidrs, MaxConns: maxConns}
	if err := m.Validate(); err != nil {
		return store.MTProtoSecret{}, err
	}
	enc, err := encodeNullableCIDRs(cidrs)
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	res, err := r.s.w.ExecContext(ctx,
		`INSERT INTO mtproto_secrets (name, secret_enc, prefix, cidrs, max_conns, enabled, created_at) VALUES (?,?,?,?,?,1,?)`,
		name, sealed, prefix, enc, maxConns, ms(time.Now()))
	if err != nil {
		return store.MTProtoSecret{}, mapErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	// читаем с writer: только что записанное должно быть видно сразу
	return scanMTSecret(r.s.w.QueryRowContext(ctx, `SELECT `+mtSecretCols+` FROM mtproto_secrets WHERE id = ?`, id))
}

func (r mtprotoSecretRepo) Get(ctx context.Context, id int64) (store.MTProtoSecret, error) {
	return scanMTSecret(r.s.w.QueryRowContext(ctx, `SELECT `+mtSecretCols+` FROM mtproto_secrets WHERE id = ?`, id))
}

func scanMTSecrets(rows *sql.Rows) ([]store.MTProtoSecret, error) {
	defer func() { _ = rows.Close() }()
	var out []store.MTProtoSecret
	for rows.Next() {
		m, err := scanMTSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, mapErr(rows.Err())
}

func (r mtprotoSecretRepo) List(ctx context.Context) ([]store.MTProtoSecret, error) {
	rows, err := r.s.r.QueryContext(ctx, `SELECT `+mtSecretCols+` FROM mtproto_secrets ORDER BY id`)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanMTSecrets(rows)
}

func (r mtprotoSecretRepo) ListActive(ctx context.Context, now time.Time) ([]store.MTProtoSecret, int64, error) {
	// версия и строки читаются в одной транзакции (снимок WAL): версия не опережает данные
	tx, err := r.s.r.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()
	var v int64
	if err := tx.QueryRowContext(ctx, `SELECT v FROM versions WHERE name = 'mtproto_secrets'`).Scan(&v); err != nil {
		return nil, 0, mapErr(err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+mtSecretCols+` FROM mtproto_secrets WHERE `+activeCond+` ORDER BY id`, ms(now))
	if err != nil {
		return nil, 0, mapErr(err)
	}
	out, err := scanMTSecrets(rows)
	return out, v, err
}

func (r mtprotoSecretRepo) Update(ctx context.Context, m store.MTProtoSecret) (store.MTProtoSecret, error) {
	if err := m.Validate(); err != nil {
		return store.MTProtoSecret{}, err
	}
	enc, err := encodeNullableCIDRs(m.CIDRs)
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	if err := r.s.execAffected(ctx,
		`UPDATE mtproto_secrets SET name = ?, cidrs = ?, max_conns = ?, enabled = ? WHERE id = ?`,
		m.Name, enc, m.MaxConns, m.Enabled, m.ID); err != nil {
		return store.MTProtoSecret{}, err
	}
	return r.Get(ctx, m.ID)
}

func (r mtprotoSecretRepo) Revoke(ctx context.Context, id int64, at time.Time) error {
	return r.s.execAffected(ctx,
		`UPDATE mtproto_secrets SET revoked_at = ?, enabled = 0, grace_until = NULL WHERE id = ?`, ms(at), id)
}

func (r mtprotoSecretRepo) Rotate(ctx context.Context, id int64, sealed []byte, prefix string, graceUntil time.Time) (store.MTProtoSecret, error) {
	if len(sealed) == 0 || prefix == "" {
		return store.MTProtoSecret{}, fmt.Errorf("%w: mtproto rotate needs sealed key and prefix", store.ErrInvalid)
	}
	tx, err := r.s.w.BeginTx(ctx, nil) // BEGIN IMMEDIATE: чтение старого и запись нового без гонки
	if err != nil {
		return store.MTProtoSecret{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()
	old, err := scanMTSecret(tx.QueryRowContext(ctx, `SELECT `+mtSecretCols+` FROM mtproto_secrets WHERE id = ?`, id))
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	if old.RevokedAt != nil {
		return store.MTProtoSecret{}, fmt.Errorf("%w: mtproto secret %d already revoked", store.ErrConflict, id)
	}
	now := time.Now()
	var grace any
	enabled := 0
	if !graceUntil.IsZero() && graceUntil.After(now) {
		grace, enabled = ms(graceUntil), 1
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE mtproto_secrets SET name = ?, revoked_at = ?, grace_until = ?, enabled = ? WHERE id = ?`,
		fmt.Sprintf("%s~%d", old.Name, id), ms(now), grace, enabled, id); err != nil {
		return store.MTProtoSecret{}, mapErr(err)
	}
	enc, err := encodeNullableCIDRs(old.CIDRs)
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO mtproto_secrets (name, secret_enc, prefix, cidrs, max_conns, enabled, created_at, rotated_from) VALUES (?,?,?,?,?,?,?,?)`,
		old.Name, sealed, prefix, enc, old.MaxConns, old.Enabled, ms(now), id)
	if err != nil {
		return store.MTProtoSecret{}, mapErr(err)
	}
	nid, err := res.LastInsertId()
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	m, err := scanMTSecret(tx.QueryRowContext(ctx, `SELECT `+mtSecretCols+` FROM mtproto_secrets WHERE id = ?`, nid))
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.MTProtoSecret{}, mapErr(err)
	}
	return m, nil
}

func (r mtprotoSecretRepo) Version(ctx context.Context) (int64, error) {
	return r.s.version(ctx, "mtproto_secrets")
}

type mtprotoSessionRepo struct{ s *Store }

func (r mtprotoSessionRepo) InsertBatch(ctx context.Context, batch []store.MTProtoSession) error {
	if len(batch) == 0 {
		return nil
	}
	for _, b := range batch {
		if err := b.Validate(); err != nil {
			return err
		}
	}
	tx, err := r.s.w.BeginTx(ctx, nil)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()
	st, err := tx.PrepareContext(ctx,
		`INSERT INTO mtproto_sessions (started_at, ended_at, client_ip, secret_id, dc, agent_id, bytes_in, bytes_out, close_reason)
		 VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = st.Close() }()
	for _, b := range batch {
		if _, err := st.ExecContext(ctx, ms(b.StartedAt), ms(b.EndedAt), b.ClientIP, b.SecretID, b.DC, b.AgentID, b.BytesIn, b.BytesOut, b.CloseReason); err != nil {
			return mapErr(err)
		}
	}
	return mapErr(tx.Commit())
}

func (r mtprotoSessionRepo) List(ctx context.Context, q store.MTProtoSessionQuery) ([]store.MTProtoSession, error) {
	query := `SELECT id, started_at, ended_at, client_ip, secret_id, dc, agent_id, bytes_in, bytes_out, close_reason FROM mtproto_sessions WHERE 1=1`
	var args []any
	add := func(cond string, v any) {
		query += ` AND ` + cond // #nosec G202 -- cond — только константные фрагменты из этой функции
		args = append(args, v)
	}
	if q.BeforeID > 0 {
		add("id < ?", q.BeforeID)
	}
	if q.SecretID != 0 {
		add("secret_id = ?", q.SecretID)
	}
	if q.AgentID != "" {
		add("agent_id = ?", q.AgentID)
	}
	if q.ClientIP != "" {
		add("client_ip = ?", q.ClientIP)
	}
	if q.DC != 0 {
		add("dc = ?", q.DC)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limitOr(q.Limit, 100))
	rows, err := r.s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.MTProtoSession
	for rows.Next() {
		var (
			m          store.MTProtoSession
			start, end int64
		)
		if err := rows.Scan(&m.ID, &start, &end, &m.ClientIP, &m.SecretID, &m.DC, &m.AgentID, &m.BytesIn, &m.BytesOut, &m.CloseReason); err != nil {
			return nil, mapErr(err)
		}
		m.StartedAt, m.EndedAt = fromMS(start), fromMS(end)
		out = append(out, m)
	}
	return out, mapErr(rows.Err())
}

func (r mtprotoSessionRepo) Prune(ctx context.Context, before time.Time) (int, error) {
	return r.s.execCount(ctx, `DELETE FROM mtproto_sessions WHERE ended_at < ?`, ms(before))
}
