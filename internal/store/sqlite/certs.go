package sqlite

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type certRepo struct{ s *Store }

const certCols = `serial, agent_id, subject, not_before, not_after, cert_pem, created_at`

func scanCert(r scanner) (store.CertRecord, error) {
	var (
		c       store.CertRecord
		nb, na  int64
		created int64
	)
	if err := r.Scan(&c.Serial, &c.AgentID, &c.Subject, &nb, &na, &c.CertPEM, &created); err != nil {
		return store.CertRecord{}, mapErr(err)
	}
	c.NotBefore, c.NotAfter, c.CreatedAt = fromMS(nb), fromMS(na), fromMS(created)
	return c, nil
}

func (r certRepo) Put(ctx context.Context, c store.CertRecord) error {
	if c.Serial == "" || c.AgentID == "" || len(c.CertPEM) == 0 {
		return store.ErrInvalid
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO certs (`+certCols+`) VALUES (?,?,?,?,?,?,?)`,
		c.Serial, c.AgentID, c.Subject, ms(c.NotBefore), ms(c.NotAfter), c.CertPEM, ms(c.CreatedAt))
	return mapErr(err)
}

func (r certRepo) Get(ctx context.Context, serial string) (store.CertRecord, error) {
	return scanCert(r.s.r.QueryRowContext(ctx, `SELECT `+certCols+` FROM certs WHERE serial = ?`, serial))
}

func (r certRepo) list(ctx context.Context, q string, args ...any) ([]store.CertRecord, error) {
	rows, err := r.s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.CertRecord
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, mapErr(rows.Err())
}

func (r certRepo) ListByAgent(ctx context.Context, agentID string) ([]store.CertRecord, error) {
	return r.list(ctx, `SELECT `+certCols+` FROM certs WHERE agent_id = ? ORDER BY not_after, serial`, agentID)
}

func (r certRepo) ListExpiring(ctx context.Context, before time.Time) ([]store.CertRecord, error) {
	return r.list(ctx, `SELECT `+certCols+` FROM certs WHERE not_after < ? ORDER BY not_after, serial`, ms(before))
}

func (r certRepo) Deny(ctx context.Context, d store.DeniedCert) error {
	if d.Serial == "" {
		return store.ErrInvalid
	}
	if d.DeniedAt.IsZero() {
		d.DeniedAt = time.Now()
	}
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO cert_denylist (serial, agent_id, reason, not_after, denied_at) VALUES (?,?,?,?,?)
		 ON CONFLICT(serial) DO NOTHING`,
		d.Serial, d.AgentID, d.Reason, ms(d.NotAfter), ms(d.DeniedAt))
	return mapErr(err)
}

func (r certRepo) IsDenied(ctx context.Context, serial string) (bool, error) {
	var one int
	err := r.s.r.QueryRowContext(ctx, `SELECT 1 FROM cert_denylist WHERE serial = ?`, serial).Scan(&one)
	if err != nil {
		if mapErr(err) == store.ErrNotFound {
			return false, nil
		}
		return false, mapErr(err)
	}
	return true, nil
}

func (r certRepo) ListDenied(ctx context.Context) ([]store.DeniedCert, error) {
	rows, err := r.s.r.QueryContext(ctx,
		`SELECT serial, agent_id, reason, not_after, denied_at FROM cert_denylist ORDER BY denied_at, serial`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.DeniedCert
	for rows.Next() {
		var (
			d      store.DeniedCert
			na, da int64
		)
		if err := rows.Scan(&d.Serial, &d.AgentID, &d.Reason, &na, &da); err != nil {
			return nil, mapErr(err)
		}
		d.NotAfter, d.DeniedAt = fromMS(na), fromMS(da)
		out = append(out, d)
	}
	return out, mapErr(rows.Err())
}

func (r certRepo) PruneDenied(ctx context.Context, now time.Time) (int, error) {
	return r.s.execCount(ctx, `DELETE FROM cert_denylist WHERE not_after < ?`, ms(now))
}

func (r certRepo) SaveCA(ctx context.Context, ca store.CARecord) error {
	if len(ca.CertPEM) == 0 || len(ca.SealedKey) == 0 {
		return store.ErrInvalid
	}
	if ca.CreatedAt.IsZero() {
		ca.CreatedAt = time.Now()
	}
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO pki_ca (id, cert_pem, sealed_key, created_at) VALUES (1,?,?,?)`,
		ca.CertPEM, ca.SealedKey, ms(ca.CreatedAt))
	return mapErr(err)
}

func (r certRepo) LoadCA(ctx context.Context) (store.CARecord, error) {
	var (
		ca store.CARecord
		c  int64
	)
	err := r.s.r.QueryRowContext(ctx, `SELECT cert_pem, sealed_key, created_at FROM pki_ca WHERE id = 1`).
		Scan(&ca.CertPEM, &ca.SealedKey, &c)
	if err != nil {
		return store.CARecord{}, mapErr(err)
	}
	ca.CreatedAt = fromMS(c)
	return ca, nil
}
