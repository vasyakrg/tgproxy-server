package sqlite

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type hostKeyRepo struct{ s *Store }

func (r hostKeyRepo) Get(ctx context.Context, host string) (store.HostKey, error) {
	k := store.HostKey{Host: host}
	var c int64
	err := r.s.r.QueryRowContext(ctx,
		`SELECT agent_id, algo, fingerprint, public_key, created_at FROM agent_hostkeys WHERE host = ?`, host).
		Scan(&k.AgentID, &k.Algo, &k.Fingerprint, &k.PublicKey, &c)
	if err != nil {
		return store.HostKey{}, mapErr(err)
	}
	k.CreatedAt = fromMS(c)
	return k, nil
}

func (r hostKeyRepo) Put(ctx context.Context, k store.HostKey) error {
	if k.Host == "" || k.Fingerprint == "" || len(k.PublicKey) == 0 {
		return store.ErrInvalid
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	_, err := r.s.w.ExecContext(ctx,
		`INSERT INTO agent_hostkeys (host, agent_id, algo, fingerprint, public_key, created_at) VALUES (?,?,?,?,?,?)
		 ON CONFLICT(host) DO UPDATE SET agent_id=excluded.agent_id, algo=excluded.algo,
		   fingerprint=excluded.fingerprint, public_key=excluded.public_key`,
		k.Host, k.AgentID, k.Algo, k.Fingerprint, k.PublicKey, ms(k.CreatedAt))
	return mapErr(err)
}

func (r hostKeyRepo) Delete(ctx context.Context, host string) error {
	return r.s.execAffected(ctx, `DELETE FROM agent_hostkeys WHERE host = ?`, host)
}
