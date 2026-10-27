package memtest

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// ---- mtproto ----

type mtSecretRepo struct{ s *Store }

func (r mtSecretRepo) find(id int64) int {
	return slices.IndexFunc(r.s.mtSecrets, func(m store.MTProtoSecret) bool { return m.ID == id })
}

func (r mtSecretRepo) nameTaken(name string, except int64) bool {
	return slices.ContainsFunc(r.s.mtSecrets, func(m store.MTProtoSecret) bool { return m.Name == name && m.ID != except })
}

func cloneMT(m store.MTProtoSecret) store.MTProtoSecret {
	m.SecretEnc = slices.Clone(m.SecretEnc)
	m.CIDRs = slices.Clone(m.CIDRs)
	if m.RevokedAt != nil {
		t := *m.RevokedAt
		m.RevokedAt = &t
	}
	if m.GraceUntil != nil {
		t := *m.GraceUntil
		m.GraceUntil = &t
	}
	if m.RotatedFrom != nil {
		v := *m.RotatedFrom
		m.RotatedFrom = &v
	}
	return m
}

func (r mtSecretRepo) Create(_ context.Context, name string, seal store.SealFunc, prefix string, cidrs []netip.Prefix, maxConns int) (store.MTProtoSecret, error) {
	if seal == nil {
		return store.MTProtoSecret{}, fmt.Errorf("%w: mtproto create needs seal", store.ErrInvalid)
	}
	m := store.MTProtoSecret{Name: name, SecretEnc: []byte{0}, Prefix: prefix, CIDRs: cidrs, MaxConns: maxConns, Enabled: true}
	if err := m.Validate(); err != nil {
		return store.MTProtoSecret{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if r.nameTaken(name, 0) {
		return store.MTProtoSecret{}, fmt.Errorf("%w: mtproto secret name %q", store.ErrConflict, name)
	}
	id := r.s.mtSecretID + 1
	sealed, err := seal(id)
	if err != nil {
		return store.MTProtoSecret{}, fmt.Errorf("memtest: seal mtproto secret %d: %w", id, err)
	}
	if len(sealed) == 0 {
		return store.MTProtoSecret{}, fmt.Errorf("%w: seal returned empty secret", store.ErrInvalid)
	}
	r.s.mtSecretID = id
	m.ID, m.CreatedAt, m.SecretEnc = id, nowMS(), sealed
	m = cloneMT(m)
	r.s.mtSecrets = append(r.s.mtSecrets, m)
	r.s.mtSecretsVer++
	return cloneMT(m), nil
}

func (r mtSecretRepo) Get(_ context.Context, id int64) (store.MTProtoSecret, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if i := r.find(id); i >= 0 {
		return cloneMT(r.s.mtSecrets[i]), nil
	}
	return store.MTProtoSecret{}, store.ErrNotFound
}

func (r mtSecretRepo) List(_ context.Context) ([]store.MTProtoSecret, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	out := make([]store.MTProtoSecret, 0, len(r.s.mtSecrets))
	for _, m := range r.s.mtSecrets {
		out = append(out, cloneMT(m))
	}
	return out, nil
}

func (r mtSecretRepo) ListActive(_ context.Context, now time.Time) ([]store.MTProtoSecret, int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.MTProtoSecret
	for _, m := range r.s.mtSecrets {
		if m.Active(now) {
			out = append(out, cloneMT(m))
		}
	}
	return out, r.s.mtSecretsVer, nil
}

func (r mtSecretRepo) Update(_ context.Context, m store.MTProtoSecret) (store.MTProtoSecret, error) {
	if err := m.Validate(); err != nil {
		return store.MTProtoSecret{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	i := r.find(m.ID)
	if i < 0 {
		return store.MTProtoSecret{}, store.ErrNotFound
	}
	if r.nameTaken(m.Name, m.ID) {
		return store.MTProtoSecret{}, fmt.Errorf("%w: mtproto secret name %q", store.ErrConflict, m.Name)
	}
	cur := &r.s.mtSecrets[i]
	cur.Name, cur.CIDRs, cur.MaxConns, cur.Enabled = m.Name, slices.Clone(m.CIDRs), m.MaxConns, m.Enabled
	r.s.mtSecretsVer++
	return cloneMT(*cur), nil
}

func (r mtSecretRepo) Revoke(_ context.Context, id int64, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	i := r.find(id)
	if i < 0 {
		return store.ErrNotFound
	}
	t := trunc(at)
	cur := &r.s.mtSecrets[i]
	cur.RevokedAt, cur.Enabled, cur.GraceUntil = &t, false, nil
	r.s.mtSecretsVer++
	return nil
}

func (r mtSecretRepo) Rotate(_ context.Context, id int64, seal store.SealFunc, prefix string, graceUntil time.Time) (store.MTProtoSecret, error) {
	if seal == nil || prefix == "" {
		return store.MTProtoSecret{}, fmt.Errorf("%w: mtproto rotate needs sealed key and prefix", store.ErrInvalid)
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	i := r.find(id)
	if i < 0 {
		return store.MTProtoSecret{}, store.ErrNotFound
	}
	old := &r.s.mtSecrets[i]
	if old.RevokedAt != nil {
		return store.MTProtoSecret{}, fmt.Errorf("%w: mtproto secret %d already revoked", store.ErrConflict, id)
	}
	now := nowMS()
	nid := r.s.mtSecretID + 1
	sealed, err := seal(nid)
	if err != nil {
		return store.MTProtoSecret{}, fmt.Errorf("memtest: seal mtproto secret %d: %w", nid, err)
	}
	if len(sealed) == 0 {
		return store.MTProtoSecret{}, fmt.Errorf("%w: seal returned empty secret", store.ErrInvalid)
	}
	nm := cloneMT(*old)
	nm.SecretEnc, nm.Prefix, nm.CreatedAt = slices.Clone(sealed), prefix, now
	nm.RevokedAt, nm.GraceUntil = nil, nil
	rf := id
	nm.RotatedFrom = &rf

	retired := fmt.Sprintf("%s~%d", old.Name, id)
	if slices.ContainsFunc(r.s.mtSecrets, func(m store.MTProtoSecret) bool { return m.Name == retired }) {
		return store.MTProtoSecret{}, fmt.Errorf("%w: mtproto secret name %q", store.ErrConflict, retired)
	}
	old.Name, old.RevokedAt = retired, &now
	if !graceUntil.IsZero() && graceUntil.After(now) {
		g := trunc(graceUntil)
		old.GraceUntil = &g
	} else {
		old.GraceUntil, old.Enabled = nil, false
	}
	r.s.mtSecretID = nid
	nm.ID = nid
	r.s.mtSecrets = append(r.s.mtSecrets, nm)
	r.s.mtSecretsVer += 2 // update + insert, как триггеры sqlite
	return cloneMT(nm), nil
}

func (r mtSecretRepo) Version(_ context.Context) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.s.mtSecretsVer, nil
}

type mtSessionRepo struct{ s *Store }

func (r mtSessionRepo) InsertBatch(_ context.Context, batch []store.MTProtoSession) error {
	for _, b := range batch {
		if err := b.Validate(); err != nil {
			return err
		}
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, b := range batch {
		r.s.mtSessionID++
		b.ID = r.s.mtSessionID
		b.StartedAt, b.EndedAt = trunc(b.StartedAt), trunc(b.EndedAt)
		r.s.mtSessions = append(r.s.mtSessions, b)
	}
	return nil
}

func (r mtSessionRepo) List(_ context.Context, q store.MTProtoSessionQuery) ([]store.MTProtoSession, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	var out []store.MTProtoSession
	for i := len(r.s.mtSessions) - 1; i >= 0 && len(out) < limit; i-- {
		m := r.s.mtSessions[i]
		switch {
		case q.BeforeID > 0 && m.ID >= q.BeforeID,
			q.SecretID != 0 && m.SecretID != q.SecretID,
			q.AgentID != "" && m.AgentID != q.AgentID,
			q.ClientIP != "" && m.ClientIP != q.ClientIP,
			q.DC != 0 && m.DC != q.DC:
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func (r mtSessionRepo) Prune(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := len(r.s.mtSessions)
	r.s.mtSessions = slices.DeleteFunc(r.s.mtSessions, func(m store.MTProtoSession) bool { return m.EndedAt.Before(before) })
	return n - len(r.s.mtSessions), nil
}
