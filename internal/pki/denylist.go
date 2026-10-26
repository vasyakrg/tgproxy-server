package pki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// ErrRevoked — сертификат в denylist.
var ErrRevoked = errors.New("certificate revoked")

// Denylist — отозванные серийники: кеш в памяти поверх CertRepo.
// Check работает без обращений к БД; изменения из других процессов (CLI)
// подхватываются Refresh/Run.
type Denylist struct {
	repo store.CertRepo
	mu   sync.RWMutex
	set  map[string]struct{}
}

// NewDenylist загружает denylist из БД.
func NewDenylist(ctx context.Context, repo store.CertRepo) (*Denylist, error) {
	d := &Denylist{repo: repo, set: map[string]struct{}{}}
	if err := d.Refresh(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// Refresh перечитывает denylist из БД.
func (d *Denylist) Refresh(ctx context.Context) error {
	list, err := d.repo.ListDenied(ctx)
	if err != nil {
		return fmt.Errorf("pki: load denylist: %w", err)
	}
	set := make(map[string]struct{}, len(list))
	for _, e := range list {
		set[normalizeSerial(e.Serial)] = struct{}{}
	}
	d.mu.Lock()
	d.set = set
	d.mu.Unlock()
	return nil
}

// Run периодически вызывает Refresh и чистит просроченные записи до отмены ctx.
func (d *Denylist) Run(ctx context.Context, interval time.Duration, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, perr := d.repo.PruneDenied(ctx, nowFunc())
			if err := errors.Join(perr, d.Refresh(ctx)); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

// IsDenied сообщает, отозван ли серийник (hex).
func (d *Denylist) IsDenied(serial string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.set[normalizeSerial(serial)]
	return ok
}

// Check — pki.Check для VerifyAgentPeer/VerifyServerPeer и gateway.
func (d *Denylist) Check(leaf *x509.Certificate) error {
	if d.IsDenied(SerialString(leaf)) {
		return fmt.Errorf("serial %s: %w", SerialString(leaf), ErrRevoked)
	}
	return nil
}

// Revoke добавляет серийник в denylist (идемпотентно). Для известного
// сертификата запоминает agent_id и срок (после NotAfter запись можно удалить);
// для неизвестного — срок DefaultTTL от текущего момента.
func (d *Denylist) Revoke(ctx context.Context, serial, reason string) error {
	serial = normalizeSerial(serial)
	if serial == "" {
		return errors.New("pki: empty serial")
	}
	entry := store.DeniedCert{Serial: serial, Reason: reason, NotAfter: nowFunc().Add(DefaultTTL), DeniedAt: nowFunc()}
	rec, err := d.repo.Get(ctx, serial)
	switch {
	case err == nil:
		entry.AgentID, entry.NotAfter = rec.AgentID, rec.NotAfter
	case errors.Is(err, store.ErrNotFound):
	default:
		return fmt.Errorf("pki: lookup cert: %w", err)
	}
	return d.deny(ctx, entry)
}

// RevokeAgent отзывает все выпущенные сертификаты агента; возвращает число
// отозванных серийников.
func (d *Denylist) RevokeAgent(ctx context.Context, agentID, reason string) (int, error) {
	recs, err := d.repo.ListByAgent(ctx, agentID)
	if err != nil {
		return 0, fmt.Errorf("pki: list certs: %w", err)
	}
	for _, r := range recs {
		e := store.DeniedCert{Serial: normalizeSerial(r.Serial), AgentID: agentID, Reason: reason, NotAfter: r.NotAfter, DeniedAt: nowFunc()}
		if err := d.deny(ctx, e); err != nil {
			return 0, err
		}
	}
	return len(recs), nil
}

func (d *Denylist) deny(ctx context.Context, e store.DeniedCert) error {
	if err := d.repo.Deny(ctx, e); err != nil {
		return fmt.Errorf("pki: deny %s: %w", e.Serial, err)
	}
	d.mu.Lock()
	d.set[e.Serial] = struct{}{}
	d.mu.Unlock()
	return nil
}
