package agents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Параметры удаления по умолчанию.
const (
	DefaultDrainTimeout  = 30 * time.Second
	DefaultDrainInterval = time.Second

	// ReasonRemoved — причина denylist при удалении агента.
	ReasonRemoved = "removed"
)

// AgentRevoker отзывает все сертификаты агента (реализует *pki.Denylist).
type AgentRevoker interface {
	RevokeAgent(ctx context.Context, agentID, reason string) (int, error)
}

// AgentDrainer — управление составом реестра (реализует *Registry).
type AgentDrainer interface {
	Ref(id string) (transport.AgentRef, bool)
	SetDraining(ctx context.Context, id string, draining bool) error
	Refresh(ctx context.Context) error
}

var _ AgentDrainer = (*Registry)(nil)

// RemoverConfig — зависимости Remover. Все поля кроме таймингов обязательны.
type RemoverConfig struct {
	Registry AgentDrainer
	Repo     store.AgentRepo
	Revoker  AgentRevoker
	Status   StatusFunc // свежий опрос inflight (AgentTransport.Status)

	DrainTimeout  time.Duration // 30s
	DrainInterval time.Duration // 1s
	NewTimer      TimerFunc
	Log           *slog.Logger
}

// RemoveResult — итог удаления.
type RemoveResult struct {
	Revoked        int  // отозвано серийников
	DrainTimedOut  bool // inflight не дошёл до 0 за таймаут
	DrainUnchecked bool // агент недоступен — ожидание пропущено
}

// Remover удаляет агента: drain → ожидание inflight → отзыв сертификатов →
// удаление из БД (Registry.Refresh публикует AgentRemoved).
type Remover struct{ cfg RemoverConfig }

// NewRemover создаёт Remover.
func NewRemover(cfg RemoverConfig) (*Remover, error) {
	if cfg.Registry == nil || cfg.Repo == nil || cfg.Revoker == nil || cfg.Status == nil {
		return nil, errors.New("agents: remover requires registry, repo, revoker and status")
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = DefaultDrainTimeout
	}
	if cfg.DrainInterval <= 0 {
		cfg.DrainInterval = DefaultDrainInterval
	}
	if cfg.NewTimer == nil {
		cfg.NewTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
			t := time.NewTimer(d)
			return t.C, t.Stop
		}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Remover{cfg: cfg}, nil
}

// Remove удаляет агента. Таймаут ожидания inflight не является ошибкой:
// удаление продолжается (см. RemoveResult). Если шаг после отзыва не удался,
// сертификаты остаются отозванными, а ошибка возвращается — повторный вызов
// безопасен (идемпотентен).
func (m *Remover) Remove(ctx context.Context, agentID string) (RemoveResult, error) {
	var res RemoveResult
	if _, err := m.cfg.Repo.Get(ctx, agentID); err != nil {
		return res, fmt.Errorf("agents: remove %q: %w", agentID, err)
	}
	if err := m.cfg.Registry.SetDraining(ctx, agentID, true); err != nil {
		return res, fmt.Errorf("agents: drain %q: %w", agentID, err)
	}
	m.waitDrained(ctx, agentID, &res)
	if err := ctx.Err(); err != nil {
		return res, err
	}
	n, err := m.cfg.Revoker.RevokeAgent(ctx, agentID, ReasonRemoved)
	if err != nil {
		return res, fmt.Errorf("agents: revoke %q: %w", agentID, err)
	}
	res.Revoked = n
	if err := m.cfg.Repo.Delete(ctx, agentID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return res, fmt.Errorf("agents: delete %q: %w", agentID, err)
	}
	if err := m.cfg.Registry.Refresh(ctx); err != nil {
		return res, fmt.Errorf("agents: refresh after remove %q: %w", agentID, err)
	}
	m.cfg.Log.Info("agents: agent removed", "agent", agentID, "revoked", n, "drain_timeout", res.DrainTimedOut)
	return res, nil
}

func (m *Remover) waitDrained(ctx context.Context, id string, res *RemoveResult) {
	ref, ok := m.cfg.Registry.Ref(id)
	if !ok {
		res.DrainUnchecked = true
		return
	}
	dl, stopDL := m.cfg.NewTimer(m.cfg.DrainTimeout)
	defer stopDL()
	for {
		st, err := m.cfg.Status(ctx, ref)
		if err != nil || st == nil {
			res.DrainUnchecked = true // агент недоступен — активных запросов через него нет
			return
		}
		if st.Inflight <= 0 {
			return
		}
		tick, stop := m.cfg.NewTimer(m.cfg.DrainInterval)
		select {
		case <-ctx.Done():
			stop()
			return
		case <-dl:
			stop()
			res.DrainTimedOut = true
			return
		case <-tick:
		}
	}
}
