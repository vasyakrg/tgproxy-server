package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

// ErrModeUnsupported — для AgentRef.Mode нет зарегистрированной реализации
// (reverse до M5-T8).
var ErrModeUnsupported = errors.New("transport: agent mode unsupported")

// Registry выбирает реализацию AgentTransport по AgentRef.Mode и сам
// реализует AgentTransport.
type Registry struct {
	mu    sync.RWMutex
	impls map[config.AgentMode]AgentTransport
}

// NewRegistry создаёт реестр; ключи — режимы связи.
func NewRegistry(impls map[config.AgentMode]AgentTransport) *Registry {
	r := &Registry{impls: make(map[config.AgentMode]AgentTransport, len(impls))}
	for m, t := range impls {
		r.impls[m] = t
	}
	return r
}

// Register добавляет/заменяет реализацию режима (reverse в M5-T8).
func (r *Registry) Register(mode config.AgentMode, t AgentTransport) {
	r.mu.Lock()
	r.impls[mode] = t
	r.mu.Unlock()
}

func (r *Registry) pick(a AgentRef) (AgentTransport, error) {
	r.mu.RLock()
	t, ok := r.impls[a.Mode]
	r.mu.RUnlock()
	if !ok || t == nil {
		return nil, fmt.Errorf("%w: %q (agent %s)", ErrModeUnsupported, a.Mode, a.ID)
	}
	return t, nil
}

// RoundTrip делегирует реализации режима.
func (r *Registry) RoundTrip(ctx context.Context, a AgentRef, req *http.Request) (*http.Response, error) {
	t, err := r.pick(a)
	if err != nil {
		return nil, err
	}
	return t.RoundTrip(ctx, a, req)
}

// Status делегирует реализации режима.
func (r *Registry) Status(ctx context.Context, a AgentRef) (*AgentStatus, error) {
	t, err := r.pick(a)
	if err != nil {
		return nil, err
	}
	return t.Status(ctx, a)
}

// Close закрывает все реализации, реализующие io.Closer.
func (r *Registry) Close() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var errs []error
	for _, t := range r.impls {
		if c, ok := t.(io.Closer); ok {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}
