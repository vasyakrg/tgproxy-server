package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	mu      sync.RWMutex
	impls   map[config.AgentMode]AgentTransport
	streams map[config.AgentMode]StreamTransport
}

// NewRegistry создаёт реестр; ключи — режимы связи.
func NewRegistry(impls map[config.AgentMode]AgentTransport) *Registry {
	r := &Registry{
		impls:   make(map[config.AgentMode]AgentTransport, len(impls)),
		streams: make(map[config.AgentMode]StreamTransport),
	}
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

// RegisterStream добавляет/заменяет StreamTransport режима (reverse — M11-T1).
func (r *Registry) RegisterStream(mode config.AgentMode, t StreamTransport) {
	r.mu.Lock()
	r.streams[mode] = t
	r.mu.Unlock()
}

// OpenMTProto делегирует StreamTransport режима агента. Для reverse без
// зарегистрированной реализации — ErrNotSupported (до M11-T1), для остальных
// режимов — ErrModeUnsupported.
func (r *Registry) OpenMTProto(ctx context.Context, a AgentRef, dc int) (net.Conn, error) {
	r.mu.RLock()
	t, ok := r.streams[a.Mode]
	r.mu.RUnlock()
	if !ok || t == nil {
		if a.Mode == config.AgentModeReverse {
			return nil, fmt.Errorf("%w: reverse (agent %s)", ErrNotSupported, a.ID)
		}
		return nil, fmt.Errorf("%w: %q (agent %s)", ErrModeUnsupported, a.Mode, a.ID)
	}
	return t.OpenMTProto(ctx, a, dc)
}

var _ StreamTransport = (*Registry)(nil)

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
	for _, t := range r.streams {
		if c, ok := t.(io.Closer); ok {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}
