package app

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Upstream — адаптер router.Upstream к transport.AgentTransport: по id агента
// находит transport.AgentRef из конфигурации.
type Upstream struct {
	t    transport.AgentTransport
	refs map[string]transport.AgentRef
	ids  []string
}

// NewUpstream строит адаптер для агентов agents.
func NewUpstream(t transport.AgentTransport, agents []config.AgentEndpoint) (*Upstream, error) {
	u := &Upstream{t: t, refs: make(map[string]transport.AgentRef, len(agents))}
	for _, a := range agents {
		ref := transport.AgentRef{ID: a.ID, Mode: a.Mode}
		if a.URL != "" {
			pu, err := url.Parse(a.URL)
			if err != nil {
				return nil, fmt.Errorf("app: agent %q: bad url: %w", a.ID, err)
			}
			ref.URL = pu
		}
		if _, dup := u.refs[a.ID]; dup {
			return nil, fmt.Errorf("app: duplicate agent id %q", a.ID)
		}
		u.refs[a.ID] = ref
		u.ids = append(u.ids, a.ID)
	}
	return u, nil
}

// RoundTrip реализует router.Upstream. Неизвестный id — ошибка.
func (u *Upstream) RoundTrip(ctx context.Context, agentID string, req *http.Request) (*http.Response, error) {
	ref, ok := u.refs[agentID]
	if !ok {
		return nil, fmt.Errorf("app: unknown agent %q", agentID)
	}
	return u.t.RoundTrip(ctx, ref, req)
}

// Status запрашивает статус агента.
func (u *Upstream) Status(ctx context.Context, agentID string) (*transport.AgentStatus, error) {
	ref, ok := u.refs[agentID]
	if !ok {
		return nil, fmt.Errorf("app: unknown agent %q", agentID)
	}
	return u.t.Status(ctx, ref)
}

// AnyReady сообщает, отвечает ли хотя бы один агент на Status.
func (u *Upstream) AnyReady(ctx context.Context) bool {
	for _, id := range u.ids {
		if _, err := u.Status(ctx, id); err == nil {
			return true
		}
	}
	return false
}
