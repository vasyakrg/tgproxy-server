package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// RefResolver отдаёт адресата транспорта по id агента (реализует agents.Registry).
type RefResolver interface {
	Ref(id string) (transport.AgentRef, bool)
}

// Upstream — адаптер router.Upstream к transport.AgentTransport: адресата
// (AgentRef) берёт из реестра агентов, а не из конфигурации.
type Upstream struct {
	t    transport.AgentTransport
	refs RefResolver
}

// NewUpstream строит адаптер.
func NewUpstream(t transport.AgentTransport, refs RefResolver) *Upstream {
	return &Upstream{t: t, refs: refs}
}

// RoundTrip реализует router.Upstream. Неизвестный id — ошибка.
func (u *Upstream) RoundTrip(ctx context.Context, agentID string, req *http.Request) (*http.Response, error) {
	ref, ok := u.refs.Ref(agentID)
	if !ok {
		return nil, fmt.Errorf("app: unknown agent %q", agentID)
	}
	return u.t.RoundTrip(ctx, ref, req)
}
