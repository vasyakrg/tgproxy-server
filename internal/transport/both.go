package transport

import (
	"context"
	"errors"
	"net/http"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Both — AgentTransport режима both: сервер ходит к агенту сам по его адресу
// (Dial), а если до агента не достучаться и он держит обратные соединения —
// запрос уходит по ним (Reverse). Запрос повторяется на другом канале только
// если в Telegram он точно не ушёл (tgapi.PhaseNotSent) и тело можно переиграть.
type Both struct {
	Dial    AgentTransport
	Reverse AgentTransport
}

var _ AgentTransport = Both{}

// RoundTrip реализует AgentTransport.
func (b Both) RoundTrip(ctx context.Context, agent AgentRef, req *http.Request) (*http.Response, error) {
	resp, err := b.Dial.RoundTrip(ctx, agent, req)
	if err == nil || ctx.Err() != nil {
		return resp, err
	}
	var pe *PhaseError
	if !errors.As(err, &pe) || !tgapi.PhaseNotSent(pe.Phase) || !replayable(req) {
		return resp, err
	}
	rresp, rerr := b.Reverse.RoundTrip(ctx, agent, req)
	if errors.Is(rerr, ErrNoReverseConn) {
		return resp, err // обратных соединений нет: ошибка dial информативнее
	}
	return rresp, rerr
}

// Status реализует AgentTransport: сначала dial, при ошибке — reverse.
func (b Both) Status(ctx context.Context, agent AgentRef) (*AgentStatus, error) {
	st, err := b.Dial.Status(ctx, agent)
	if err == nil || ctx.Err() != nil {
		return st, err
	}
	if rst, rerr := b.Reverse.Status(ctx, agent); rerr == nil {
		return rst, nil
	}
	return st, err
}
