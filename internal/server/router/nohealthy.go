package router

import (
	"context"
	"errors"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
)

// noAgentPollStep — шаг опроса Pick, пока нет здоровых агентов.
const noAgentPollStep = 200 * time.Millisecond

// pickWait выбирает агента; если здоровых нет — опрашивает Pick с шагом
// noAgentPollStep, пока не пройдёт wait (по часам роутера) или не истечёт ctx.
// wait <= 0 — без ожидания. Возвращает balancer.ErrNoHealthyAgents по истечении.
func (r *Router) pickWait(ctx context.Context, exclude []string, wait time.Duration) (string, func(balancer.Result), error) {
	start := r.clock()
	for {
		id, rel, err := r.picker.Pick(ctx, exclude)
		if !errors.Is(err, balancer.ErrNoHealthyAgents) {
			return id, rel, err
		}
		left := wait - r.clock().Sub(start)
		if left <= 0 {
			return "", nil, err
		}
		if serr := r.sleep(ctx, min(noAgentPollStep, left)); serr != nil {
			return "", nil, serr
		}
	}
}

// cfgPicker — выбор без балансировщика (поведение M1): первый агент из
// конфигурации, не попавший в exclude.
type cfgPicker struct{ r *Router }

func (p cfgPicker) Pick(ctx context.Context, exclude []string) (string, func(balancer.Result), error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	for _, a := range p.r.cfg.Agents {
		if !contains(exclude, a.ID) {
			return a.ID, func(balancer.Result) {}, nil
		}
	}
	return "", nil, balancer.ErrNoHealthyAgents
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
