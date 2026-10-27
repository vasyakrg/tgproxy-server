package agents

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// ensurePollersLocked запускает poller для каждого агента без него; вызывать
// под r.mu. Без Run (runCtx == nil) poller'ы не стартуют.
func (r *Registry) ensurePollersLocked(runCtx context.Context) {
	if runCtx == nil {
		return
	}
	for id, e := range r.agents {
		if e.cancelPoll != nil {
			continue
		}
		pctx, cancel := context.WithCancel(runCtx)
		e.cancelPoll = cancel
		r.wg.Add(1)
		go r.pollLoop(pctx, id)
	}
}

// jittered возвращает интервал опроса ±10%.
func (r *Registry) jittered() time.Duration {
	f := 1 + (r.rnd()*2-1)*pollJitter
	return time.Duration(float64(r.pollInterval) * f)
}

func (r *Registry) pollLoop(ctx context.Context, id string) {
	defer r.wg.Done()
	r.pollOnce(ctx, id)
	for {
		ch, stop := r.newTimer(r.jittered())
		select {
		case <-ctx.Done():
			stop()
			return
		case <-ch:
		}
		r.pollOnce(ctx, id)
	}
}

// pollOnce опрашивает агента один раз и применяет результат.
func (r *Registry) pollOnce(ctx context.Context, id string) {
	ref, ok := r.Ref(id)
	if !ok {
		return
	}
	qctx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	st, err := r.status(qctx, ref)
	cancel()
	if ctx.Err() != nil {
		return // остановка, а не неудача опроса
	}
	if err == nil && st == nil {
		err = errNoStatus
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.agents[id]
	if !ok {
		return
	}
	if err != nil {
		e.ConsecutiveFails++
		if e.ConsecutiveFails >= r.failThreshold && e.Up {
			r.markDownLocked(e)
		}
		return
	}
	r.applySuccessLocked(e, st)
}

func (r *Registry) applySuccessLocked(e *entry, st *transport.AgentStatus) {
	id := e.Agent.ID
	e.ConsecutiveFails = 0
	e.passiveFails = 0
	e.LastSeen = r.now()
	cp := *st
	changed := mtprotoChanged(e.LastStatus, &cp)
	e.LastStatus = &cp
	e.reportedDraining = st.Draining
	if eff := e.Agent.Draining || st.Draining; eff != e.Draining {
		e.Draining = eff
		r.sink.SetDraining(id, eff)
		r.publishLocked(AgentDraining, id, eff)
	}
	if !e.Up {
		e.Up = true
		r.sink.SetHealthy(id, true)
		r.publishLocked(AgentUp, id, false)
	}
	if changed {
		r.publishLocked(AgentMTProto, id, false)
	}
}

// markDownLocked переводит агента в down (событие ровно один раз).
func (r *Registry) markDownLocked(e *entry) {
	e.Up = false
	r.sink.SetHealthy(e.Agent.ID, false)
	r.publishLocked(AgentDown, e.Agent.ID, false)
}
