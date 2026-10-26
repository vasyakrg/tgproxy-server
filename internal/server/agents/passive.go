package agents

import "errors"

var errNoStatus = errors.New("agents: empty status response")

// ReportResult — пассивный health по реальному трафику (вызывает роутер).
// failThreshold транспортных ошибок подряд переводят агента в down без
// ожидания опроса. Успех обновляет LastSeen и сбрасывает счётчик, но из down
// не выводит — это делает только успешный опрос статуса.
func (r *Registry) ReportResult(agentID string, transportErr bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.agents[agentID]
	if !ok {
		return
	}
	if !transportErr {
		e.passiveFails = 0
		e.LastSeen = r.now()
		return
	}
	e.passiveFails++
	if e.passiveFails >= r.failThreshold && e.Up {
		r.markDownLocked(e)
	}
}
