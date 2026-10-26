package balancer

import (
	"errors"
	"time"
)

// ErrNoHealthyAgents — нет ни одного подходящего кандидата.
var ErrNoHealthyAgents = errors.New("balancer: no healthy agents")

// eligible: healthy && !draining && breaker != open && weight > 0.
func (a *agentState) eligible(now time.Time) bool {
	return a.healthy && !a.draining && a.weight > 0 && a.br.available(now)
}
