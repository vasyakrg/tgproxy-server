package balancer

import "time"

const (
	breakerThreshold = 5
	breakerOpenFor   = 30 * time.Second
)

type breakerState int

const (
	stateClosed breakerState = iota
	stateOpen
	stateHalfOpen
)

// breaker — circuit breaker агента. Не потокобезопасен: защищается мьютексом Balancer.
type breaker struct {
	state    breakerState
	fails    int
	openedAt time.Time
	probing  bool // пробная попытка half-open в полёте
}

// available — можно ли выбрать агента сейчас (не потребляет пробную попытку).
func (b *breaker) available(now time.Time) bool {
	switch b.state {
	case stateClosed:
		return true
	case stateOpen:
		return now.Sub(b.openedAt) >= breakerOpenFor
	default:
		return !b.probing
	}
}

// acquire вызывается при фактическом выборе агента; потребляет пробу в half-open.
func (b *breaker) acquire(now time.Time) {
	if b.state == stateOpen && now.Sub(b.openedAt) >= breakerOpenFor {
		b.state = stateHalfOpen
	}
	if b.state == stateHalfOpen {
		b.probing = true
	}
}

func (b *breaker) success() {
	switch b.state {
	case stateClosed:
		b.fails = 0
	case stateHalfOpen:
		b.state, b.fails, b.probing = stateClosed, 0, false
	}
	// open: запоздалые результаты игнорируются.
}

func (b *breaker) failure(now time.Time) {
	switch b.state {
	case stateClosed:
		b.fails++
		if b.fails >= breakerThreshold {
			b.state, b.openedAt = stateOpen, now
		}
	case stateHalfOpen:
		b.state, b.openedAt, b.probing = stateOpen, now, false
	}
}

// cancel освобождает пробу half-open без изменения состояния.
func (b *breaker) cancel() {
	if b.state == stateHalfOpen {
		b.probing = false
	}
}
