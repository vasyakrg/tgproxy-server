package balancer

import (
	"math"
	"sync"
	"time"
)

const (
	ewmaAlpha          = 0.3
	defaultEWMALatency = 100 * time.Millisecond
	// ewmaIdleDecay — постоянная времени затухания оценки простаивающего
	// агента к нулю (как peak-EWMA в Finagle/Linkerd). Простаивающий агент
	// становится привлекательнее и получает пробный запрос, поэтому один
	// медленный ответ не выключает его из P2C навсегда.
	ewmaIdleDecay = 5 * time.Second
)

// ewma — потокобезопасное экспоненциальное скользящее среднее задержки.
type ewma struct {
	mu    sync.Mutex
	value float64 // секунды
	init  bool
	last  time.Time // время последнего наблюдения (zero — без затухания)
}

// Value возвращает текущее среднее в секундах (дефолт до первых данных).
func (e *ewma) Value() float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.init {
		return defaultEWMALatency.Seconds()
	}
	return e.value
}

// ValueAt — оценка на момент now с учётом затухания за время простоя.
func (e *ewma) ValueAt(now time.Time) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.init {
		return defaultEWMALatency.Seconds()
	}
	if e.last.IsZero() || !now.After(e.last) {
		return e.value
	}
	return e.value * math.Exp(-float64(now.Sub(e.last))/float64(ewmaIdleDecay))
}

// ObserveAt добавляет наблюдение, сделанное в момент now.
func (e *ewma) ObserveAt(d time.Duration, now time.Time) {
	e.Observe(d)
	e.mu.Lock()
	e.last = now
	e.mu.Unlock()
}

// Observe добавляет наблюдение.
func (e *ewma) Observe(d time.Duration) {
	s := d.Seconds()
	if s < 0 {
		s = 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.init {
		// Первое наблюдение сглаживается с дефолтом: обычно это запрос с
		// TLS-рукопожатием, и целиком он бы надолго завысил оценку агента.
		e.value, e.init = ewmaAlpha*s+(1-ewmaAlpha)*defaultEWMALatency.Seconds(), true
		return
	}
	e.value = ewmaAlpha*s + (1-ewmaAlpha)*e.value
}
