package mux

import (
	"net/netip"
	"sync"
)

// limits — глобальный счётчик соединений, счётчик на IP и потолок
// незавершённых рукопожатий. Соединение считается с admit до release;
// fallthrough освобождает слот сразу после передачи TLS-обработчику.
type limits struct {
	mu         sync.Mutex
	maxConns   int
	maxPerIP   int
	maxPending int
	total      int
	pending    int
	perIP      map[netip.Addr]int
	perSecret  map[int64]int
}

func newLimits(maxConns, maxPerIP, maxPending int) *limits {
	return &limits{
		maxConns: maxConns, maxPerIP: maxPerIP, maxPending: maxPending,
		perIP: make(map[netip.Addr]int), perSecret: make(map[int64]int),
	}
}

// set применяет новые потолки; уже занятые слоты не трогаются.
func (l *limits) set(maxConns, maxPerIP, maxPending int) {
	l.mu.Lock()
	l.maxConns, l.maxPerIP, l.maxPending = maxConns, maxPerIP, maxPending
	l.mu.Unlock()
}

// admitSecret занимает слот секрета id; max<=0 — без лимита (слот не считается).
func (l *limits) admitSecret(id int64, limit int) bool {
	if limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perSecret[id] >= limit {
		return false
	}
	l.perSecret[id]++
	return true
}

// releaseSecret освобождает слот, занятый admitSecret с max>0.
func (l *limits) releaseSecret(id int64) {
	l.mu.Lock()
	if l.perSecret[id]--; l.perSecret[id] <= 0 {
		delete(l.perSecret, id)
	}
	l.mu.Unlock()
}

// admit занимает слот (общий, IP, рукопожатие); false — лимит превышен.
func (l *limits) admit(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxConns || l.pending >= l.maxPending || l.perIP[ip] >= l.maxPerIP {
		return false
	}
	l.total++
	l.pending++
	l.perIP[ip]++
	return true
}

// handshakeDone освобождает слот незавершённого рукопожатия.
func (l *limits) handshakeDone() {
	l.mu.Lock()
	l.pending--
	l.mu.Unlock()
}

// release освобождает общий слот и слот IP.
func (l *limits) release(ip netip.Addr) {
	l.mu.Lock()
	l.total--
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
	l.mu.Unlock()
}
