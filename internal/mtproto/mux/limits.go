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
}

func newLimits(maxConns, maxPerIP, maxPending int) *limits {
	return &limits{
		maxConns: maxConns, maxPerIP: maxPerIP, maxPending: maxPending,
		perIP: make(map[netip.Addr]int),
	}
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
