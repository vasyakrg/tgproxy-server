package agent

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

var phases = [...]string{
	tgapi.PhaseDial, tgapi.PhaseTLS, tgapi.PhasePreSend,
	tgapi.PhaseWrite, tgapi.PhaseRead, tgapi.PhaseTimeout,
}

const (
	rpsWindow = 60
	rttAlpha  = 0.3
)

// stats — счётчики в памяти для /_agent/status (Prometheus — в M3).
type stats struct {
	now      func() time.Time
	inflight atomic.Int64 // все запросы в полёте, включая long-poll
	// inflightLP — подмножество inflight: висящие getUpdates (long-poll).
	inflightLP atomic.Int64
	errs       [len(phases)]atomic.Int64

	mu      sync.Mutex
	secs    [rpsWindow]int64
	counts  [rpsWindow]int64
	rtt     float64
	rttInit bool
}

func newStats(now func() time.Time) *stats { return &stats{now: now} }

func (s *stats) begin(longPoll bool) {
	s.inflight.Add(1)
	if longPoll {
		s.inflightLP.Add(1)
	}
	sec := s.now().Unix()
	i := int(sec % rpsWindow)
	s.mu.Lock()
	if s.secs[i] != sec {
		s.secs[i], s.counts[i] = sec, 0
	}
	s.counts[i]++
	s.mu.Unlock()
}

func (s *stats) end(longPoll bool) {
	s.inflight.Add(-1)
	if longPoll {
		s.inflightLP.Add(-1)
	}
}

func (s *stats) recordError(phase string) {
	for i, p := range phases {
		if p == phase {
			s.errs[i].Add(1)
			return
		}
	}
}

func (s *stats) errorsByPhase() map[string]int64 {
	out := make(map[string]int64, len(phases))
	for i, p := range phases {
		out[p] = s.errs[i].Load()
	}
	return out
}

func (s *stats) observeRTT(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	s.mu.Lock()
	if !s.rttInit {
		s.rtt, s.rttInit = ms, true
	} else {
		s.rtt = rttAlpha*ms + (1-rttAlpha)*s.rtt
	}
	s.mu.Unlock()
}

func (s *stats) upstreamRTT() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rtt
}

// rps1m — среднее число запросов в секунду за последнюю минуту.
func (s *stats) rps1m() float64 {
	now := s.now().Unix()
	var total int64
	s.mu.Lock()
	for i := range s.secs {
		if now-s.secs[i] < rpsWindow && s.secs[i] <= now {
			total += s.counts[i]
		}
	}
	s.mu.Unlock()
	return float64(total) / rpsWindow
}
