package app

import (
	"sync"
	"time"
)

const (
	ruleStatsBucket  = 5 * time.Minute
	ruleStatsBuckets = int(24 * time.Hour / ruleStatsBucket)
)

// ruleStats — счётчики запросов по правилу доступа за скользящие 24 ч и время
// последнего запроса. Только память (с момента старта процесса): на горячем
// пути БД не трогаем.
type ruleStats struct {
	mu    sync.Mutex
	now   func() time.Time
	rules map[string]*ruleWindow
}

type ruleWindow struct {
	ids  [ruleStatsBuckets]int64
	n    [ruleStatsBuckets]int64
	last time.Time
}

func newRuleStats(now func() time.Time) *ruleStats {
	if now == nil {
		now = time.Now
	}
	return &ruleStats{now: now, rules: map[string]*ruleWindow{}}
}

func bucketID(t time.Time) int64 { return t.Unix() / int64(ruleStatsBucket/time.Second) }

// Observe учитывает запрос, прошедший проверку доступа по правилу rule.
func (s *ruleStats) Observe(rule string) {
	if rule == "" {
		return
	}
	now := s.now()
	id := bucketID(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.rules[rule]
	if w == nil {
		w = &ruleWindow{}
		s.rules[rule] = w
	}
	i := int(id % int64(ruleStatsBuckets))
	if w.ids[i] != id {
		w.ids[i], w.n[i] = id, 0
	}
	w.n[i]++
	w.last = now
}

// RuleStats возвращает запросы за 24 ч и время последнего запроса. ok всегда true:
// счётчики ведутся с момента старта, нулевой lastSeen — запросов не было.
func (s *ruleStats) RuleStats(name string) (requests24h int64, lastSeen time.Time, ok bool) {
	cur := bucketID(s.now())
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.rules[name]
	if w == nil {
		return 0, time.Time{}, true
	}
	for i := range w.ids {
		if w.ids[i] > cur-int64(ruleStatsBuckets) && w.ids[i] <= cur {
			requests24h += w.n[i]
		}
	}
	return requests24h, w.last, true
}
