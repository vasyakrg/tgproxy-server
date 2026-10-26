package history

import (
	"context"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const errRateTimeout = 5 * time.Second

// AgentErrorRate реализует notify.ErrorRateSource: доля ошибок прокси
// (Sample.Err) среди ответов агента за последние window по samples_10s.
// 429 и ответы Telegram 4xx/5xx к ошибкам агента не относятся. requests —
// число запросов (ok+err) в окне; при чтении из БД ошибка → (0, 0).
func (q *Query) AgentErrorRate(agent string, window time.Duration) (rate float64, requests int64) {
	ctx, cancel := context.WithTimeout(context.Background(), errRateTimeout)
	defer cancel()
	now := q.now()
	rows, err := q.History.Range(ctx, store.Res10s, agent, now.Add(-window), now)
	if err != nil {
		return 0, 0
	}
	var ok, bad int64
	for _, s := range rows {
		ok += s.OK
		bad += s.Err
	}
	requests = ok + bad
	if requests == 0 {
		return 0, 0
	}
	return float64(bad) / float64(requests), requests
}
