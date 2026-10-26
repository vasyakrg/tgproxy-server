package transport

import (
	"context"
	"time"
)

// Параметры h2 PING по умолчанию (architecture §4.1): период 15s, ответ
// ждём 5s, 2 пропуска подряд = соединение мёртво (≤35s до down).
const (
	DefaultPingEvery   = 15 * time.Second
	DefaultPingTimeout = 5 * time.Second
	DefaultMaxMisses   = 2
)

// pinger — часть *http2.ClientConn, нужная для проверки живости.
type pinger interface {
	Ping(ctx context.Context) error
}

// pingLoop шлёт PING каждые every и ждёт ack не дольше timeout. После
// maxMisses неудач подряд вызывает onDead и завершается; завершается и по
// отмене ctx (onDead тогда не вызывается).
func pingLoop(ctx context.Context, p pinger, every, timeout time.Duration, maxMisses int, onDead func()) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		pctx, cancel := context.WithTimeout(ctx, timeout)
		err := p.Ping(pctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			misses = 0
			continue
		}
		misses++
		if misses >= maxMisses {
			onDead()
			return
		}
	}
}
