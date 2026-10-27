package ban

import (
	"context"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// DefaultDigestInterval — окно агрегации алертов об автобанах: десятки банов за минуту
// (скан из ботнета) превращаются в одно сообщение.
const DefaultDigestInterval = time.Minute

// Digest собирает автобаны и периодически отдаёт их одной пачкой.
type Digest struct {
	mu      sync.Mutex
	pending []store.Ban
	flush   func(ctx context.Context, bans []store.Ban)
}

// NewDigest создаёт агрегатор; flush вызывается только при непустой пачке.
func NewDigest(flush func(ctx context.Context, bans []store.Ban)) *Digest {
	return &Digest{flush: flush}
}

// Add ставит бан в очередь пачки.
func (d *Digest) Add(b store.Ban) {
	d.mu.Lock()
	d.pending = append(d.pending, b)
	d.mu.Unlock()
}

// Flush отправляет накопленное (если есть).
func (d *Digest) Flush(ctx context.Context) {
	d.mu.Lock()
	batch := d.pending
	d.pending = nil
	d.mu.Unlock()
	if len(batch) > 0 {
		d.flush(ctx, batch)
	}
}

// Run шлёт пачки раз в interval; при остановке отдаёт остаток.
func (d *Digest) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultDigestInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.Flush(context.WithoutCancel(ctx))
			return
		case <-t.C:
			d.Flush(ctx)
		}
	}
}
