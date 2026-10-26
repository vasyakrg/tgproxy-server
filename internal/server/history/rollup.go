package history

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Ретенция по умолчанию (architecture §7).
const (
	Retention10s = 24 * time.Hour
	Retention5m  = 30 * 24 * time.Hour
)

// Roller агрегирует 10s → 5m и применяет ретенцию. Не потокобезопасен
// (вызывается из одной горутины Sampler).
type Roller struct {
	Repo         store.HistoryRepo
	Keep10s      time.Duration // 0 → Retention10s
	Keep5m       time.Duration // 0 → Retention5m
	next         time.Time     // начало первого ещё не свёрнутого 5m-окна
	lastPrune    time.Time
	backfillSpan time.Duration
}

// NewRoller создаёт Roller; при старте досчитывает до 1ч назад (upsert идемпотентен).
func NewRoller(repo store.HistoryRepo) *Roller {
	return &Roller{Repo: repo, backfillSpan: time.Hour}
}

// Step сворачивает все завершённые 5m-окна и раз в 5 минут чистит старое.
func (r *Roller) Step(ctx context.Context, now time.Time) error {
	if r.next.IsZero() {
		span := r.backfillSpan
		if span == 0 {
			span = time.Hour
		}
		r.next = now.Add(-span).Truncate(Step5m)
	}
	end := now.Truncate(Step5m) // до него все окна завершены
	if end.After(r.next) {
		if err := r.roll(ctx, r.next, end); err != nil {
			return err
		}
		r.next = end
	}
	if now.Sub(r.lastPrune) >= Step5m {
		if err := r.Prune(ctx, now); err != nil {
			return err
		}
		r.lastPrune = now
	}
	return nil
}

// Prune удаляет 10s старше Keep10s и 5m старше Keep5m.
func (r *Roller) Prune(ctx context.Context, now time.Time) error {
	if _, err := r.Repo.Prune(ctx, store.Res10s, now.Add(-cmp.Or(r.Keep10s, Retention10s))); err != nil {
		return err
	}
	_, err := r.Repo.Prune(ctx, store.Res5m, now.Add(-cmp.Or(r.Keep5m, Retention5m)))
	return err
}

type groupKey struct {
	agent string
	ts    time.Time
}

func (r *Roller) roll(ctx context.Context, from, to time.Time) error {
	src, err := r.Repo.Range(ctx, store.Res10s, "", from, to)
	if err != nil {
		return err
	}
	groups := map[groupKey]*store.Sample{}
	for _, s := range src {
		k := groupKey{s.AgentID, s.At.Truncate(Step5m)}
		g, ok := groups[k]
		if !ok {
			g = &store.Sample{At: k.ts, AgentID: s.AgentID}
			groups[k] = g
		}
		g.OK += s.OK
		g.Err += s.Err
		g.RateLimited += s.RateLimited
		g.Inflight = max(g.Inflight, s.Inflight)
		g.Buckets = addBuckets(g.Buckets, s.Buckets)
	}
	out := make([]store.Sample, 0, len(groups))
	for _, g := range groups {
		g.P95Ms = P95(g.Buckets)
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b store.Sample) int {
		return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.AgentID, b.AgentID))
	})
	return r.Repo.Append(ctx, store.Res5m, out)
}
