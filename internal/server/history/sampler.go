package history

import (
	"context"
	"log/slog"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Sampler раз в 10s сбрасывает Collector в samples_10s и двигает rollup/retention.
type Sampler struct {
	Collector *Collector
	Repo      store.HistoryRepo
	Roller    *Roller // nil — без rollup
	Log       *slog.Logger
}

// Tick обрабатывает один тик: At = начало только что закончившегося 10s-интервала.
func (s *Sampler) Tick(ctx context.Context, now time.Time) error {
	samples := s.Collector.Drain()
	at := now.Truncate(Step10s).Add(-Step10s)
	for i := range samples {
		samples[i].At = at
	}
	err := s.Repo.Append(ctx, store.Res10s, samples)
	if s.Roller != nil {
		if rerr := s.Roller.Step(ctx, now); rerr != nil && err == nil {
			err = rerr
		}
	}
	return err
}

// Run крутит Tick по каналу тиков до отмены ctx. После отмены делает финальный Drain.
func (s *Sampler) Run(ctx context.Context, ticks <-chan time.Time) {
	lg := s.Log
	if lg == nil {
		lg = slog.Default()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case now, ok := <-ticks:
			if !ok {
				return
			}
			if err := s.Tick(ctx, now); err != nil && ctx.Err() == nil {
				lg.Error("history: sampler tick", "err", err)
			}
		}
	}
}

// RunTicker — Run с реальным тикером 10s.
func (s *Sampler) RunTicker(ctx context.Context) {
	t := time.NewTicker(Step10s)
	defer t.Stop()
	s.Run(ctx, t.C)
}
