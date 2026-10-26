package history

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Лимиты журнала ошибок по умолчанию.
const (
	DefaultErrorBuffer = 1024
	DefaultKeepErrors  = 100_000
	DefaultErrorAge    = 30 * 24 * time.Hour
)

// ErrorLog — асинхронная запись error_events: Record не блокирует горячий путь.
type ErrorLog struct {
	Repo      store.ErrorEventRepo
	Keep      int           // 0 → DefaultKeepErrors
	MaxAge    time.Duration // 0 → DefaultErrorAge
	TrimEvery time.Duration // 0 → 5m
	Log       *slog.Logger

	ch      chan store.ErrorEvent
	dropped atomic.Int64
}

// NewErrorLog создаёт журнал с буфером buf (<=0 → DefaultErrorBuffer).
func NewErrorLog(repo store.ErrorEventRepo, buf int) *ErrorLog {
	if buf <= 0 {
		buf = DefaultErrorBuffer
	}
	return &ErrorLog{Repo: repo, ch: make(chan store.ErrorEvent, buf)}
}

// Record ставит событие в очередь. Описание очищается через redact. При переполнении
// событие теряется и растёт Dropped(). Никогда не блокируется.
func (l *ErrorLog) Record(_ context.Context, e store.ErrorEvent) {
	e.Description = redact.String(e.Description)
	select {
	case l.ch <- e:
	default:
		l.dropped.Add(1)
	}
}

// Dropped — число потерянных из-за переполнения событий.
func (l *ErrorLog) Dropped() int64 { return l.dropped.Load() }

// Pending — число событий в очереди.
func (l *ErrorLog) Pending() int { return len(l.ch) }

func (l *ErrorLog) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return slog.Default()
}

func (l *ErrorLog) write(ctx context.Context, e store.ErrorEvent) {
	if _, err := l.Repo.Append(ctx, e); err != nil {
		l.log().Error("history: error_events append", "err", err)
	}
}

// Trim применяет лимиты по количеству и возрасту.
func (l *ErrorLog) Trim(ctx context.Context, now time.Time) error {
	keep, age := l.Keep, l.MaxAge
	if keep == 0 {
		keep = DefaultKeepErrors
	}
	if age == 0 {
		age = DefaultErrorAge
	}
	_, err := l.Repo.Trim(ctx, keep, now.Add(-age))
	return err
}

// Run пишет события в БД и периодически вызывает Trim. После отмены ctx
// дописывает то, что осталось в очереди, и возвращается.
func (l *ErrorLog) Run(ctx context.Context) {
	every := l.TrimEvery
	if every == 0 {
		every = Step5m
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case e := <-l.ch:
			l.write(ctx, e)
		case now := <-t.C:
			if err := l.Trim(ctx, now); err != nil {
				l.log().Error("history: error_events trim", "err", err)
			}
		case <-ctx.Done():
			bg := context.WithoutCancel(ctx)
			for {
				select {
				case e := <-l.ch:
					l.write(bg, e)
				default:
					return
				}
			}
		}
	}
}
