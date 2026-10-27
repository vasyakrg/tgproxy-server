package mtproto

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Параметры журнала по умолчанию.
const (
	DefaultJournalFlush    = 10 * time.Second
	DefaultJournalQueue    = 100_000
	DefaultJournalMaxAge   = 30 * 24 * time.Hour // как error_events (history.DefaultErrorAge)
	DefaultJournalPruneGap = 5 * time.Minute

	// journalCloseReason — mtg не сообщает причину закрытия.
	journalCloseReason = "closed"
)

type sessKey struct {
	secretID int64
	streamID string
}

type session struct {
	started  time.Time
	ip       netip.Addr
	dc       atomic.Int64
	bytesIn  atomic.Int64 // клиент → Telegram
	bytesOut atomic.Int64 // Telegram → клиент
}

// Journal — Observer, собирающий завершённые соединения в mtproto_sessions.
// Горячий путь (методы Observer) в БД не пишет и не блокируется: завершённые
// сессии попадают в ограниченную очередь, переполнение увеличивает Dropped().
// Поле агента в записи пустое: события mtg не сообщают, через какого агента идёт relay.
// Также реализует history.MTProtoCounters.
type Journal struct {
	Repo store.MTProtoSessionRepo
	Log  *slog.Logger
	// Flush — период батч-записи (0 → DefaultJournalFlush).
	Flush time.Duration
	// QueueCap — потолок очереди завершённых сессий (0 → DefaultJournalQueue).
	QueueCap int
	// MaxAge — срок хранения (0 → DefaultJournalMaxAge).
	MaxAge time.Duration
	// PruneEvery — период очистки (0 → DefaultJournalPruneGap).
	PruneEvery time.Duration
	// Now — источник времени (тесты).
	Now func() time.Time

	active   sync.Map // sessKey → *session
	nActive  atomic.Int64
	totalIn  atomic.Int64
	totalOut atomic.Int64
	dropped  atomic.Int64

	qmu   sync.Mutex
	queue []store.MTProtoSession

	flushMu sync.Mutex // сериализует flush: порядок записей и целостность Close
}

var _ Observer = (*Journal)(nil)

// NewJournal создаёт журнал над репозиторием.
func NewJournal(repo store.MTProtoSessionRepo, log *slog.Logger) *Journal {
	return &Journal{Repo: repo, Log: log}
}

func (j *Journal) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

func (j *Journal) logger() *slog.Logger {
	if j.Log != nil {
		return j.Log
	}
	return slog.Default()
}

func (j *Journal) queueCap() int {
	if j.QueueCap > 0 {
		return j.QueueCap
	}
	return DefaultJournalQueue
}

// Start — Observer.
func (j *Journal) Start(secretID int64, streamID string, ip netip.Addr) {
	s := &session{started: j.now(), ip: ip}
	if _, loaded := j.active.Swap(sessKey{secretID, streamID}, s); !loaded {
		j.nActive.Add(1)
	}
}

// ConnectedToDC — Observer.
func (j *Journal) ConnectedToDC(secretID int64, streamID string, dc int) {
	if v, ok := j.active.Load(sessKey{secretID, streamID}); ok {
		v.(*session).dc.Store(int64(dc))
	}
}

// Traffic — Observer.
func (j *Journal) Traffic(secretID int64, streamID string, n uint, fromTelegram bool) {
	d := int64(min(n, uint(1<<62))) //nolint:gosec // ограничено сверху
	if fromTelegram {
		j.totalOut.Add(d)
	} else {
		j.totalIn.Add(d)
	}
	v, ok := j.active.Load(sessKey{secretID, streamID})
	if !ok {
		return
	}
	s := v.(*session)
	if fromTelegram {
		s.bytesOut.Add(d)
	} else {
		s.bytesIn.Add(d)
	}
}

// Finish — Observer: сессия уходит в очередь записи.
func (j *Journal) Finish(secretID int64, streamID string) {
	v, ok := j.active.LoadAndDelete(sessKey{secretID, streamID})
	if !ok {
		return
	}
	j.nActive.Add(-1)
	s := v.(*session)
	rec := store.MTProtoSession{
		StartedAt:   s.started,
		EndedAt:     j.now(),
		SecretID:    secretID,
		DC:          int(s.dc.Load()),
		BytesIn:     s.bytesIn.Load(),
		BytesOut:    s.bytesOut.Load(),
		CloseReason: journalCloseReason,
	}
	if s.ip.IsValid() {
		rec.ClientIP = s.ip.String()
	}
	if rec.EndedAt.Before(rec.StartedAt) {
		rec.EndedAt = rec.StartedAt
	}
	j.qmu.Lock()
	if len(j.queue) >= j.queueCap() {
		j.qmu.Unlock()
		j.dropped.Add(1)
		return
	}
	j.queue = append(j.queue, rec)
	j.qmu.Unlock()
}

// ActiveConns — текущее число активных соединений.
func (j *Journal) ActiveConns() int64 { return j.nActive.Load() }

// TotalBytes — монотонные суммы байт: in — клиент → Telegram, out — Telegram → клиент.
func (j *Journal) TotalBytes() (in, out int64) { return j.totalIn.Load(), j.totalOut.Load() }

// Dropped — число сессий, потерянных из-за переполнения очереди или сбоя записи.
func (j *Journal) Dropped() int64 { return j.dropped.Load() }

// Pending — число сессий в очереди.
func (j *Journal) Pending() int {
	j.qmu.Lock()
	defer j.qmu.Unlock()
	return len(j.queue)
}

// FlushNow записывает накопленную очередь одним батчем. При ошибке записи пачка
// возвращается в очередь (в пределах потолка, остаток → Dropped).
func (j *Journal) FlushNow(ctx context.Context) error {
	j.flushMu.Lock()
	defer j.flushMu.Unlock()
	j.qmu.Lock()
	batch := j.queue
	j.queue = nil
	j.qmu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if err := j.Repo.InsertBatch(ctx, batch); err != nil {
		j.qmu.Lock()
		room := j.queueCap() - len(j.queue)
		if room < 0 {
			room = 0
		}
		keep := batch
		if len(keep) > room {
			j.dropped.Add(int64(len(keep) - room))
			keep = keep[:room]
		}
		j.queue = append(keep[:len(keep):len(keep)], j.queue...)
		j.qmu.Unlock()
		return err
	}
	return nil
}

// Prune удаляет сессии старше MaxAge.
func (j *Journal) Prune(ctx context.Context) (int, error) {
	age := j.MaxAge
	if age <= 0 {
		age = DefaultJournalMaxAge
	}
	return j.Repo.Prune(ctx, j.now().Add(-age))
}

// Run пишет очередь раз в Flush и чистит старое; после отмены ctx делает финальный сброс.
func (j *Journal) Run(ctx context.Context) {
	flush := j.Flush
	if flush <= 0 {
		flush = DefaultJournalFlush
	}
	pe := j.PruneEvery
	if pe <= 0 {
		pe = DefaultJournalPruneGap
	}
	ft, pt := time.NewTicker(flush), time.NewTicker(pe)
	defer ft.Stop()
	defer pt.Stop()
	for {
		select {
		case <-ft.C:
			if err := j.FlushNow(ctx); err != nil && ctx.Err() == nil {
				j.logger().Error("mtproto journal: flush", "err", err)
			}
		case <-pt.C:
			if _, err := j.Prune(ctx); err != nil && ctx.Err() == nil {
				j.logger().Error("mtproto journal: prune", "err", err)
			}
		case <-ctx.Done():
			if err := j.FlushNow(context.WithoutCancel(ctx)); err != nil {
				j.logger().Error("mtproto journal: final flush", "err", err)
			}
			return
		}
	}
}

// Close делает финальный сброс очереди (независимо от отмены Run).
func (j *Journal) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return j.FlushNow(ctx)
}
