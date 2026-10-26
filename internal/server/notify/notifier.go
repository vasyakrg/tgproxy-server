package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const (
	defaultRepeat       = time.Hour
	defaultMaxPerMinute = 20
	rateWindow          = time.Minute
	digestKey           = "digest"
	digestListMax       = 10
)

// Options — параметры Notifier.
type Options struct {
	RepeatInterval time.Duration // повтор firing того же ключа; 0 → 1ч
	MaxPerMinute   int           // глобальный лимит сообщений; 0 → 20
	Clock          Clock
	Logger         *slog.Logger
}

// Notifier применяет правила дедупа/лимитов и пишет алерты в outbox.
//
// Состояние firing/resolved хранится в outbox (LastByKey), поэтому переживает
// рестарт. Алерты сверх лимита записываются в outbox как уже обработанные
// (состояние не теряется), а их суть уходит одним сообщением-сводкой.
type Notifier struct {
	outbox  store.OutboxRepo
	repeat  time.Duration
	maxPM   int
	clock   Clock
	log     *slog.Logger
	mu      sync.Mutex
	sentAt  []time.Time // моменты постановки сообщений в окне лимита
	overrun []string    // строки сводки
}

// NewNotifier создаёт Notifier.
func NewNotifier(outbox store.OutboxRepo, o Options) *Notifier {
	n := &Notifier{outbox: outbox, repeat: o.RepeatInterval, maxPM: o.MaxPerMinute, clock: o.Clock, log: o.Logger}
	if n.repeat <= 0 {
		n.repeat = defaultRepeat
	}
	if n.maxPM <= 0 {
		n.maxPM = defaultMaxPerMinute
	}
	if n.clock == nil {
		n.clock = time.Now
	}
	if n.log == nil {
		n.log = slog.Default()
	}
	return n
}

// Fire ставит алерт в очередь. Повтор того же ключа допускается не чаще
// RepeatInterval; после resolved ключ снова «свободен».
func (n *Notifier) Fire(ctx context.Context, a Alert) error {
	key := a.key()
	now := n.clock()
	n.mu.Lock()
	defer n.mu.Unlock()

	last, err := n.outbox.LastByKey(ctx, key)
	switch {
	case err == nil:
		if last.State == store.OutboxFiring && now.Sub(last.CreatedAt) < n.repeat {
			return nil // дедуп
		}
	case !errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("notify: last by key: %w", err)
	}
	text := formatAlert(a)
	return n.enqueueLocked(ctx, now, store.OutboxItem{
		DedupKey: key, AgentID: a.AgentID, Type: string(a.Type),
		State: store.OutboxFiring, Text: text, CreatedAt: now,
	}, headline(a))
}

// Resolve шлёт «восстановлено» один раз и только если ключ был в firing.
func (n *Notifier) Resolve(ctx context.Context, key string) error {
	now := n.clock()
	n.mu.Lock()
	defer n.mu.Unlock()

	last, err := n.outbox.LastByKey(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("notify: last by key: %w", err)
	}
	if last.State != store.OutboxFiring {
		return nil
	}
	title := resolvedTitle(AlertType(last.Type), last.AgentID)
	return n.enqueueLocked(ctx, now, store.OutboxItem{
		DedupKey: key, AgentID: last.AgentID, Type: last.Type,
		State: store.OutboxResolved, Text: "✅ " + escapeHTML(title), CreatedAt: now,
	}, title)
}

// Flush формирует сводку по отброшенным лимитом алертам, когда окно лимита
// освободилось. Вызывается Evaluator-ом по тикеру и из Fire/Resolve.
func (n *Notifier) Flush(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.flushLocked(ctx, n.clock())
}

func (n *Notifier) prune(now time.Time) {
	i := 0
	for i < len(n.sentAt) && now.Sub(n.sentAt[i]) >= rateWindow {
		i++
	}
	n.sentAt = n.sentAt[i:]
}

// direct — сколько обычных сообщений допускается в окне: один слот резервируется под сводку.
func (n *Notifier) direct() int { return max(n.maxPM-1, 1) }

func (n *Notifier) enqueueLocked(ctx context.Context, now time.Time, it store.OutboxItem, line string) error {
	if err := n.flushLocked(ctx, now); err != nil {
		return err
	}
	n.prune(now)
	saved, err := n.outbox.Enqueue(ctx, it)
	if err != nil {
		return fmt.Errorf("notify: enqueue: %w", err)
	}
	if len(n.sentAt) < n.direct() {
		n.sentAt = append(n.sentAt, now)
		return nil
	}
	// лимит исчерпан: состояние сохранено, доставка заменена сводкой
	if err := n.outbox.MarkSent(ctx, saved.ID, now); err != nil {
		return fmt.Errorf("notify: absorb: %w", err)
	}
	n.overrun = append(n.overrun, line)
	return nil
}

func (n *Notifier) flushLocked(ctx context.Context, now time.Time) error {
	n.prune(now)
	if len(n.overrun) == 0 || len(n.sentAt) >= n.direct() {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "📦 <b>Сводка</b>: ещё алертов за период — %d", len(n.overrun))
	for i, l := range n.overrun {
		if i == digestListMax {
			fmt.Fprintf(&b, "\n… и ещё %d", len(n.overrun)-digestListMax)
			break
		}
		b.WriteString("\n• " + escapeHTML(redact.String(l)))
	}
	if _, err := n.outbox.Enqueue(ctx, store.OutboxItem{
		DedupKey: digestKey, Type: digestKey, State: store.OutboxFiring, Text: b.String(), CreatedAt: now,
	}); err != nil {
		return fmt.Errorf("notify: enqueue digest: %w", err)
	}
	n.sentAt = append(n.sentAt, now)
	n.overrun = nil
	return nil
}
