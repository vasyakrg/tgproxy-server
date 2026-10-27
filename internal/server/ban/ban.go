// Package ban — встроенный fail2ban: блокировка IP по числу отказов доступа и ручные баны.
//
// Проверка бана идёт ДО access.Check и до агентов (Manager.Banned): забаненный клиент получает
// дешёвый 403 без разбора пути и без обращения к БД (кэш в памяти, инвалидация по версии
// таблицы bans — поэтому изменения из CLI подхватываются за секунды). Автобан считает отказы
// no_rule | key_required | bad_key скользящим окном в памяти (LRU, ограниченный по числу IP).
// Префикс бана: IPv4 — /32, IPv6 — /64 (клиент из /64 меняет адрес как перчатки).
package ban

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Значения по умолчанию внутренних периодов.
const (
	DefaultRefreshInterval = 2 * time.Second
	flushEvery             = 5 // тиков обновления между сбросами счётчиков попаданий в БД
	exemptFor              = time.Minute
	maxCommentLen          = 200
)

// MaxManualDuration — потолок срока ручного бана (бессрочный задаётся отдельно).
const MaxManualDuration = 365 * 24 * time.Hour

// Ошибки ручного бана.
var (
	// ErrBadAddr — адрес не разобран или не определён.
	ErrBadAddr = errors.New("ban: bad address")
	// ErrBadDuration — срок вне допустимых пределов.
	ErrBadDuration = errors.New("ban: bad duration")
	// ErrComment — слишком длинный комментарий.
	ErrComment = errors.New("ban: comment too long")
)

// ProtectedError — адрес нельзя банить (защита от самоблокировки).
type ProtectedError struct{ Reason string }

func (e *ProtectedError) Error() string { return "ban: protected address: " + e.Reason }

// Protector решает, что префикс банить нельзя. Пустая строка — можно.
type Protector interface {
	Protected(ctx context.Context, p netip.Prefix) string
}

// Options настраивают Manager.
type Options struct {
	Config          config.BanConfig
	Protect         Protector                    // nil — защиты нет
	OnAutoBan       func(b store.Ban, count int) // вызывается после успешного автобана; nil — не нужен
	Now             func() time.Time
	Log             *slog.Logger
	RefreshInterval time.Duration
	// Tick заменяет внутренний тикер Run (тесты).
	Tick <-chan time.Time
}

// PrefixOf возвращает префикс бана для адреса: IPv4 → /32, IPv6 → /64. Невалидный адрес → невалидный префикс.
func PrefixOf(a netip.Addr) netip.Prefix {
	if !a.IsValid() {
		return netip.Prefix{}
	}
	a = a.Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	return netip.PrefixFrom(a.WithZone(""), 64).Masked()
}

type entry struct {
	ban  store.Ban
	hits atomic.Int64 // непросохшие попадания (сбрасываются в БД)
}

type state struct {
	byPrefix map[netip.Prefix]*entry
	version  int64
}

// Manager — кэш банов и автобан.
type Manager struct {
	repo store.BanRepo
	o    Options
	cfg  config.BanConfig
	log  *slog.Logger
	now  func() time.Time

	st atomic.Pointer[state]
	mu sync.Mutex // сериализует Refresh/Flush

	tr *tracker
	wg sync.WaitGroup
}

// New создаёт Manager и сразу загружает баны.
func New(ctx context.Context, repo store.BanRepo, o Options) (*Manager, error) {
	m := &Manager{repo: repo, o: o, cfg: o.Config, log: o.Log, now: o.Now}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.o.RefreshInterval <= 0 {
		m.o.RefreshInterval = DefaultRefreshInterval
	}
	m.tr = newTracker(max(m.cfg.Threshold, 1), m.cfg.MaxTracked)
	m.st.Store(&state{byPrefix: map[netip.Prefix]*entry{}, version: -1})
	if err := m.Refresh(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// Banned сообщает, забанен ли адрес, и засчитывает попадание. Горячий путь: без блокировок и БД.
func (m *Manager) Banned(a netip.Addr) bool {
	p := PrefixOf(a)
	if !p.IsValid() {
		return false
	}
	e := m.st.Load().byPrefix[p]
	if e == nil || !e.ban.Active(m.now()) {
		return false
	}
	e.hits.Add(1)
	return true
}

// Record засчитывает отказ доступа адресу; при превышении порога выдаёт автобан (асинхронно).
// Причины, не входящие в учёт (rate_limited, banned), и выключенный автобан игнорируются.
func (m *Manager) Record(a netip.Addr, reason access.Reason) {
	if !m.cfg.Enabled || !reason.CountsForBan() {
		return
	}
	p := PrefixOf(a)
	if !p.IsValid() {
		return
	}
	n, fire := m.tr.hit(p, m.now(), m.cfg.Window, string(reason))
	if !fire {
		return
	}
	m.wg.Go(func() { m.autoBan(context.Background(), p, n) })
}

// Wait ждёт завершения фоновых автобанов (тесты, остановка).
func (m *Manager) Wait() { m.wg.Wait() }

func (m *Manager) duration(level int) time.Duration {
	if level <= 0 || len(m.cfg.Escalation) == 0 {
		return m.cfg.Duration
	}
	return m.cfg.Escalation[min(level, len(m.cfg.Escalation))-1]
}

func (m *Manager) autoBan(ctx context.Context, p netip.Prefix, count int) {
	defer m.tr.done(p)
	if m.o.Protect != nil {
		if why := m.o.Protect.Protected(ctx, p); why != "" {
			m.tr.exempt(p, m.now().Add(exemptFor))
			m.log.Warn("ban: autoban skipped, address is protected", "prefix", p.String(), "why", why, "denials", count)
			return
		}
	}
	now := m.now()
	level := 0
	prev, err := m.repo.GetByPrefix(ctx, p)
	switch {
	case err == nil:
		if prev.Active(now) {
			return // уже забанен (в том числе вручную): эскалировать нечего
		}
		last := prev.LastHitAt
		if prev.CreatedAt.After(last) {
			last = prev.CreatedAt
		}
		if now.Sub(last) <= m.cfg.ResetAfter {
			level = prev.Level + 1
		}
	case !errors.Is(err, store.ErrNotFound):
		m.log.Error("ban: autoban lookup failed", "prefix", p.String(), "err", err)
		return
	}
	level = min(level, max(len(m.cfg.Escalation), 0))
	exp := now.Add(m.duration(level))
	b, err := m.repo.Upsert(ctx, store.Ban{
		Prefix: p, Source: store.BanAuto, Actor: "auto", CreatedAt: now, ExpiresAt: &exp, Level: level,
		Comment: fmt.Sprintf("автобан: %d отказов за %s", count, m.cfg.Window),
	})
	if err != nil {
		m.log.Error("ban: autoban failed", "prefix", p.String(), "err", err)
		return
	}
	if err := m.Refresh(ctx); err != nil {
		m.log.Warn("ban: refresh after autoban failed", "err", err)
	}
	m.log.Warn("ban: autoban", "prefix", p.String(), "level", level, "until", exp.UTC().Format(time.RFC3339), "denials", count)
	if m.o.OnAutoBan != nil {
		m.o.OnAutoBan(b, count)
	}
}

// Refresh перечитывает баны, если версия в БД изменилась.
func (m *Manager) Refresh(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ver, err := m.repo.Version(ctx)
	if err != nil {
		return err
	}
	cur := m.st.Load()
	if ver == cur.version {
		return nil
	}
	list, err := m.repo.ListActive(ctx, m.now())
	if err != nil {
		return err
	}
	m.flushLocked(ctx, cur)
	next := &state{byPrefix: make(map[netip.Prefix]*entry, len(list)), version: ver}
	for _, b := range list {
		if old := cur.byPrefix[b.Prefix]; old != nil && sameBan(old.ban, b) {
			next.byPrefix[b.Prefix] = old
			continue
		}
		next.byPrefix[b.Prefix] = &entry{ban: b}
	}
	m.st.Store(next)
	return nil
}

func sameBan(a, b store.Ban) bool {
	if a.ID != b.ID || !a.CreatedAt.Equal(b.CreatedAt) {
		return false
	}
	if (a.ExpiresAt == nil) != (b.ExpiresAt == nil) {
		return false
	}
	return a.ExpiresAt == nil || a.ExpiresAt.Equal(*b.ExpiresAt)
}

// Flush сбрасывает накопленные попадания в БД.
func (m *Manager) Flush(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushLocked(ctx, m.st.Load())
}

func (m *Manager) flushLocked(ctx context.Context, s *state) {
	now := m.now()
	for _, e := range s.byPrefix {
		n := e.hits.Swap(0)
		if n == 0 {
			continue
		}
		if err := m.repo.AddHits(ctx, e.ban.ID, n, now); err != nil {
			e.hits.Add(n)
			m.log.Warn("ban: flush hits failed", "err", err)
			return
		}
	}
}

// Run обновляет кэш, сбрасывает счётчики и чистит устаревшие записи до отмены ctx.
func (m *Manager) Run(ctx context.Context) {
	tick := m.o.Tick
	if tick == nil {
		t := time.NewTicker(m.o.RefreshInterval)
		defer t.Stop()
		tick = t.C
	}
	var n int
	lastPrune := m.now()
	for {
		select {
		case <-ctx.Done():
			m.Flush(context.WithoutCancel(ctx))
			m.Wait()
			return
		case <-tick:
			if err := m.Refresh(ctx); err != nil {
				m.log.Warn("ban: refresh failed", "err", err)
			}
			if n++; n%flushEvery == 0 {
				m.Flush(ctx)
			}
			if now := m.now(); now.Sub(lastPrune) >= time.Hour {
				lastPrune = now
				if _, err := m.repo.Prune(ctx, now.Add(-m.cfg.ResetAfter)); err != nil {
					m.log.Warn("ban: prune failed", "err", err)
				}
			}
		}
	}
}

// AddRequest — ввод ручного бана.
type AddRequest struct {
	Addr      netip.Addr
	Duration  time.Duration // 0 при Permanent
	Permanent bool
	Comment   string
	Actor     string
}

// Add создаёт ручной бан. Защищённые адреса (прокси, агенты, сети правил, приватные) — *ProtectedError.
func (m *Manager) Add(ctx context.Context, r AddRequest) (store.Ban, error) {
	p := PrefixOf(r.Addr)
	if !p.IsValid() {
		return store.Ban{}, ErrBadAddr
	}
	if !r.Permanent && (r.Duration <= 0 || r.Duration > MaxManualDuration) {
		return store.Ban{}, ErrBadDuration
	}
	if len([]rune(r.Comment)) > maxCommentLen {
		return store.Ban{}, ErrComment
	}
	if m.o.Protect != nil {
		if why := m.o.Protect.Protected(ctx, p); why != "" {
			return store.Ban{}, &ProtectedError{Reason: why}
		}
	}
	now := m.now()
	b := store.Ban{Prefix: p, Source: store.BanManual, Actor: r.Actor, Comment: r.Comment, CreatedAt: now}
	if !r.Permanent {
		exp := now.Add(r.Duration)
		b.ExpiresAt = &exp
	}
	if prev, err := m.repo.GetByPrefix(ctx, p); err == nil {
		b.Level = prev.Level // память об эскалации не теряется
	}
	got, err := m.repo.Upsert(ctx, b)
	if err != nil {
		return store.Ban{}, err
	}
	m.tr.forget(p)
	if err := m.Refresh(ctx); err != nil {
		m.log.Warn("ban: refresh after add failed", "err", err)
	}
	return got, nil
}

// Remove снимает бан по id (store.ErrNotFound, если нет).
func (m *Manager) Remove(ctx context.Context, id int64) (store.Ban, error) {
	b, err := m.repo.Get(ctx, id)
	if err != nil {
		return store.Ban{}, err
	}
	if err := m.repo.Delete(ctx, id); err != nil {
		return store.Ban{}, err
	}
	m.tr.forget(b.Prefix)
	if err := m.Refresh(ctx); err != nil {
		m.log.Warn("ban: refresh after remove failed", "err", err)
	}
	return b, nil
}

// List возвращает действующие баны с актуальным счётчиком попаданий (включая ещё не сброшенные в БД).
func (m *Manager) List(ctx context.Context) ([]store.Ban, error) {
	list, err := m.repo.ListActive(ctx, m.now())
	if err != nil {
		return nil, err
	}
	s := m.st.Load()
	for i := range list {
		if e := s.byPrefix[list[i].Prefix]; e != nil && e.ban.ID == list[i].ID {
			list[i].Hits += e.hits.Load()
		}
	}
	return list, nil
}

// Active — число действующих банов в кэше.
func (m *Manager) Active() int {
	now, n := m.now(), 0
	for _, e := range m.st.Load().byPrefix {
		if e.ban.Active(now) {
			n++
		}
	}
	return n
}

// ---- скользящее окно с LRU ----

type tracked struct {
	key     netip.Prefix
	ts      []int64 // не более threshold последних отказов (UnixNano), кольцо
	head    int
	busy    bool // автобан в процессе
	exempt  time.Time
	lastWhy string
}

type tracker struct {
	mu        sync.Mutex
	threshold int
	maxItems  int
	ll        *list.List
	idx       map[netip.Prefix]*list.Element
}

func newTracker(threshold, maxItems int) *tracker {
	return &tracker{threshold: threshold, maxItems: max(maxItems, 1), ll: list.New(), idx: map[netip.Prefix]*list.Element{}}
}

// hit добавляет отказ. fire=true, если за окно набралось threshold отказов и бан ещё не запущен.
func (t *tracker) hit(p netip.Prefix, now time.Time, window time.Duration, why string) (count int, fire bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var it *tracked
	if el, ok := t.idx[p]; ok {
		t.ll.MoveToFront(el)
		it = el.Value.(*tracked)
	} else {
		it = &tracked{key: p}
		t.idx[p] = t.ll.PushFront(it)
		for t.ll.Len() > t.maxItems {
			last := t.ll.Back()
			delete(t.idx, last.Value.(*tracked).key)
			t.ll.Remove(last)
		}
	}
	if it.busy || now.Before(it.exempt) {
		return 0, false
	}
	it.lastWhy = why
	ns := now.UnixNano()
	if len(it.ts) < t.threshold {
		it.ts = append(it.ts, ns)
	} else {
		it.ts[it.head] = ns
		it.head = (it.head + 1) % t.threshold
	}
	if len(it.ts) < t.threshold {
		return 0, false
	}
	oldest := it.ts[it.head%len(it.ts)]
	if ns-oldest > int64(window) {
		return 0, false
	}
	it.busy = true
	it.ts, it.head = nil, 0
	return t.threshold, true
}

func (t *tracker) done(p netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.idx[p]; ok {
		el.Value.(*tracked).busy = false
	}
}

func (t *tracker) exempt(p netip.Prefix, until time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.idx[p]; ok {
		el.Value.(*tracked).exempt = until
	}
}

func (t *tracker) forget(p netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.idx[p]; ok {
		delete(t.idx, p)
		t.ll.Remove(el)
	}
}

// Tracked — сколько адресов сейчас отслеживается (тесты, диагностика).
func (m *Manager) Tracked() int {
	m.tr.mu.Lock()
	defer m.tr.mu.Unlock()
	return m.tr.ll.Len()
}
