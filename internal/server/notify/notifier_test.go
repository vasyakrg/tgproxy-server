package notify

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

func newNotifier(t *testing.T) (*Notifier, *memtest.Store, *fakeClock) {
	t.Helper()
	s := memtest.New()
	c := newClock()
	return NewNotifier(s.Outbox(), Options{Clock: c.Now}), s, c
}

func fire(n *Notifier, agent string) error {
	return n.Fire(context.Background(), Alert{Type: AgentDown, AgentID: agent, Severity: SeverityCritical, Title: "Агент " + agent + " недоступен"})
}

func TestFireRepeatSuppressedAt59Sent61(t *testing.T) {
	n, s, c := newNotifier(t)
	if err := fire(n, "fra-1"); err != nil {
		t.Fatal(err)
	}
	c.Add(59 * time.Minute)
	if err := fire(n, "fra-1"); err != nil {
		t.Fatal(err)
	}
	if got := len(pending(t, s)); got != 1 {
		t.Fatalf("after 59m: %d items, want 1", got)
	}
	c.Add(2 * time.Minute)
	if err := fire(n, "fra-1"); err != nil {
		t.Fatal(err)
	}
	if got := len(pending(t, s)); got != 2 {
		t.Fatalf("after 61m: %d items, want 2", got)
	}
}

func TestFireDifferentKeysIndependent(t *testing.T) {
	n, s, _ := newNotifier(t)
	_ = fire(n, "a")
	_ = fire(n, "b")
	if got := len(pending(t, s)); got != 2 {
		t.Fatalf("got %d, want 2", got)
	}
}

func TestResolveWithoutFiringIsSilent(t *testing.T) {
	n, s, _ := newNotifier(t)
	if err := n.Resolve(context.Background(), "agent_down:x"); err != nil {
		t.Fatal(err)
	}
	if got := len(pending(t, s)); got != 0 {
		t.Fatalf("got %d items", got)
	}
}

func TestResolveOnceAndRefireAfterResolve(t *testing.T) {
	n, s, _ := newNotifier(t)
	ctx := context.Background()
	_ = fire(n, "a")
	for range 3 {
		if err := n.Resolve(ctx, "agent_down:a"); err != nil {
			t.Fatal(err)
		}
	}
	items := pending(t, s)
	if len(items) != 2 || items[1].State != store.OutboxResolved {
		t.Fatalf("items = %+v", items)
	}
	if !strings.Contains(items[1].Text, "a") {
		t.Fatalf("resolved text %q", items[1].Text)
	}
	// после resolved новый firing проходит сразу, без ожидания часа
	_ = fire(n, "a")
	if got := len(pending(t, s)); got != 3 {
		t.Fatalf("got %d, want 3", got)
	}
}

func TestRateLimitCollapsesIntoDigest(t *testing.T) {
	n, s, c := newNotifier(t)
	ctx := context.Background()
	for i := range 25 {
		if err := fire(n, fmt.Sprintf("n%02d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(pending(t, s)); got != 19 {
		t.Fatalf("within minute: %d pending, want 19", got)
	}
	// состояние поглощённых алертов сохранено (дедуп работает)
	if it := all(t, s, "agent_down:n24"); it.State != store.OutboxFiring || it.SentAt == nil {
		t.Fatalf("absorbed item = %+v", it)
	}
	c.Add(61 * time.Second)
	if err := n.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	items := pending(t, s)
	if len(items) != 20 {
		t.Fatalf("total messages %d, want 20", len(items))
	}
	last := items[len(items)-1]
	if !strings.Contains(last.Text, "Сводка") || !strings.Contains(last.Text, "6") {
		t.Fatalf("digest = %q", last.Text)
	}
	if err := n.Flush(ctx); err != nil { // повторно сводка не создаётся
		t.Fatal(err)
	}
	if got := len(pending(t, s)); got != 20 {
		t.Fatalf("after second flush: %d", got)
	}
}

func TestDigestListTruncatedAndFlushedByNextFire(t *testing.T) {
	s := memtest.New()
	c := newClock()
	n := NewNotifier(s.Outbox(), Options{Clock: c.Now, MaxPerMinute: 2})
	for i := range 20 {
		_ = fire(n, fmt.Sprintf("n%02d", i))
	}
	c.Add(2 * time.Minute)
	_ = fire(n, "later") // Fire сам сбрасывает накопленную сводку
	items := pending(t, s)
	var digest *store.OutboxItem
	for i := range items {
		if items[i].DedupKey == "digest" {
			digest = &items[i]
		}
	}
	if digest == nil || !strings.Contains(digest.Text, "и ещё") {
		t.Fatalf("digest = %+v", digest)
	}
}

func TestResolveAbsorbedByRateLimit(t *testing.T) {
	s := memtest.New()
	c := newClock()
	n := NewNotifier(s.Outbox(), Options{Clock: c.Now, MaxPerMinute: 2})
	ctx := context.Background()
	_ = fire(n, "a") // прямое
	_ = fire(n, "b") // поглощено
	if err := n.Resolve(ctx, "agent_down:b"); err != nil {
		t.Fatal(err)
	}
	if it := all(t, s, "agent_down:b"); it.State != store.OutboxResolved {
		t.Fatalf("state = %s", it.State)
	}
}

type failingOutbox struct {
	store.OutboxRepo
	last, enq, sent bool
}

func (f failingOutbox) LastByKey(ctx context.Context, k string) (store.OutboxItem, error) {
	if f.last {
		return store.OutboxItem{}, errors.New("db")
	}
	return f.OutboxRepo.LastByKey(ctx, k)
}
func (f failingOutbox) Enqueue(ctx context.Context, it store.OutboxItem) (store.OutboxItem, error) {
	if f.enq {
		return store.OutboxItem{}, errors.New("db")
	}
	return f.OutboxRepo.Enqueue(ctx, it)
}
func (f failingOutbox) MarkSent(ctx context.Context, id int64, at time.Time) error {
	if f.sent {
		return errors.New("db")
	}
	return f.OutboxRepo.MarkSent(ctx, id, at)
}

func TestStoreErrorsPropagate(t *testing.T) {
	ctx := context.Background()
	base := memtest.New().Outbox()
	n := NewNotifier(failingOutbox{OutboxRepo: base, last: true}, Options{})
	if fire(n, "a") == nil || n.Resolve(ctx, "k") == nil {
		t.Fatal("LastByKey error must propagate")
	}
	n = NewNotifier(failingOutbox{OutboxRepo: base, enq: true}, Options{})
	if fire(n, "a") == nil {
		t.Fatal("Enqueue error must propagate")
	}
	n = NewNotifier(failingOutbox{OutboxRepo: base, sent: true}, Options{MaxPerMinute: 1})
	_ = fire(n, "x") // direct()=1
	if fire(n, "y") == nil {
		t.Fatal("MarkSent error must propagate")
	}
	// ошибка Enqueue сводки
	s := memtest.New()
	c := newClock()
	fo := &flipOutbox{OutboxRepo: s.Outbox()}
	n = NewNotifier(fo, Options{Clock: c.Now, MaxPerMinute: 1})
	_ = fire(n, "x")
	_ = fire(n, "y")
	c.Add(2 * time.Minute)
	fo.failDigest = true
	if n.Flush(ctx) == nil {
		t.Fatal("digest enqueue error must propagate")
	}
}

type flipOutbox struct {
	store.OutboxRepo
	failDigest bool
}

func (f *flipOutbox) Enqueue(ctx context.Context, it store.OutboxItem) (store.OutboxItem, error) {
	if f.failDigest && it.DedupKey == digestKey {
		return store.OutboxItem{}, errors.New("db")
	}
	return f.OutboxRepo.Enqueue(ctx, it)
}

var tokenRe = regexp.MustCompile(`[0-9]{5,15}:[A-Za-z0-9_-]{30,}`)

func TestAlertTextHasNoTokens(t *testing.T) {
	n, s, _ := newNotifier(t)
	err := n.Fire(context.Background(), Alert{
		Type: AgentDown, AgentID: "a", Title: "bot " + testToken,
		Text: "ошибка https://api.telegram.org/bot" + testToken + "/sendMessage <b>",
	})
	if err != nil {
		t.Fatal(err)
	}
	txt := pending(t, s)[0].Text
	if tokenRe.MatchString(txt) || strings.Contains(txt, "AAEhBOweik") {
		t.Fatalf("token leaked: %q", txt)
	}
	if strings.Contains(txt, "<b>\n") || !strings.Contains(txt, "&lt;b&gt;") {
		t.Fatalf("html not escaped: %q", txt)
	}
}

func TestAlertKeyAndIcons(t *testing.T) {
	if AlertKey(AllAgentsDown, "") != "all_agents_down" || AlertKey(AgentDown, "x") != "agent_down:x" {
		t.Fatal("AlertKey")
	}
	a := Alert{Type: Overload, AgentID: "z"}
	if a.key() != "overload:z" || headline(a) != "overload" {
		t.Fatal("key/headline")
	}
	for _, s := range []Severity{SeverityCritical, SeverityInfo, SeverityWarning, ""} {
		if icon(s) == "" {
			t.Fatal("icon")
		}
	}
	for _, ty := range []AlertType{AgentDown, AgentDegraded, Overload, CertExpiring, IngressCertExpiring, IngressCertInvalid, VersionMismatch, AllAgentsDown, LoginLockout} {
		if resolvedTitle(ty, "x") == "" {
			t.Fatal(ty)
		}
	}
	if resolvedTitle(AgentDown, "") == "" {
		t.Fatal("no agent")
	}
}

func TestInternalContext(t *testing.T) {
	ctx := context.Background()
	if IsInternal(ctx) || !IsInternal(InternalContext(ctx)) {
		t.Fatal("internal flag")
	}
}
