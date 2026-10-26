package notify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

func TestDisabledTypeIsNotQueued(t *testing.T) {
	s := memtest.New()
	tg := NewToggles(s.Settings())
	n := NewNotifier(s.Outbox(), Options{Clock: newClock().Now, Enabled: tg.Enabled})
	ctx := context.Background()
	if err := tg.Set(ctx, map[AlertType]bool{AgentDegraded: false}); err != nil {
		t.Fatal(err)
	}
	_ = n.Fire(ctx, Alert{Type: AgentDegraded, AgentID: "a", Title: "x"})
	if got := len(pending(t, s)); got != 0 {
		t.Fatalf("выключенный тип попал в outbox: %d", got)
	}
	_ = n.Fire(ctx, Alert{Type: AgentDown, AgentID: "a", Title: "x"})
	if got := len(pending(t, s)); got != 1 {
		t.Fatalf("включённый тип: %d сообщений, want 1", got)
	}
	// включили обратно — снова уходит
	if err := tg.Set(ctx, map[AlertType]bool{AgentDegraded: true}); err != nil {
		t.Fatal(err)
	}
	_ = n.Fire(ctx, Alert{Type: AgentDegraded, AgentID: "a", Title: "x"})
	if got := len(pending(t, s)); got != 2 {
		t.Fatalf("после включения: %d, want 2", got)
	}
}

func TestResolveSkippedForDisabledType(t *testing.T) {
	s := memtest.New()
	tg := NewToggles(s.Settings())
	n := NewNotifier(s.Outbox(), Options{Clock: newClock().Now, Enabled: tg.Enabled})
	ctx := context.Background()
	_ = n.Fire(ctx, Alert{Type: AgentDown, AgentID: "a", Title: "x"})
	if err := tg.Set(ctx, map[AlertType]bool{AgentDown: false}); err != nil {
		t.Fatal(err)
	}
	if err := n.Resolve(ctx, AlertKey(AgentDown, "a")); err != nil {
		t.Fatal(err)
	}
	if got := len(pending(t, s)); got != 1 {
		t.Fatalf("resolved выключенного типа не должен уходить: %d", got)
	}
}

func TestTogglesPersistAndValidate(t *testing.T) {
	s := memtest.New()
	ctx := context.Background()
	tg := NewToggles(s.Settings())
	st, err := tg.States(ctx)
	if err != nil || !st[AgentDown] || !st[AgentEnrolled] || len(st) != len(Catalog()) {
		t.Fatalf("по умолчанию все включены: %v %v", st, err)
	}
	if err := tg.Set(ctx, map[AlertType]bool{Overload: false, AgentEnrolled: false}); err != nil {
		t.Fatal(err)
	}
	// новый экземпляр читает из хранилища
	tg2 := NewToggles(s.Settings())
	if tg2.Enabled(ctx, Overload) || tg2.Enabled(ctx, AgentEnrolled) || !tg2.Enabled(ctx, AgentDown) {
		t.Fatal("настройки не сохранились")
	}
	if err := tg2.Set(ctx, map[AlertType]bool{"bogus": false}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("неизвестный тип: %v", err)
	}
	// Set не трогает типы, которых нет в карте
	if err := tg2.Set(ctx, map[AlertType]bool{AgentDown: false}); err != nil {
		t.Fatal(err)
	}
	if tg2.Enabled(ctx, AgentDown) || tg2.Enabled(ctx, Overload) {
		t.Fatal("частичное обновление сбросило остальные типы")
	}
	if !KnownType(AllAgentsDown) || KnownType("x") {
		t.Fatal("KnownType")
	}
}

type failingSettings struct{ store.SettingsRepo }

func (failingSettings) Get(context.Context, string) (string, error) { return "", errors.New("db down") }

func TestTogglesFailOpen(t *testing.T) {
	tg := NewToggles(failingSettings{})
	if !tg.Enabled(context.Background(), AgentDown) {
		t.Fatal("при ошибке чтения алерты не должны теряться")
	}
	if _, err := tg.States(context.Background()); err == nil {
		t.Fatal("States должен вернуть ошибку")
	}
	if err := tg.Set(context.Background(), map[AlertType]bool{AgentDown: false}); err == nil {
		t.Fatal("Set должен вернуть ошибку")
	}
}

func TestSendTestQueuesAndDelivers(t *testing.T) {
	f := newFixture(t)
	f.n = NewNotifier(f.s.Outbox(), Options{Clock: f.clock.Now,
		Enabled: func(context.Context, AlertType) bool { return false }}) // фильтр типов тест не отключает
	ctx := context.Background()
	if err := f.n.SendTest(ctx, "ad<m>in"); err != nil {
		t.Fatal(err)
	}
	if err := f.n.SendTest(ctx, ""); err != nil {
		t.Fatal(err)
	}
	items := pending(t, f.s)
	if len(items) != 2 || items[0].Type != TestType || items[0].State != store.OutboxFiring {
		t.Fatalf("outbox: %+v", items)
	}
	if items[0].DedupKey == items[1].DedupKey {
		t.Fatal("тесты не должны дедуплицироваться")
	}
	if !strings.Contains(items[0].Text, "ad&lt;m&gt;in") {
		t.Fatalf("актор не экранирован: %q", items[0].Text)
	}
	n, err := f.d.DeliverOnce(ctx)
	if err != nil || n != 2 || f.snd.count() != 2 {
		t.Fatalf("доставлено %d, отправок %d, err=%v", n, f.snd.count(), err)
	}
}
