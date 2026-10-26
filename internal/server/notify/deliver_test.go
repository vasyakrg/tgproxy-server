package notify

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type fixture struct {
	d     *Deliverer
	s     *memtest.Store
	n     *Notifier
	snd   *fakeSender
	clock *fakeClock
	m     *fakeMetrics
	rc    []Recipient
}

func newFixture(t *testing.T, mut ...func(*DeliverOptions)) *fixture {
	t.Helper()
	f := &fixture{s: memtest.New(), snd: &fakeSender{}, clock: newClock(), m: &fakeMetrics{},
		rc: []Recipient{{User: "admin", TelegramID: 111}}}
	f.n = NewNotifier(f.s.Outbox(), Options{Clock: f.clock.Now})
	o := DeliverOptions{
		Outbox: f.s.Outbox(), Sender: f.snd, Token: testToken, Metrics: f.m, Clock: f.clock.Now,
		Load:    func() ([]Recipient, error) { return f.rc, nil },
		Backoff: time.Minute, Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	for _, m := range mut {
		m(&o)
	}
	f.d = NewDeliverer(o)
	return f
}

func TestDeliverSendsToAllRecipients(t *testing.T) {
	f := newFixture(t)
	f.rc = []Recipient{{"a", 111}, {"b", 222}}
	_ = fire(f.n, "x")
	n, err := f.d.DeliverOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if f.snd.count() != 2 {
		t.Fatalf("calls = %d", f.snd.count())
	}
	c := f.snd.calls[0]
	if !IsInternal(c.ctx) {
		t.Fatal("request must carry internal mark")
	}
	if c.route.Method != "sendmessage" || c.route.Token != testToken {
		t.Fatalf("route = %+v", c.route)
	}
	for _, want := range []string{`"parse_mode":"HTML"`, `"disable_web_page_preview":true`, `"chat_id":111`} {
		if !strings.Contains(c.body, want) {
			t.Fatalf("body %s lacks %s", c.body, want)
		}
	}
	if got := len(pending(t, f.s)); got != 0 {
		t.Fatalf("still pending: %d", got)
	}
	if n, _ := f.d.DeliverOnce(context.Background()); n != 0 || f.snd.count() != 2 {
		t.Fatal("must not resend")
	}
}

func TestNoAgentsAccumulatesThenDelivers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.snd.err = errors.New("tgproxy: no healthy agents: " + testToken)
	_ = fire(f.n, "x")
	if n, _ := f.d.DeliverOnce(ctx); n != 0 {
		t.Fatal("delivered without agents")
	}
	if f.m.count() != 1 {
		t.Fatalf("undeliverable = %d", f.m.count())
	}
	it := pending(t, f.s)
	if len(it) != 1 || it[0].Attempts != 1 || strings.Contains(it[0].LastError, "AAEhBOweik") {
		t.Fatalf("items = %+v", it)
	}
	// backoff: сразу повторно не пытаемся
	_, _ = f.d.DeliverOnce(ctx)
	if f.snd.count() != 1 {
		t.Fatalf("retried inside backoff: %d calls", f.snd.count())
	}
	// агент появился
	f.snd.err = nil
	f.clock.Add(61 * time.Second)
	if n, _ := f.d.DeliverOnce(ctx); n != 1 {
		t.Fatal("not delivered after agents appeared")
	}
	if len(pending(t, f.s)) != 0 {
		t.Fatal("still pending")
	}
}

func TestBackoffGrowsExponentially(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.snd.status = http.StatusBadGateway
	_ = fire(f.n, "x")
	_, _ = f.d.DeliverOnce(ctx) // attempt 1 → +1m
	f.clock.Add(61 * time.Second)
	_, _ = f.d.DeliverOnce(ctx) // attempt 2 → +2m
	f.clock.Add(61 * time.Second)
	_, _ = f.d.DeliverOnce(ctx)
	if f.snd.count() != 2 {
		t.Fatalf("calls = %d, want 2 (third inside 2m backoff)", f.snd.count())
	}
	f.clock.Add(61 * time.Second)
	_, _ = f.d.DeliverOnce(ctx)
	if f.snd.count() != 3 {
		t.Fatalf("calls = %d, want 3", f.snd.count())
	}
}

func TestNoRecipientsIsUndeliverable(t *testing.T) {
	f := newFixture(t)
	f.rc = nil
	_ = fire(f.n, "x")
	_, _ = f.d.DeliverOnce(context.Background())
	if f.snd.count() != 0 || f.m.count() != 1 || len(pending(t, f.s)) != 1 {
		t.Fatal("no recipients must keep alert pending")
	}
}

func TestRecipientsLoadErrorAndReload(t *testing.T) {
	f := newFixture(t)
	fail := true
	f.d.o.Load = func() ([]Recipient, error) {
		if fail {
			return nil, errors.New("boom")
		}
		return f.rc, nil
	}
	_ = fire(f.n, "x")
	_, _ = f.d.DeliverOnce(context.Background())
	if f.m.count() != 1 {
		t.Fatal("load error must count as undeliverable")
	}
	fail = false
	if err := f.d.Reload(); err != nil {
		t.Fatal(err)
	}
	f.clock.Add(2 * time.Minute)
	if n, _ := f.d.DeliverOnce(context.Background()); n != 1 {
		t.Fatal("not delivered after reload")
	}
	fail = true
	if f.d.Reload() == nil {
		t.Fatal("Reload must return error")
	}
}

func TestPermanentRejectionDropsAlert(t *testing.T) {
	f := newFixture(t)
	f.snd.status = http.StatusForbidden
	_ = fire(f.n, "x")
	_, _ = f.d.DeliverOnce(context.Background())
	if len(pending(t, f.s)) != 0 || f.m.count() != 0 {
		t.Fatal("403 is permanent: no retry, no undeliverable")
	}
}

func TestPartialDeliveryMarksSent(t *testing.T) {
	f := newFixture(t)
	f.rc = []Recipient{{"a", 111}, {"b", 222}}
	f.snd.perID = map[string]int{`"chat_id":222`: http.StatusTooManyRequests}
	_ = fire(f.n, "x")
	if n, _ := f.d.DeliverOnce(context.Background()); n != 1 || len(pending(t, f.s)) != 0 {
		t.Fatal("partial delivery counts as sent")
	}
}

func TestBadResponses(t *testing.T) {
	for name, tc := range map[string]*fakeSender{
		"200 not ok":  {body: `{"ok":false}`},
		"200 garbage": {body: `not json`},
		"500":         {status: 500},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.snd = tc
			f.d.o.Sender = tc
			_ = fire(f.n, "x")
			_, _ = f.d.DeliverOnce(context.Background())
			if len(pending(t, f.s)) != 1 || f.m.count() != 1 {
				t.Fatal("must stay pending")
			}
		})
	}
}

func TestInvalidTokenIsPermanent(t *testing.T) {
	f := newFixture(t, func(o *DeliverOptions) { o.Token = "bad" })
	_ = fire(f.n, "x")
	_, _ = f.d.DeliverOnce(context.Background())
	if f.snd.count() != 0 || len(pending(t, f.s)) != 0 {
		t.Fatal("invalid token must not hit the sender")
	}
}

func TestStaleAlertDropped(t *testing.T) {
	f := newFixture(t)
	f.rc = nil
	_ = fire(f.n, "x")
	f.clock.Add(25 * time.Hour)
	_, _ = f.d.DeliverOnce(context.Background())
	if len(pending(t, f.s)) != 0 || f.snd.count() != 0 {
		t.Fatal("stale alert must be dropped without sending")
	}
}

func TestBatchLimit(t *testing.T) {
	f := newFixture(t, func(o *DeliverOptions) { o.Batch = 2 })
	for _, a := range []string{"a", "b", "c"} {
		_ = fire(f.n, a)
	}
	if n, _ := f.d.DeliverOnce(context.Background()); n != 2 {
		t.Fatalf("n = %d", n)
	}
}

func TestRunDeliversAndStops(t *testing.T) {
	f := newFixture(t, func(o *DeliverOptions) { o.Poll = time.Hour })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.d.Run(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for f.snd.count() == 0 {
		_ = fire(f.n, "x")
		f.d.Wake()
		f.d.Wake()
		select {
		case <-deadline:
			t.Fatal("not delivered by Run")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

type errPending struct{ store.OutboxRepo }

func (errPending) Pending(context.Context, int) ([]store.OutboxItem, error) {
	return nil, errors.New("db")
}

func TestPendingErrorAndRunLogs(t *testing.T) {
	d := NewDeliverer(DeliverOptions{Outbox: errPending{memtest.New().Outbox()}, Sender: &fakeSender{}, Poll: time.Millisecond, Logger: slog.New(slog.DiscardHandler)})
	if _, err := d.DeliverOnce(context.Background()); err == nil {
		t.Fatal("want error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	d.Run(ctx) // не паникует, выходит по ctx
}

type errMark struct {
	store.OutboxRepo
	mark, rec bool
}

func (e errMark) MarkSent(ctx context.Context, id int64, at time.Time) error {
	if e.mark {
		return errors.New("db")
	}
	return e.OutboxRepo.MarkSent(ctx, id, at)
}
func (e errMark) RecordAttempt(ctx context.Context, id int64, s string) error {
	if e.rec {
		return errors.New("db")
	}
	return e.OutboxRepo.RecordAttempt(ctx, id, s)
}

func TestMarkErrorsPropagate(t *testing.T) {
	for name, em := range map[string]func(store.OutboxRepo) errMark{
		"mark": func(o store.OutboxRepo) errMark { return errMark{OutboxRepo: o, mark: true} },
		"rec":  func(o store.OutboxRepo) errMark { return errMark{OutboxRepo: o, rec: true} },
	} {
		t.Run(name, func(t *testing.T) {
			s := memtest.New()
			n := NewNotifier(s.Outbox(), Options{})
			_ = fire(n, "x")
			snd := &fakeSender{}
			if name == "rec" {
				snd.status = 500
			}
			d := NewDeliverer(DeliverOptions{Outbox: em(s.Outbox()), Sender: snd, Token: testToken,
				Load: func() ([]Recipient, error) { return []Recipient{{"a", 1}}, nil }})
			if _, err := d.DeliverOnce(context.Background()); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestLoadRecipients(t *testing.T) {
	p := filepath.Join(t.TempDir(), "users.yml")
	yml := `users:
  zed:
    displayname: Z
    password: '$argon2id$v=19$m=65536,t=3,p=4$x$y'
    email: z@example.test
    telegram_id: 222
  admin:
    password: secret
    telegram_id: 111
  nobody:
    telegram_id: 0
  silent:
    email: s@example.test
  off:
    telegram_id: 333
    disabled: true
`
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRecipients(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (Recipient{"admin", 111}) || got[1] != (Recipient{"zed", 222}) {
		t.Fatalf("got %+v", got)
	}
	if _, err := LoadRecipients(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("missing file")
	}
	bad := filepath.Join(t.TempDir(), "bad.yml")
	_ = os.WriteFile(bad, []byte("users: [1"), 0o600)
	if _, err := LoadRecipients(bad); err == nil {
		t.Fatal("bad yaml")
	}
	big := filepath.Join(t.TempDir(), "big.yml")
	_ = os.WriteFile(big, []byte(strings.Repeat("#", maxUsersFile+1)), 0o600)
	if _, err := LoadRecipients(big); err == nil {
		t.Fatal("too large")
	}
	if _, err := LoadRecipients(t.TempDir()); err == nil {
		t.Fatal("dir")
	}
}

func TestLoadRecipientsDevUsers(t *testing.T) {
	got, err := LoadRecipients("../../../dev/users.yml")
	if err != nil || len(got) != 0 { // telegram_id: 0 → пропущен
		t.Fatalf("got %+v err %v", got, err)
	}
}
