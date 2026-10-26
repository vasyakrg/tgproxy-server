package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type admins map[string]auth.User

func (a admins) Names() []string {
	out := make([]string, 0, len(a))
	for n := range a {
		out = append(out, n)
	}
	// детерминированный порядок
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
func (a admins) Get(n string) (auth.User, bool) { u, ok := a[n]; return u, ok }

type notifEnv struct {
	mux   *http.ServeMux
	st    *memtest.Store
	svc   *api.NotificationsService
	clock *time.Time
	woke  *atomic.Int32
}

func newNotif(t *testing.T, wrap api.Wrap, mut func(*api.NotificationsConfig)) *notifEnv {
	t.Helper()
	st := memtest.New()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	tg := notify.NewToggles(st.Settings())
	n := notify.NewNotifier(st.Outbox(), notify.Options{Enabled: tg.Enabled})
	var woke atomic.Int32
	cfg := api.NotificationsConfig{
		Sender: n, BotID: "7012345678", Toggles: tg, Audit: st.Audit(), Outbox: st.Outbox(),
		Admins: admins{
			"alice": {TelegramID: 111, TOTPSecretEnc: "enc"},
			"bob":   {TelegramID: 0, Disabled: true},
		},
		Wake: func() { woke.Add(1) },
	}
	e := &notifEnv{st: st, clock: &now, woke: &woke}
	cfg.Now = func() time.Time { return *e.clock }
	if mut != nil {
		mut(&cfg)
	}
	e.svc = api.NewNotificationsService(cfg)
	e.mux = http.NewServeMux()
	(&api.NotificationsAPI{Service: e.svc}).Routes(e.mux, wrap)
	return e
}

func (e *notifEnv) do(method, url, body string) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, url, rd)
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func TestNotificationsInfo(t *testing.T) {
	e := newNotif(t, nil, nil)
	login := time.Date(2026, 2, 28, 9, 0, 0, 0, time.UTC)
	for _, a := range []store.AuditEntry{
		{At: login.Add(-time.Hour), Actor: "alice", Action: auth.AuditLoginOK},
		{At: login, Actor: "alice", Action: auth.AuditLoginOK},
		{At: login.Add(time.Hour), Actor: "alice", Action: auth.AuditLoginFail},
		{At: login, Actor: "bob", Action: auth.AuditLoginFail},
	} {
		if _, err := e.st.Audit().Append(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = e.st.Outbox().Enqueue(context.Background(), store.OutboxItem{DedupKey: "k", Type: "agent_down", State: store.OutboxFiring})
	rec := e.do("GET", "/api/v1/notifications", "")
	var info api.NotificationsInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil || rec.Code != 200 {
		t.Fatalf("%d %v %s", rec.Code, err, rec.Body)
	}
	if !info.Enabled || info.BotID != "7012345678" || info.Pending != 1 || len(info.Admins) != 2 {
		t.Fatalf("info: %+v", info)
	}
	a, b := info.Admins[0], info.Admins[1]
	if a.Name != "alice" || !a.TOTP || a.TelegramID != 111 || a.LastLogin != login.Format(time.RFC3339) {
		t.Fatalf("alice: %+v", a)
	}
	if b.Name != "bob" || b.TOTP || !b.Disabled || b.LastLogin != "" {
		t.Fatalf("bob: %+v", b)
	}
	if len(info.Events) != len(notify.Catalog()) {
		t.Fatalf("events: %d", len(info.Events))
	}
	for _, ev := range info.Events {
		if !ev.Enabled || ev.Title == "" {
			t.Fatalf("по умолчанию всё включено: %+v", ev)
		}
	}
	if strings.Contains(rec.Body.String(), "enc") && strings.Contains(rec.Body.String(), "totp_secret") {
		t.Fatal("секрет TOTP в ответе")
	}
}

func TestNotificationsPutTogglesAndDisabledNotSent(t *testing.T) {
	e := newNotif(t, nil, nil)
	rec := e.do("PUT", "/api/v1/notifications", `{"events":{"overload":false,"agent_enrolled":false}}`)
	if rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	var info api.NotificationsInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	off := map[string]bool{}
	for _, ev := range info.Events {
		if !ev.Enabled {
			off[ev.Type] = true
		}
	}
	if len(off) != 2 || !off["overload"] || !off["agent_enrolled"] {
		t.Fatalf("выключены: %v", off)
	}
	if !strings.Contains(auditActions(t, e.st), "notifications.update") {
		t.Fatal("нет записи аудита")
	}
	for _, bad := range []string{`{"events":{"nope":true}}`, `{"events":1}`, `{"x":1}`} {
		if rec = e.do("PUT", "/api/v1/notifications", bad); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	if rec = e.do("PUT", "/api/v1/notifications", `{"events":{"nope":true}}`); rec.Code != 422 {
		t.Fatalf("неизвестный тип: %d %s", rec.Code, rec.Body)
	}
}

func TestNotificationsTestGoesToOutboxAndIsThrottled(t *testing.T) {
	e := newNotif(t, nil, nil)
	rec := e.do("POST", "/api/v1/notifications/test", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("test: %d %s", rec.Code, rec.Body)
	}
	items, _ := e.st.Outbox().Pending(context.Background(), 10)
	if len(items) != 1 || items[0].Type != notify.TestType {
		t.Fatalf("outbox: %+v", items)
	}
	if e.woke.Load() != 1 {
		t.Fatal("доставка не разбужена")
	}
	if rec = e.do("POST", "/api/v1/notifications/test", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("повтор сразу: %d", rec.Code)
	}
	*e.clock = e.clock.Add(11 * time.Second)
	if rec = e.do("POST", "/api/v1/notifications/test", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("через 11 с: %d", rec.Code)
	}
	if !strings.Contains(auditActions(t, e.st), "notifications.test") {
		t.Fatal("нет записи аудита")
	}
}

type failingSender struct{}

func (failingSender) SendTest(context.Context, string) error { return errors.New("db down") }

func TestNotificationsTestFailureAllowsRetry(t *testing.T) {
	e := newNotif(t, nil, func(c *api.NotificationsConfig) { c.Sender = failingSender{} })
	if rec := e.do("POST", "/api/v1/notifications/test", ""); rec.Code != 500 {
		t.Fatalf("%d", rec.Code)
	}
	if err := e.svc.SendTest(context.Background(), api.Actor{}); err == nil || errors.Is(err, api.ErrTestTooOften) {
		t.Fatalf("после сбоя пауза не должна действовать: %v", err)
	}
}

func TestNotificationsNotConfigured(t *testing.T) {
	e := newNotif(t, nil, func(c *api.NotificationsConfig) { c.Sender, c.Toggles, c.BotID = nil, nil, "" })
	if rec := e.do("POST", "/api/v1/notifications/test", ""); rec.Code != http.StatusNotImplemented {
		t.Fatalf("test: %d", rec.Code)
	}
	if rec := e.do("PUT", "/api/v1/notifications", `{"events":{"overload":false}}`); rec.Code != http.StatusNotImplemented {
		t.Fatalf("put: %d", rec.Code)
	}
	var info api.NotificationsInfo
	rec := e.do("GET", "/api/v1/notifications", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if rec.Code != 200 || info.Enabled || len(info.Events) == 0 {
		t.Fatalf("get: %d %+v", rec.Code, info)
	}
}

func TestNotificationsRequireSession(t *testing.T) {
	deny := api.Wrap(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	})
	e := newNotif(t, deny, nil)
	for _, rt := range [][2]string{{"GET", "/api/v1/notifications"}, {"PUT", "/api/v1/notifications"}, {"POST", "/api/v1/notifications/test"}} {
		if rec := e.do(rt[0], rt[1], ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%v: %d", rt, rec.Code)
		}
	}
	if items, _ := e.st.Outbox().Pending(context.Background(), 10); len(items) != 0 {
		t.Fatal("без сессии в outbox ничего не попадает")
	}
}

func TestNotificationsCrossOriginForbidden(t *testing.T) {
	var hit atomic.Int32
	prot := api.Wrap(func(h http.Handler) http.Handler {
		return auth.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1); h.ServeHTTP(w, r) }))
	})
	e := newNotif(t, prot, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/notifications/test", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || hit.Load() != 0 {
		t.Fatalf("%d hit=%d", rec.Code, hit.Load())
	}
	if items, _ := e.st.Outbox().Pending(context.Background(), 10); len(items) != 0 {
		t.Fatal("кросс-доменный запрос поставил тест в очередь")
	}
}
