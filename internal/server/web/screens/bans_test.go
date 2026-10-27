package screens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/ban"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type geoStub struct{}

func (geoStub) Available() bool { return true }
func (geoStub) LookupString(ip string) string {
	if ip == "198.51.100.20" || ip == "203.0.113.9" {
		return "NL"
	}
	return ""
}

type bansFx struct {
	*fx
	mgr *ban.Manager
	sid *http.Cookie
}

func newBansFx(t *testing.T, geo screens.GeoLookup) *bansFx {
	t.Helper()
	f := newFx(t, false)
	mgr, err := ban.New(context.Background(), f.st.Bans(), ban.Options{
		Config:  config.BanConfig{Enabled: true, Threshold: 5, Window: time.Minute, Duration: time.Hour, ResetAfter: time.Hour, MaxTracked: 100},
		Protect: ban.StaticProtector{Trusted: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Wait)
	screens.MountBans(f.rt, screens.BansDeps{
		Auth: f.a, Service: api.NewBansService(mgr, f.st.Audit(), nil, nil), Geo: geo,
	})
	return &bansFx{fx: f, mgr: mgr, sid: f.sessionCookie("alice")}
}

func (b *bansFx) call(method, path string, form url.Values, htmx bool, extra ...string) *httptestRec {
	hd := map[string]string{}
	if htmx {
		hd["HX-Request"] = "true"
	}
	for i := 0; i+1 < len(extra); i += 2 {
		hd[extra[i]] = extra[i+1]
	}
	return b.do(req{method: method, path: path, form: form, hdr: hd, cookies: []*http.Cookie{b.sid}})
}

func TestBansRequireAuthAndHTMX(t *testing.T) {
	b := newBansFx(t, nil)
	for _, c := range [][2]string{{"GET", "/bans"}, {"GET", "/bans/new"}, {"POST", "/bans"}, {"POST", "/bans/1/delete"}} {
		w := b.do(req{method: c[0], path: c[1], hdr: map[string]string{"HX-Request": "true"}})
		if w.Code == http.StatusOK || w.Code == http.StatusCreated {
			t.Errorf("%s %s без сессии: %d", c[0], c[1], w.Code)
		}
	}
	// без htmx изменения не принимаются, форма редиректит на список
	if w := b.call("POST", "/bans", url.Values{"ip": {"8.8.8.8"}, "duration": {"1h"}}, false); w.Code != http.StatusBadRequest {
		t.Errorf("POST без htmx: %d", w.Code)
	}
	if w := b.call("GET", "/bans/new", nil, false); w.Code != http.StatusSeeOther {
		t.Errorf("GET new без htmx: %d", w.Code)
	}
	// CSRF: кросс-доменный POST отбивается
	if w := b.call("POST", "/bans", url.Values{"ip": {"8.8.8.8"}, "duration": {"1h"}}, true, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", w.Code)
	}
	if list, _ := b.st.Bans().ListActive(context.Background(), time.Now()); len(list) != 0 {
		t.Fatalf("баны созданы без прав: %+v", list)
	}
}

func TestBansCreateListUnban(t *testing.T) {
	b := newBansFx(t, geoStub{})
	w := b.call("GET", "/bans/new?ip=203.0.113.9&from=errors", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `value="203.0.113.9"`) || !strings.Contains(w.Body.String(), `value="errors"`) ||
		!strings.Contains(w.Body.String(), `<option value="permanent"`) {
		t.Fatalf("форма: %d %s", w.Code, w.Body)
	}
	// из «Ошибок»: закрываем модалку, таблицу не трогаем
	w = b.call("POST", "/bans", url.Values{"ip": {"203.0.113.9"}, "duration": {"24h"}, "comment": {"скан"}, "from": {"errors"}}, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `hx-swap-oob="true"`) || strings.Contains(w.Body.String(), "bans-section") ||
		!strings.Contains(w.Header().Get("HX-Trigger"), "toast") {
		t.Fatalf("create from errors: %d %s %v", w.Code, w.Body, w.Header())
	}
	// со страницы банов: обновляем таблицу
	w = b.call("POST", "/bans", url.Values{"ip": {"198.51.100.20"}, "duration": {"permanent"}, "from": {"bans"}}, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "bans-section") || !strings.Contains(w.Body.String(), "198.51.100.20") {
		t.Fatalf("create from bans: %d %s", w.Code, w.Body)
	}
	if !b.mgr.Banned(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("бан не действует")
	}

	page := b.call("GET", "/bans", nil, false).Body.String()
	for _, want := range []string{"203.0.113.9", "198.51.100.20", "🇳🇱", "навсегда", "вручную", "IP Geolocation by DB-IP", "скан", `id="ban-modal"`} {
		if !strings.Contains(page, want) {
			t.Errorf("нет %q", want)
		}
	}
	checkCSP(t, page)

	au, _ := b.st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 2 || au[0].Action != api.AuditBanCreate || au[0].Actor != "alice" {
		t.Fatalf("аудит: %+v", au)
	}

	list, _ := b.st.Bans().ListActive(context.Background(), time.Now())
	w = b.call("POST", "/bans/"+itoa(list[0].ID)+"/delete", nil, true)
	if w.Code != 200 || strings.Contains(w.Body.String(), "198.51.100.20") || !strings.Contains(w.Header().Get("HX-Trigger"), "toast") {
		t.Fatalf("unban: %d %s", w.Code, w.Body)
	}
	// повторное снятие — не ошибка UI
	if w = b.call("POST", "/bans/"+itoa(list[0].ID)+"/delete", nil, true); w.Code != 200 {
		t.Fatalf("повторный unban: %d", w.Code)
	}
	if w = b.call("POST", "/bans/zzz/delete", nil, true); w.Code != 404 {
		t.Fatalf("кривой id: %d", w.Code)
	}
}

func TestBansFormValidation(t *testing.T) {
	b := newBansFx(t, nil)
	cases := map[string]url.Values{
		"не IP":       {"ip": {"nope"}, "duration": {"1h"}},
		"нет срока":   {"ip": {"8.8.8.8"}, "duration": {""}},
		"доверенный":  {"ip": {"192.0.2.9"}, "duration": {"permanent"}},
		"приватный":   {"ip": {"10.0.0.5"}, "duration": {"1h"}},
		"loopback":    {"ip": {"127.0.0.1"}, "duration": {"1h"}},
		"кривой срок": {"ip": {"8.8.8.8"}, "duration": {"forever"}},
	}
	for name, form := range cases {
		form.Set("from", "bans")
		w := b.call("POST", "/bans", form, true)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "field-error") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if list, _ := b.st.Bans().ListActive(context.Background(), time.Now()); len(list) != 0 {
		t.Fatalf("невалидный ввод создал баны: %+v", list)
	}
	if page := b.call("GET", "/bans", nil, false).Body.String(); !strings.Contains(page, "Банов нет") || strings.Contains(page, "DB-IP") {
		t.Errorf("пустая страница без базы стран: %s", page)
	}
}

func TestErrorsAccessRowsFlagsAndBanIcon(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.Errors().Append(ctx, store.ErrorEvent{At: t0.Add(-time.Minute), RequestID: "01JBX4ABCDEFGHQ2", BotID: "123", Method: "sendmessage",
		Phase: "access", Code: 403, Outcome: store.OutcomeFailedToBot, ClientIP: "203.0.113.9", Reason: "key_required", Description: "access denied: key_required"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Errors().Append(ctx, store.ErrorEvent{At: t0.Add(-2 * time.Minute), Phase: "dial", Code: 502, Outcome: store.OutcomeRetried, AgentID: "ams-1"}); err != nil {
		t.Fatal(err)
	}
	h := screens.NewErrors(screens.ErrorsDeps{Shell: e.shell, Source: e.q, Agents: agentStates(), Geo: geoStub{}, Location: time.UTC, Now: func() time.Time { return t0 }})
	body := get(h, "/errors").Body.String()
	for _, want := range []string{"203.0.113.9", "🇳🇱", "нужен ключ", "Забанить 203.0.113.9", `data-modal-open="ban-modal"`, `id="ban-modal"`,
		"IP Geolocation by DB-IP", "отказы доступа", `name="reason"`, `name="client_ip"`, "access"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	checkCSP(t, body)
	// фильтр по причине и по IP
	only := get(h, "/errors?reason=key_required&client_ip=203.0.113.9", "HX-Request", "true").Body.String()
	if !strings.Contains(only, "203.0.113.9") || strings.Contains(only, "ams-1") {
		t.Errorf("фильтр по причине: %s", only)
	}
	none := get(h, "/errors?reason=bad_key", "HX-Request", "true").Body.String()
	if strings.Contains(none, "203.0.113.9") {
		t.Errorf("фильтр bad_key вернул чужое")
	}
	// без базы стран — ни флагов, ни атрибуции
	h2 := screens.NewErrors(screens.ErrorsDeps{Shell: e.shell, Source: e.q, Agents: agentStates(), Location: time.UTC, Now: func() time.Time { return t0 }})
	body2 := get(h2, "/errors").Body.String()
	if strings.Contains(body2, "🇳🇱") || strings.Contains(body2, "DB-IP") || !strings.Contains(body2, "203.0.113.9") {
		t.Errorf("без geo: флаг/атрибуция лишние")
	}
}

type httptestRec = httptest.ResponseRecorder

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
