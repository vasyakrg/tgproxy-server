package screens_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/metrics"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

var updateAccess = flag.Bool("update-access", false, "обновить golden-файлы экранов входа и доступа")

var (
	accHashRe  = regexp.MustCompile(`\?v=[0-9a-f]{12}`)
	accInline  = regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>`)
	accStyle   = regexp.MustCompile(`(?i)\sstyle\s*=`)
	accHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	keyRe      = regexp.MustCompile(`tgp_[0-9A-Za-z]{24}`)
)

func assertStrictCSP(t *testing.T, html string) {
	t.Helper()
	if accStyle.MatchString(html) {
		t.Error("в HTML есть style=")
	}
	for _, m := range accInline.FindAllString(html, -1) {
		if !strings.Contains(m, "src=") {
			t.Errorf("inline-скрипт: %s", m)
		}
	}
	if accHandler.MatchString(html) {
		t.Error("inline-обработчики событий в HTML")
	}
}

func accGolden(t *testing.T, name string, c templ.Component) {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Render(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	got := accHashRe.ReplaceAllString(buf.String(), "?v=HASH")
	path := filepath.Join("testdata", name+".golden.html")
	if *updateAccess {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // тестовая константа
	if err != nil {
		t.Fatalf("нет golden %s (запустите с -update-access): %v", path, err)
	}
	if strings.TrimSuffix(string(want), "\n") != got {
		t.Errorf("%s: не совпало с golden (-update-access, если намеренно)\n%s", name, got)
	}
}

type accEnv struct {
	base  string
	stats map[string][3]any // name -> {requests, lastSeen, ok}
}

func (e accEnv) PublicBaseURL() string { return e.base }

func (e accEnv) RuleStats(name string) (int64, time.Time, bool) {
	s, ok := e.stats[name]
	if !ok {
		return 0, time.Time{}, false
	}
	return s[0].(int64), s[1].(time.Time), s[2].(bool) //nolint:forcetypeassert // тест
}

var accNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type accFx struct {
	*fx
	svc  *api.AccessService
	bots *metrics.TopBots
	sid  *http.Cookie
}

func newAccessFx(t *testing.T, env screens.AccessEnv) *accFx {
	t.Helper()
	f := newFx(t, false)
	af := &accFx{fx: f, bots: metrics.NewTopBots(0)}
	af.svc = api.NewAccessService(f.st.AccessRules(), f.st.Audit(), nil, func() time.Time { return accNow })
	screens.MountAccess(f.rt, screens.AccessDeps{
		Auth: f.a, Service: af.svc, Env: env, Bots: af.bots, Now: func() time.Time { return accNow },
	})
	af.sid = f.sessionCookie("alice")
	return af
}

func (a *accFx) call(method, path string, form url.Values, htmx bool) (code int, body string, h http.Header) {
	a.t.Helper()
	hd := map[string]string{}
	if htmx {
		hd["HX-Request"] = "true"
	}
	w := a.do(req{method: method, path: path, form: form, hdr: hd, cookies: []*http.Cookie{a.sid}})
	return w.Code, w.Body.String(), w.Header()
}

func (a *accFx) seed() (net, key, both store.AccessRule) {
	a.t.Helper()
	ctx := context.Background()
	mk := func(r store.AccessRule) store.AccessRule {
		got, err := a.st.AccessRules().Create(ctx, r)
		if err != nil {
			a.t.Fatal(err)
		}
		return got
	}
	h := func(s string) []byte { return access.HashKey(s) }
	net = mk(store.AccessRule{Name: "office", CIDRs: pfx("10.20.0.0/16", "10.30.0.0/16"), RPS: 50, Enabled: true})
	key = mk(store.AccessRule{Name: "crm", KeyHash: h("k1"), KeyPrefix: "tgp_k7Qm", RPS: 30, Enabled: true})
	both = mk(store.AccessRule{Name: "monitoring", CIDRs: pfx("192.168.5.10/32"), KeyHash: h("k2"), KeyPrefix: "tgp_c1Zr", Enabled: true})
	return net, key, both
}

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestAccessRequiresSession(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://tgproxy.test"})
	for _, p := range []string{"/access", "/access/new", "/access/1/edit", "/access/1/delete"} {
		w := a.do(req{method: "GET", path: p})
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("GET %s без сессии: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	w := a.do(req{method: "GET", path: "/access", hdr: hx})
	if w.Code != 401 || w.Header().Get("HX-Redirect") != "/login" {
		t.Errorf("htmx без сессии: %d %q", w.Code, w.Header().Get("HX-Redirect"))
	}
	for _, p := range []string{"/access", "/access/1", "/access/1/delete"} {
		if w := a.do(req{method: "POST", path: p, form: url.Values{"name": {"x"}}, hdr: hx}); w.Code != 401 {
			t.Errorf("POST %s без сессии: %d", p, w.Code)
		}
	}
	if n, _ := a.st.AccessRules().List(context.Background()); len(n) != 0 {
		t.Error("без сессии правила создаваться не должны")
	}
}

func TestAccessPage(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://tgproxy.corp.local/", stats: map[string][3]any{
		"office":     {int64(694120), accNow.Add(-10 * time.Second), true},
		"crm":        {int64(0), time.Time{}, true},
		"monitoring": {int64(4812), accNow.Add(-3 * time.Minute), true},
	}})
	a.seed()
	a.bots.Observe(6123450001, "office", 200)
	a.bots.Observe(6123450001, "office", 429)
	a.bots.Observe(6123450001, "office", 200)
	a.bots.Observe(5550001111, "monitoring", 500)

	code, body, hdr := a.call("GET", "/access", nil, false)
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	assertStrictCSP(t, body)
	if !strings.Contains(hdr.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("нет CSP")
	}
	for _, want := range []string{
		"<title>Доступ — tgproxy</title>", "+ Новое правило", `aria-current="page"`, "Как подключить бота",
		"https://tgproxy.corp.local/bot&lt;token&gt;/sendMessage", "https://tgproxy.corp.local/k/&lt;ключ&gt;/bot&lt;token&gt;/sendMessage",
		">office", ">crm", ">monitoring", "сеть + ключ", `>ключ<`, "10.20.0.0/16", "10.30.0.0/16", "любые",
		"tgp_k7Qm…", "50 rps", "30 rps", "без лимита",
		"694 120", "4 812", "только что", "3 мин назад", "не было",
		`aria-label="Изменить правило office"`, `aria-label="Удалить правило crm"`,
		"Активные боты за 24 часа", "6123450001", "5550001111", "33,3 %", "100,0 %", `id="rule-modal"`, `data-modal-open="rule-modal"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if keyRe.MatchString(body) {
		t.Error("в списке не должно быть ключей")
	}
}

func TestAccessPageEmptyStatsAndBaseFallback(t *testing.T) {
	a := newAccessFx(t, nil)
	a.seed()
	_, body, _ := a.call("GET", "/access", nil, false)
	if !strings.Contains(body, "http://example.com/bot&lt;token&gt;") {
		t.Errorf("base URL по умолчанию — из Host запроса")
	}
	if strings.Count(body, ">—<") < 3 {
		t.Error("нет данных статистики — должно быть «—»")
	}
	// пустой список
	b := newAccessFx(t, accEnv{base: "https://x.test"})
	_, body, _ = b.call("GET", "/access", nil, false)
	if !strings.Contains(body, "Правил пока нет") {
		t.Error("нет пустого состояния")
	}
}

func TestAccessFormsAreFragments(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://x.test"})
	net, _, _ := a.seed()
	for _, p := range []string{"/access/new", "/access/1/edit", "/access/1/delete"} {
		code, body, _ := a.call("GET", p, nil, true)
		if code != 200 || strings.Contains(body, "<html") {
			t.Errorf("%s: code=%d, ожидался фрагмент", p, code)
		}
		assertStrictCSP(t, body)
		// без htmx -> редирект на страницу
		if code, _, h := a.call("GET", p, nil, false); code != 303 || h.Get("Location") != "/access" {
			t.Errorf("%s без htmx: %d", p, code)
		}
	}
	_, body, _ := a.call("GET", "/access/new", nil, true)
	for _, want := range []string{`hx-post="/access"`, `name="name"`, `name="cidrs"`, `name="with_key"`, `name="rps"`, "Скрытый ключ в адресе", "открытый прокси"} {
		if !strings.Contains(body, want) {
			t.Errorf("форма: нет %q", want)
		}
	}
	_, body, _ = a.call("GET", "/access/1/edit", nil, true)
	for _, want := range []string{`hx-post="/access/1"`, `value="office"`, "10.20.0.0/16\n10.30.0.0/16", `value="50"`, `name="enabled"`} {
		if !strings.Contains(body, want) {
			t.Errorf("edit: нет %q", want)
		}
	}
	_, body, _ = a.call("GET", "/access/2/delete", nil, true)
	if !strings.Contains(body, "Удалить правило?") || !strings.Contains(body, `hx-post="/access/2/delete"`) || !strings.Contains(body, "crm") {
		t.Errorf("confirm: %s", body)
	}
	if code, body, _ := a.call("GET", "/access/99/edit", nil, true); code != 404 || !strings.Contains(body, "не найдено") {
		t.Errorf("edit 404: %d", code)
	}
	if code, _, _ := a.call("GET", "/access/abc/edit", nil, true); code != 404 {
		t.Errorf("edit abc: %d", code)
	}
	_ = net
}

func TestAccessCreateNetworkRule(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://tgproxy.test"})
	code, body, h := a.call("POST", "/access", url.Values{"name": {"Office.1"}, "cidrs": {"10.0.0.0/8\n192.168.1.5"}, "rps": {"12,5"}}, true)
	if code != 200 {
		t.Fatalf("code=%d %s", code, body)
	}
	for _, want := range []string{"Office.1", "https://tgproxy.test", "Доступ — только из указанных сетей", `id="rules-section"`, `hx-swap-oob="true"`, "10.0.0.0/8", "192.168.1.5/32", "12.5 rps"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(body, "/k/") || strings.Contains(body, "Ключ показан один раз") {
		t.Error("у правила-сети нет ключа")
	}
	if !strings.Contains(h.Get("HX-Trigger"), `"toast"`) || strings.ContainsAny(h.Get("HX-Trigger"), "«»аеиоу") {
		t.Errorf("HX-Trigger должен быть ASCII-JSON: %q", h.Get("HX-Trigger"))
	}
	assertStrictCSP(t, body)
	r, err := a.st.AccessRules().GetByName(context.Background(), "Office.1")
	if err != nil || r.KeyHash != nil || len(r.CIDRs) != 2 || r.RPS != 12.5 || !r.Enabled {
		t.Fatalf("repo: %+v %v", r, err)
	}
	au, _ := a.st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 1 || au[0].Action != api.AuditRuleCreate || au[0].Actor != "alice" || au[0].Target != "Office.1" {
		t.Errorf("аудит: %+v", au)
	}
}

func TestAccessCreateKeyRuleShowsKeyOnce(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://tgproxy.test"})
	code, body, h := a.call("POST", "/access", url.Values{"name": {"crm"}, "with_key": {"1"}, "rps": {"30"}}, true)
	if code != 200 {
		t.Fatalf("code=%d %s", code, body)
	}
	key := keyRe.FindString(body)
	if key == "" {
		t.Fatal("ключ не показан")
	}
	for _, want := range []string{"Ключ показан один раз", "https://tgproxy.test/k/" + key, `data-copy="new-rule-url"`, `data-copy="new-rule-key"`, `aria-label="Копировать Base URL"`, "X-Proxy-Key", "Вебхуки не поддерживаются"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Error("ответ с ключом не должен кешироваться")
	}
	if strings.Contains(h.Get("HX-Trigger"), key) {
		t.Error("ключ в HX-Trigger")
	}
	// в БД — только хеш
	r, err := a.st.AccessRules().GetByName(context.Background(), "crm")
	if err != nil || !bytes.Equal(r.KeyHash, access.HashKey(key)) || r.KeyPrefix != key[:8] {
		t.Fatalf("repo: %+v %v", r, err)
	}
	// ключа нет ни в списке, ни в форме правки, ни в аудите
	for _, p := range []string{"/access"} {
		if _, b, _ := a.call("GET", p, nil, false); strings.Contains(b, key) || keyRe.MatchString(b) {
			t.Errorf("%s: ключ в списке", p)
		}
	}
	if _, b, _ := a.call("GET", "/access/1/edit", nil, true); strings.Contains(b, key) {
		t.Error("ключ в форме правки")
	}
	au, _ := a.st.Audit().List(context.Background(), store.AuditQuery{})
	dump := ""
	for _, e := range au {
		dump += e.Detail + e.Target + e.Action
	}
	if strings.Contains(dump, key) || strings.Contains(dump, hex.EncodeToString(r.KeyHash)) {
		t.Error("ключ/хеш в аудите")
	}
}

func TestAccessCreateValidation(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://tgproxy.test"})
	cases := []struct {
		name string
		form url.Values
		want string
		id   string // id поля с ошибкой
	}{
		{"невалидный CIDR", url.Values{"name": {"x"}, "cidrs": {"10.0.0.0/33"}}, "неверная сеть", "rule-cidrs"},
		{"мусор вместо CIDR", url.Values{"name": {"x"}, "cidrs": {"not-a-net"}}, "неверная сеть", "rule-cidrs"},
		{"биты хоста", url.Values{"name": {"x"}, "cidrs": {"10.0.0.1/8"}}, "биты хоста", "rule-cidrs"},
		{"без сети и без ключа", url.Values{"name": {"x"}}, "открытый прокси", "rule-cidrs"},
		{"0.0.0.0/0 без ключа", url.Values{"name": {"x"}, "cidrs": {"0.0.0.0/0"}}, "открытый прокси", "rule-cidrs"},
		{"::/0 без ключа", url.Values{"name": {"x"}, "cidrs": {"::/0"}}, "открытый прокси", "rule-cidrs"},
		{"пустое имя", url.Values{"cidrs": {"10.0.0.0/8"}}, "Укажите название", "rule-name"},
		{"имя с недопустимым символом", url.Values{"name": {"my/rule"}, "cidrs": {"10.0.0.0/8"}}, "Буквы, цифры", "rule-name"},
		{"rps не число", url.Values{"name": {"x"}, "cidrs": {"10.0.0.0/8"}, "rps": {"abc"}}, "Введите число", "rule-rps"},
		{"rps NaN", url.Values{"name": {"x"}, "cidrs": {"10.0.0.0/8"}, "rps": {"NaN"}}, "Введите число", "rule-rps"},
		{"rps отрицательный", url.Values{"name": {"x"}, "cidrs": {"10.0.0.0/8"}, "rps": {"-1"}}, "отрицательным", "rule-rps"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := a.call("POST", "/access", tc.form, true)
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("code=%d", code)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("нет текста %q в %s", tc.want, body)
			}
			if !strings.Contains(body, tc.id+"-error") || !strings.Contains(body, `aria-invalid="true"`) {
				t.Errorf("ошибка не привязана к полю %s", tc.id)
			}
			if strings.Contains(body, "<html") {
				t.Error("нужен фрагмент формы")
			}
		})
	}
	if rs, _ := a.st.AccessRules().List(context.Background()); len(rs) != 0 {
		t.Errorf("невалидные правила не должны создаваться: %d", len(rs))
	}
	// 0.0.0.0/0 с ключом — разрешено
	if code, _, _ := a.call("POST", "/access", url.Values{"name": {"any"}, "cidrs": {"0.0.0.0/0"}, "with_key": {"1"}}, true); code != 200 {
		t.Errorf("0.0.0.0/0 с ключом должен быть допустим: %d", code)
	}
	// дубликат имени
	code, body, _ := a.call("POST", "/access", url.Values{"name": {"any"}, "cidrs": {"10.0.0.0/8"}}, true)
	if code != 422 || !strings.Contains(body, "уже существует") {
		t.Errorf("дубликат: %d", code)
	}
	// все ошибки сразу + поля сохраняются
	code, body, _ = a.call("POST", "/access", url.Values{"name": {"bad/name"}, "cidrs": {"zzz"}, "rps": {"q"}}, true)
	if code != 422 || strings.Count(body, `role="alert"`) < 3 || !strings.Contains(body, `value="bad/name"`) {
		t.Errorf("несколько ошибок: %d", code)
	}
	// без htmx — отказ
	if code, _, _ := a.call("POST", "/access", url.Values{"name": {"z"}, "cidrs": {"10.0.0.0/8"}}, false); code != 400 {
		t.Errorf("POST без htmx: %d", code)
	}
}

func TestAccessUpdate(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://tgproxy.test"})
	a.seed()
	code, body, h := a.call("POST", "/access/1", url.Values{"name": {"office2"}, "cidrs": {"172.16.0.0/12"}, "rps": {"7"}, "enabled": {"1"}}, true)
	if code != 200 {
		t.Fatalf("code=%d %s", code, body)
	}
	if !strings.Contains(body, `id="rule-modal-wrap"`) || !strings.Contains(body, "office2") || !strings.Contains(body, "172.16.0.0/12") {
		t.Errorf("ответ: нужен закрытый диалог (OOB) и обновлённая таблица: %s", body)
	}
	if strings.Contains(body, " open") {
		t.Error("диалог должен быть закрытым")
	}
	if !strings.Contains(h.Get("HX-Trigger"), "toast") {
		t.Error("нет toast")
	}
	r, _ := a.st.AccessRules().Get(context.Background(), 1)
	if r.Name != "office2" || r.RPS != 7 || len(r.CIDRs) != 1 || r.CIDRs[0].String() != "172.16.0.0/12" {
		t.Errorf("repo: %+v", r)
	}
	// отключение
	a.call("POST", "/access/1", url.Values{"name": {"office2"}, "cidrs": {"172.16.0.0/12"}}, true)
	if r, _ = a.st.AccessRules().Get(context.Background(), 1); r.Enabled {
		t.Error("enabled должен сняться")
	}
	// ключевое правило: сети можно убрать (ключ остаётся)
	if code, _, _ := a.call("POST", "/access/2", url.Values{"name": {"crm"}, "enabled": {"1"}}, true); code != 200 {
		t.Errorf("правило с ключом без сетей: %d", code)
	}
	// сетевое правило: убрать все сети нельзя
	code, body, _ = a.call("POST", "/access/1", url.Values{"name": {"office2"}, "enabled": {"1"}}, true)
	if code != 422 || !strings.Contains(body, "открытый прокси") {
		t.Errorf("пустые сети без ключа: %d", code)
	}
	if code, _, _ = a.call("POST", "/access/1", url.Values{"name": {"office2"}, "cidrs": {"nope"}, "enabled": {"1"}}, true); code != 422 {
		t.Errorf("невалидный CIDR: %d", code)
	}
	// конфликт имён
	if code, body, _ = a.call("POST", "/access/1", url.Values{"name": {"crm"}, "cidrs": {"10.0.0.0/8"}}, true); code != 422 || !strings.Contains(body, "уже существует") {
		t.Errorf("конфликт имён: %d", code)
	}
	if code, _, _ = a.call("POST", "/access/77", url.Values{"name": {"q"}, "cidrs": {"10.0.0.0/8"}}, true); code != 404 {
		t.Errorf("несуществующее: %d", code)
	}
	au, _ := a.st.Audit().List(context.Background(), store.AuditQuery{})
	n := 0
	for _, e := range au {
		if e.Action == api.AuditRuleUpdate {
			n++
		}
	}
	if n != 3 {
		t.Errorf("аудит обновлений: %d", n)
	}
}

func TestAccessDelete(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://tgproxy.test"})
	a.seed()
	before, _ := a.st.AccessRules().Version(context.Background())
	code, body, h := a.call("POST", "/access/2/delete", nil, true)
	if code != 200 || !strings.Contains(h.Get("HX-Trigger"), "toast") {
		t.Fatalf("code=%d", code)
	}
	if strings.Contains(body, ">crm") || !strings.Contains(body, ">office") {
		t.Errorf("таблица после удаления: %s", body)
	}
	if _, err := a.st.AccessRules().Get(context.Background(), 2); err == nil {
		t.Error("правило должно быть удалено из repo")
	}
	if after, _ := a.st.AccessRules().Version(context.Background()); after == before {
		t.Error("версия правил должна меняться (инвалидация кеша access)")
	}
	au, _ := a.st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 1 || au[0].Action != api.AuditRuleDelete || au[0].Target != "crm" {
		t.Errorf("аудит: %+v", au)
	}
	if code, _, _ := a.call("POST", "/access/2/delete", nil, true); code != 404 {
		t.Errorf("повторное удаление: %d", code)
	}
}

func TestAccessCrossOriginRejected(t *testing.T) {
	a := newAccessFx(t, accEnv{base: "https://tgproxy.test"})
	w := a.do(req{method: "POST", path: "/access", form: url.Values{"name": {"x"}, "cidrs": {"10.0.0.0/8"}},
		hdr: map[string]string{"HX-Request": "true", "Sec-Fetch-Site": "cross-site"}, cookies: []*http.Cookie{a.sid}})
	if w.Code != 403 {
		t.Errorf("cross-site POST: %d", w.Code)
	}
	if rs, _ := a.st.AccessRules().List(context.Background()); len(rs) != 0 {
		t.Error("правило создано кросс-доменным запросом")
	}
}

func TestAccessGolden(t *testing.T) {
	rows := []screens.RuleRow{
		{ID: 1, Name: "office", Enabled: true, KindLabel: "сеть", CIDRs: []string{"10.20.0.0/16"}, KeyPrefix: "—", Limit: "50 rps", Requests: "694 120", LastSeen: "только что"},
		{ID: 2, Name: "crm", Enabled: false, KindLabel: "ключ", KindTone: "accent", KeyPrefix: "tgp_k7Qm…", Limit: "без лимита", Requests: "—", LastSeen: "—", SeenMuted: true},
	}
	cases := map[string]templ.Component{
		"access_rules_table":   screens.RulesSection(rows, false),
		"access_rules_empty":   screens.RulesSection(nil, true),
		"access_form_new":      screens.RuleForm(screens.RuleFormVM{WithKey: true}),
		"access_form_errors":   screens.RuleForm(screens.RuleFormVM{Name: "x", CIDRs: "0.0.0.0/0", Errors: api.FieldErrors{"cidrs": "открытый прокси"}}),
		"access_form_edit":     screens.RuleForm(screens.RuleFormVM{ID: 2, Name: "crm", KeyPrefix: "tgp_k7Qm…", RPS: "30", Enabled: true}),
		"access_delete":        screens.DeleteConfirm(2, "crm"),
		"access_created_key":   screens.CreatedPanel(screens.CreatedVM{Name: "crm", Key: "tgp_k7Qm2vXa9LrT4cNw8ZpE1hYs", BaseURL: "https://tgproxy.corp.local/k/tgp_k7Qm2vXa9LrT4cNw8ZpE1hYs"}),
		"access_created_plain": screens.CreatedPanel(screens.CreatedVM{Name: "office", BaseURL: "https://tgproxy.corp.local"}),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { accGolden(t, name, c) })
	}
}
