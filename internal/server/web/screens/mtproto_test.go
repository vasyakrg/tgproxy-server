package screens_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
)

var (
	mtKeyRe  = regexp.MustCompile(`secret=[0-9A-Za-z_-]{20,}`)
	mtHexRe  = regexp.MustCompile(`ee[0-9a-f]{32}`)
	mtStatic = screens.MTLinkVM{
		Title: "Секрет «phones» создан", Name: "phones", Fresh: true,
		TG: "tg://proxy?server=tg.example.com&port=443&secret=eeAAAA", HTTPS: "https://t.me/proxy?server=tg.example.com&port=443&secret=eeAAAA",
		QR: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8" fill="#fff"/></svg>`,
	}
)

type mtStats struct{ s api.MTProtoStats }

func (m mtStats) Snapshot() api.MTProtoStats { return m.s }

type mtFx struct {
	*fx
	svc  *api.MTProtoService
	ep   api.MTProtoEndpoint
	sid  *http.Cookie
	conn map[string]int
}

func newMTFx(t *testing.T, ep api.MTProtoEndpoint, stats api.MTProtoStatsSource) *mtFx {
	t.Helper()
	f := newFx(t, false)
	m := &mtFx{fx: f, ep: ep, conn: map[string]int{"phones": 3}}
	m.svc = api.NewMTProtoService(f.st.MTProtoSecrets(), f.st.Audit(), fxSealer{}, func() api.MTProtoEndpoint { return m.ep }, nil, time.Now)
	screens.MountMTProto(f.rt, screens.MTProtoDeps{
		Auth: f.a, Service: m.svc, Stats: stats,
		ActiveConns: func(n string) int { return m.conn[n] }, Now: time.Now,
	})
	m.sid = f.sessionCookie("alice")
	return m
}

func (m *mtFx) call(method, path string, form url.Values, htmx bool) (int, string) {
	m.t.Helper()
	hd := map[string]string{}
	if htmx {
		hd["HX-Request"] = "true"
	}
	w := m.do(req{method: method, path: path, form: form, hdr: hd, cookies: []*http.Cookie{m.sid}})
	return w.Code, w.Body.String()
}

var mtEP = api.MTProtoEndpoint{Host: "tg.example.com", Port: 443, Domain: "www.example.org", Enabled: true}

func (m *mtFx) create(name string) int64 {
	m.t.Helper()
	code, body := m.call("POST", "/mtproto", url.Values{"name": {name}, "max_conns": {"100"}}, true)
	if code != 200 || !strings.Contains(body, "tg://proxy") {
		m.t.Fatalf("create: %d %s", code, body)
	}
	all, err := m.svc.List(context.Background())
	if err != nil || len(all) == 0 {
		m.t.Fatal(err)
	}
	return all[len(all)-1].ID
}

func TestMTProtoRequiresSession(t *testing.T) {
	m := newMTFx(t, mtEP, nil)
	for _, p := range []string{"/mtproto", "/mtproto/new", "/mtproto/1/link", "/mtproto/1/rotate", "/mtproto/1/revoke"} {
		if w := m.do(req{method: "GET", path: p}); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("GET %s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/mtproto", "/mtproto/1/link", "/mtproto/1/rotate", "/mtproto/1/revoke"} {
		if w := m.do(req{method: "POST", path: p, form: url.Values{"name": {"x"}}, hdr: hx}); w.Code != 401 {
			t.Errorf("POST %s без сессии: %d", p, w.Code)
		}
	}
}

func TestMTProtoPageAndBanners(t *testing.T) {
	st := mtStats{api.MTProtoStats{Enabled: true, Agents: []api.MTProtoAgentStat{
		{AgentID: "a1", Capable: true, Streams: 5, DC: []api.MTProtoDCStat{{DC: 1, Up: true, RTTMs: 41, Streams: 3}, {DC: 2, Up: false}}},
		{AgentID: "old", Capable: false},
	}}}
	m := newMTFx(t, mtEP, st)
	m.create("phones")
	code, body := m.call("GET", "/mtproto", nil, false)
	if code != 200 {
		t.Fatal(code)
	}
	assertStrictCSP(t, body)
	for _, want := range []string{
		"<title>MTProto — tgproxy</title>", `aria-current="page"`, ">phones", "активен", "3 / 100", "+ Новый секрет",
		`aria-label="Ссылка и QR секрета phones"`, `aria-label="Повернуть секрет phones"`, `aria-label="Отозвать секрет phones"`,
		"DC 1", "DC 2", "41 мс · 3 стр.", "недоступен", "без mtproto/1", `id="mt-modal"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if mtKeyRe.MatchString(body) || mtHexRe.MatchString(body) || strings.Contains(body, "tg://") {
		t.Error("в списке не должно быть ключа или ссылки")
	}
	if strings.Contains(body, "MTProto выключен в server.yaml") || strings.Contains(body, "Не заданы mtproto.fronting_domain") {
		t.Error("баннеры не должны показываться при рабочей конфигурации")
	}

	m.ep = api.MTProtoEndpoint{}
	_, body = m.call("GET", "/mtproto", nil, false)
	for _, want := range []string{"MTProto выключен в server.yaml — секреты можно подготовить заранее.", "Не заданы mtproto.fronting_domain", "матрица появится после включения"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
}

func TestMTProtoCreateShowsLinkOnce(t *testing.T) {
	m := newMTFx(t, mtEP, nil)
	code, body := m.call("POST", "/mtproto", url.Values{"name": {"phones"}, "cidrs": {"203.0.113.0/24"}}, true)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	for _, want := range []string{"Ссылка показана один раз", "tg://proxy?server=tg.example.com", "https://t.me/proxy", `class="qr-box"`, "<svg", `id="mt-secrets"`, "203.0.113.0/24"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	_, list := m.call("GET", "/mtproto/list", nil, true)
	if mtKeyRe.MatchString(list) || !strings.Contains(list, "phones") {
		t.Error("список не должен содержать ключ")
	}
	if code, _ := m.call("POST", "/mtproto", url.Values{"name": {"x"}}, false); code != 400 {
		t.Errorf("без htmx: %d", code)
	}
}

func TestMTProtoCreateValidationAndNoEndpoint(t *testing.T) {
	m := newMTFx(t, mtEP, nil)
	code, body := m.call("POST", "/mtproto", url.Values{"name": {"!!"}, "cidrs": {"zzz"}}, true)
	if code != 422 || !strings.Contains(body, "field-error") {
		t.Errorf("валидация: %d", code)
	}
	if code, body = m.call("POST", "/mtproto", url.Values{"name": {"ok"}, "max_conns": {"abc"}}, true); code != 422 || !strings.Contains(body, "Целое число") {
		t.Errorf("max_conns: %d", code)
	}
	if all, _ := m.svc.List(context.Background()); len(all) != 0 {
		t.Error("секрет создан при ошибке валидации")
	}
	m.ep.Domain = ""
	code, body = m.call("POST", "/mtproto", url.Values{"name": {"nolink"}}, true)
	if code != 200 || !strings.Contains(body, "ссылка недоступна") || strings.Contains(body, "tg://") {
		t.Errorf("link_error: %d %s", code, body)
	}
	if all, _ := m.svc.List(context.Background()); len(all) != 1 {
		t.Error("секрет должен быть создан, несмотря на отсутствие endpoint")
	}
}

func TestMTProtoLinkRequiresFreshTOTP(t *testing.T) {
	m := newMTFx(t, mtEP, nil)
	id := m.create("phones")
	path := "/mtproto/" + itoa(id) + "/link"

	code, body := m.call("GET", path, nil, true)
	if code != 401 || !strings.Contains(body, `name="code"`) || !strings.Contains(body, "Подтвердите вход") {
		t.Fatalf("без TOTP: %d %s", code, body)
	}
	if strings.Contains(body, "tg://") || mtKeyRe.MatchString(body) || strings.Contains(body, "<svg") {
		t.Error("без свежего TOTP ссылка и QR не рендерятся")
	}
	if code, body = m.call("POST", path, url.Values{"code": {"000000"}}, true); code != 401 || !strings.Contains(body, "Неверный код") || strings.Contains(body, "tg://") {
		t.Errorf("неверный код: %d", code)
	}
	if code, body = m.call("GET", path, nil, true); code != 401 || strings.Contains(body, "tg://") {
		t.Error("после неверного кода TOTP не свежий")
	}
	code, body = m.call("POST", path, url.Values{"code": {m.code()}}, true)
	if code != 200 || !strings.Contains(body, "tg://proxy?server=tg.example.com") || !strings.Contains(body, "<svg") || !strings.Contains(body, "Открытие записано в аудит") {
		t.Fatalf("верный код: %d %s", code, body)
	}
	if code, body = m.call("GET", path, nil, true); code != 200 || !strings.Contains(body, "tg://proxy") {
		t.Errorf("свежий TOTP: %d", code)
	}
	if code, _ = m.call("GET", path, nil, false); code != http.StatusSeeOther {
		t.Errorf("без htmx — редирект: %d", code)
	}
	if code, _ = m.call("GET", "/mtproto/999/link", nil, true); code != 404 {
		t.Errorf("несуществующий: %d", code)
	}
}

func TestMTProtoRotateAndRevoke(t *testing.T) {
	m := newMTFx(t, mtEP, nil)
	id := m.create("phones")
	p := "/mtproto/" + itoa(id)

	if code, body := m.call("GET", p+"/rotate", nil, true); code != 200 || !strings.Contains(body, `name="grace"`) || mtKeyRe.MatchString(body) {
		t.Errorf("форма ротации: %d", code)
	}
	if code, body := m.call("POST", p+"/rotate", url.Values{"grace": {"nonsense"}}, true); code != 422 || !strings.Contains(body, "Длительность") {
		t.Errorf("плохой grace: %d", code)
	}
	code, body := m.call("POST", p+"/rotate", url.Values{"grace": {"24h"}}, true)
	if code != 200 || !strings.Contains(body, "tg://proxy") || !strings.Contains(body, "повёрнут") || !strings.Contains(body, "24h0m0s") {
		t.Fatalf("ротация: %d %s", code, body)
	}
	all, _ := m.svc.List(context.Background())
	if len(all) != 2 {
		t.Fatalf("после ротации секретов %d", len(all))
	}
	if !strings.Contains(body, "grace до ") {
		t.Errorf("старый секрет должен быть в grace: %s", body)
	}

	if code, body = m.call("GET", p+"/revoke", nil, true); code != 200 || !strings.Contains(body, "Отозвать секрет?") {
		t.Errorf("подтверждение: %d", code)
	}
	code, body = m.call("POST", p+"/revoke", nil, true)
	if code != 200 || !strings.Contains(body, "отозван") || !strings.Contains(body, `id="mt-modal-wrap"`) {
		t.Errorf("отзыв: %d %s", code, body)
	}
	if code, _ = m.call("POST", "/mtproto/999/revoke", nil, true); code != 404 {
		t.Errorf("отзыв несуществующего: %d", code)
	}
}

func TestMTProtoPurgeUI(t *testing.T) {
	m := newMTFx(t, mtEP, nil)
	live := m.create("live")
	dead := m.create("dead")
	pd, pl := "/mtproto/"+itoa(dead), "/mtproto/"+itoa(live)

	// у активного нет иконки удаления, кнопки «Удалить отозванные» тоже
	_, body := m.call("GET", "/mtproto", nil, false)
	if strings.Contains(body, "Удалить окончательно") || strings.Contains(body, "Удалить отозванные") {
		t.Fatal("кнопки удаления без отозванных секретов")
	}
	if code, body := m.call("POST", pd+"/revoke", nil, true); code != 200 || !strings.Contains(body, "отозван") {
		t.Fatalf("revoke: %d", code)
	}
	_, body = m.call("GET", "/mtproto", nil, false)
	for _, want := range []string{`aria-label="Удалить окончательно секрет dead"`, "Удалить отозванные (1)", `hx-get="/mtproto/purge-revoked"`} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(body, `aria-label="Удалить окончательно секрет live"`) {
		t.Error("иконка удаления у активного секрета")
	}

	// модалки подтверждения
	if code, body := m.call("GET", pd+"/purge", nil, true); code != 200 || !strings.Contains(body, "нельзя отменить") || !strings.Contains(body, `hx-post="`+pd+`/purge"`) {
		t.Errorf("confirm: %d %s", code, body)
	}
	if code, body := m.call("GET", pl+"/purge", nil, true); code != 200 || !strings.Contains(body, "ещё действует") || strings.Contains(body, "hx-post") {
		t.Errorf("confirm активного: %d %s", code, body)
	}
	if code, body := m.call("GET", "/mtproto/purge-revoked", nil, true); code != 200 || !strings.Contains(body, "<strong>1</strong>") {
		t.Errorf("confirm all: %d %s", code, body)
	}
	if code, _ := m.call("GET", pd+"/purge", nil, false); code != http.StatusSeeOther {
		t.Errorf("без htmx: %d", code)
	}

	// активный удалить нельзя
	if code, body := m.call("POST", pl+"/purge", nil, true); code != 409 || !strings.Contains(body, "ещё действует") {
		t.Errorf("purge активного: %d %s", code, body)
	}
	if code, _ := m.call("POST", pd+"/purge", nil, false); code != 400 {
		t.Errorf("POST без htmx: %d", code)
	}
	// удаление отозванного
	code, body := m.call("POST", pd+"/purge", nil, true)
	if code != 200 || !strings.Contains(body, `id="mt-modal-wrap"`) || !strings.Contains(body, `id="mt-secrets"`) || strings.Contains(body, ">dead<") {
		t.Fatalf("purge: %d %s", code, body)
	}
	if code, _ = m.call("POST", pd+"/purge", nil, true); code != 404 {
		t.Errorf("повтор: %d", code)
	}
	all, _ := m.svc.List(context.Background())
	if len(all) != 1 || all[0].ID != live {
		t.Fatalf("осталось %+v", all)
	}
	// массово
	extra := m.create("extra")
	m.call("POST", "/mtproto/"+itoa(extra)+"/revoke", nil, true)
	if code, body := m.call("POST", "/mtproto/purge-revoked", nil, true); code != 200 || !strings.Contains(body, `id="mt-secrets"`) {
		t.Fatalf("purge all: %d", code)
	}
	if all, _ = m.svc.List(context.Background()); len(all) != 1 {
		t.Fatalf("после массового: %+v", all)
	}
	if code, body := m.call("GET", "/mtproto/purge-revoked", nil, true); code != 200 || !strings.Contains(body, "нет") {
		t.Errorf("confirm пустой: %d %s", code, body)
	}
}

func TestMTProtoPurgeAuthAndCSRF(t *testing.T) {
	m := newMTFx(t, mtEP, nil)
	id := m.create("dead")
	m.call("POST", "/mtproto/"+itoa(id)+"/revoke", nil, true)
	for _, p := range []string{"/mtproto/" + itoa(id) + "/purge", "/mtproto/purge-revoked"} {
		if w := m.do(req{method: "GET", path: p}); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("GET %s без сессии: %d", p, w.Code)
		}
		if w := m.do(req{method: "POST", path: p, hdr: hx}); w.Code != 401 {
			t.Errorf("POST %s без сессии: %d", p, w.Code)
		}
		w := m.do(req{method: "POST", path: p, hdr: map[string]string{"HX-Request": "true", "Sec-Fetch-Site": "cross-site"}, cookies: []*http.Cookie{m.sid}})
		if w.Code != 403 {
			t.Errorf("cross-site POST %s: %d", p, w.Code)
		}
	}
	if all, _ := m.svc.List(context.Background()); len(all) != 1 {
		t.Error("секрет удалён без авторизации/CSRF")
	}
}

func TestMTProtoCrossOriginRejected(t *testing.T) {
	m := newMTFx(t, mtEP, nil)
	id := m.create("phones")
	for _, p := range []string{"/mtproto", "/mtproto/" + itoa(id) + "/revoke", "/mtproto/" + itoa(id) + "/rotate", "/mtproto/" + itoa(id) + "/link"} {
		w := m.do(req{method: "POST", path: p, form: url.Values{"name": {"evil"}, "code": {m.code()}},
			hdr: map[string]string{"HX-Request": "true", "Sec-Fetch-Site": "cross-site"}, cookies: []*http.Cookie{m.sid}})
		if w.Code != 403 {
			t.Errorf("cross-site POST %s: %d", p, w.Code)
		}
	}
	if all, _ := m.svc.List(context.Background()); len(all) != 1 || all[0].RevokedAt != nil {
		t.Error("кросс-доменный запрос изменил секреты")
	}
}

func TestMTProtoGolden(t *testing.T) {
	rows := []screens.MTSecretRow{
		{ID: 1, Name: "phones", Prefix: "ab12…", Status: "active", StatusText: "активен", StatusTone: "ok", CIDRs: []string{"203.0.113.0/24"}, Conns: "3 / 100", CanLink: true, CanRotate: true, CanRevoke: true},
		{ID: 2, Name: "old", Prefix: "cd34…", Status: "grace", StatusText: "grace до 02.03 12:00 UTC", StatusTone: "warn", Conns: "1", CanLink: true, CanRevoke: true},
		{ID: 3, Name: "dead", Prefix: "ef56…", Status: "revoked", StatusText: "отозван", StatusTone: "err", Conns: "—", CanPurge: true},
	}
	matrix := screens.MTMatrixVM{Enabled: true, DCs: []int{1, 2}, Agents: []screens.MTAgentRow{
		{ID: "a1", Capable: true, Streams: "5", Cells: []screens.MTCell{{Present: true, Up: true, Text: "41 мс · 3 стр."}, {Present: true, Text: "недоступен"}}},
		{ID: "old", Streams: "0", Cells: []screens.MTCell{{Text: "—"}, {Text: "—"}}},
	}}
	cases := map[string]templ.Component{
		"mtproto_page":           screens.MTProtoPage(screens.MTProtoVM{Rows: rows, Matrix: matrix}),
		"mtproto_page_empty":     screens.MTProtoPage(screens.MTProtoVM{Matrix: screens.MTMatrixVM{Enabled: true}}),
		"mtproto_page_disabled":  screens.MTProtoPage(screens.MTProtoVM{Disabled: true, NoEndpoint: true}),
		"mtproto_form_new":       screens.MTCreateForm(screens.MTFormVM{}),
		"mtproto_form_errors":    screens.MTCreateForm(screens.MTFormVM{Name: "!!", MaxConns: "x", Errors: api.FieldErrors{"name": "Буквы, цифры", "max_conns": "Целое число"}}),
		"mtproto_link_created":   screens.MTLinkPanel(mtStatic),
		"mtproto_link_totp":      screens.MTTOTPPrompt(screens.MTTOTPVM{ID: 1, Name: "phones", Error: "Неверный код."}),
		"mtproto_rotate":         screens.MTRotateForm(screens.MTRotateVM{ID: 1, Name: "phones", Grace: "24h"}),
		"mtproto_revoke":         screens.MTRevokeConfirm(screens.MTRevokeVM{ID: 1, Name: "phones"}),
		"mtproto_purge":          screens.MTPurgeConfirm(screens.MTPurgeVM{ID: 3, Name: "dead"}),
		"mtproto_purge_active":   screens.MTPurgeConfirm(screens.MTPurgeVM{ID: 1, Err: "Секрет ещё действует: сначала отзовите его (и дождитесь конца grace)."}),
		"mtproto_purge_all":      screens.MTPurgeAllConfirm(screens.MTPurgeAllVM{Count: 2}),
		"mtproto_purge_all_none": screens.MTPurgeAllConfirm(screens.MTPurgeAllVM{}),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { accGolden(t, name, c) })
	}
}
