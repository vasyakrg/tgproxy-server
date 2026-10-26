package screens_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
	"github.com/vasyakrg/tgproxy-server/internal/server/updater"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// fakeUpd — UpdateBackend: считает вызовы Stage, ведёт staged как настоящий Updater.
type fakeUpd struct {
	mu       sync.Mutex
	st       updater.Status
	rel      updater.Release
	checkErr error
	stageErr error
	stages   int
	caches   int
	cacheErr error
	src      string
}

func (f *fakeUpd) Check(context.Context) (updater.Release, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.checkErr != nil {
		f.st.LastError = f.checkErr.Error()
		return updater.Release{}, f.checkErr
	}
	f.st.CheckedAt = time.Now()
	f.st.Available, f.st.Notes = "", ""
	if f.rel.Version != f.st.Current {
		f.st.Available, f.st.Notes = f.rel.Version, f.rel.Notes
	}
	f.st.LastError = ""
	return f.rel, nil
}

func (f *fakeUpd) Stage(_ context.Context, v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stageErr != nil {
		f.st.LastError = f.stageErr.Error()
		return f.stageErr
	}
	f.stages++
	f.st.Staged = v
	return nil
}

func (f *fakeUpd) Cache(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.caches++
	return f.cacheErr
}

func (f *fakeUpd) Status() updater.Status { f.mu.Lock(); defer f.mu.Unlock(); return f.st }

func (f *fakeUpd) SetSource(_ updater.Source, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.src, f.st.Source = name, name
	f.rel = updater.Release{Version: "1.6.0", Tag: "v1.6.0"}
}

type usersDir map[string]auth.User

func (u usersDir) Names() []string {
	out := make([]string, 0, len(u))
	for n := range u {
		out = append(out, n)
	}
	if len(out) == 2 && out[0] > out[1] {
		out[0], out[1] = out[1], out[0]
	}
	return out
}
func (u usersDir) Get(n string) (auth.User, bool) { x, ok := u[n]; return x, ok }

type sysFx struct {
	*fx
	upd    *fakeUpd
	svc    *api.SystemService
	nsvc   *api.NotificationsService
	sid    *http.Cookie
	upload string
	key    minisign.PrivateKey
	pub    minisign.PublicKey
}

func newSysFx(t *testing.T, mut func(*api.SystemConfig, *api.NotificationsConfig, *fakeUpd)) *sysFx {
	t.Helper()
	f := newFx(t, false)
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &sysFx{fx: f, upd: &fakeUpd{
		st:  updater.Status{Current: "1.4.1", Source: "github"},
		rel: updater.Release{Version: "1.5.0", Tag: "v1.5.0", Notes: "## Новое\n- <b>жирный</b>", Assets: []updater.Asset{{Name: "tgproxy_1.5.0_amd64.deb", Size: 15 << 20}}},
	}, upload: filepath.Join(t.TempDir(), "upload"), key: priv, pub: pub}
	scfg := api.SystemConfig{
		Updater: s.upd, Source: api.SourceInfo{Kind: "github", Detail: "vasyakrg/tgproxy-server"}, Version: "1.4.1",
		UploadDir: s.upload, Arch: "amd64", PubKeys: []verify.PublicKey{pub}, Audit: f.st.Audit(),
		ResultPath: filepath.Join(t.TempDir(), "result.json"),
	}
	tg := notify.NewToggles(f.st.Settings())
	ncfg := api.NotificationsConfig{
		Sender: notify.NewNotifier(f.st.Outbox(), notify.Options{Enabled: tg.Enabled}), BotID: "7012345678",
		Toggles: tg, Audit: f.st.Audit(), Outbox: f.st.Outbox(),
		Admins: usersDir{"alice": {TelegramID: 111, TOTPSecretEnc: "x"}, "bob": {}},
	}
	if mut != nil {
		mut(&scfg, &ncfg, s.upd)
	}
	s.svc = api.NewSystemService(scfg)
	s.nsvc = api.NewNotificationsService(ncfg)
	screens.MountSystem(f.rt, screens.SystemDeps{Auth: f.a, Update: s.svc, Notify: s.nsvc})
	s.sid = f.sessionCookie("alice")
	return s
}

func (s *sysFx) call(method, path string, form url.Values, htmx bool) *httptest.ResponseRecorder {
	s.t.Helper()
	hd := map[string]string{}
	if htmx {
		hd["HX-Request"] = "true"
	}
	return s.do(req{method: method, path: path, form: form, hdr: hd, cookies: []*http.Cookie{s.sid}})
}

func (s *sysFx) multipart(path string, files map[string][2]string, hdr map[string]string) *httptest.ResponseRecorder {
	s.t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, field := range []string{"deb", "checksums", "signature"} {
		fl, ok := files[field]
		if !ok {
			continue
		}
		fw, err := w.CreateFormFile(field, fl[0])
		if err != nil {
			s.t.Fatal(err)
		}
		_, _ = fw.Write([]byte(fl[1]))
	}
	_ = w.Close()
	hr := httptest.NewRequestWithContext(context.Background(), "POST", path, &buf)
	hr.RemoteAddr = "203.0.113.7:4000"
	hr.Header.Set("Content-Type", w.FormDataContentType())
	hr.Header.Set("HX-Request", "true")
	for k, v := range hdr {
		hr.Header.Set(k, v)
	}
	hr.AddCookie(s.sid)
	rec := httptest.NewRecorder()
	s.rt.ServeHTTP(rec, hr)
	return rec
}

// release подписывает релиз ключом key.
func (s *sysFx) release(version string, key minisign.PrivateKey) map[string][2]string {
	deb := strings.Repeat("deb-"+version, 500)
	name := fmt.Sprintf("tgproxy_%s_amd64.deb", version)
	h := sha256.Sum256([]byte(deb))
	sums := hex.EncodeToString(h[:]) + "  " + name + "\n"
	r := minisign.NewReader(strings.NewReader(sums))
	_, _ = io.Copy(io.Discard, r)
	sig := r.SignWithComments(key, "timestamp:1 file:checksums.txt", "t")
	return map[string][2]string{
		"deb": {name, deb}, "checksums": {"checksums.txt", sums}, "signature": {"checksums.txt.minisig", string(sig)},
	}
}

func hasToast(t *testing.T, rec *httptest.ResponseRecorder, kind, text string) {
	t.Helper()
	h := rec.Header().Get("HX-Trigger")
	if !strings.Contains(h, `"kind":"`+kind+`"`) || !strings.Contains(h, text) {
		t.Fatalf("тост %s/%q не найден в HX-Trigger: %s", kind, text, h)
	}
}

func uni(s string) string { // HX-Trigger кодирует не-ASCII как \uXXXX
	var b strings.Builder
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

func TestSystemRequiresSessionAndSameOrigin(t *testing.T) {
	s := newSysFx(t, nil)
	if w := s.do(req{method: "GET", path: "/system"}); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Errorf("GET /system без сессии: %d", w.Code)
	}
	for _, p := range []string{"/system/check", "/system/install", "/system/upload", "/system/notify/test", "/system/notify/events"} {
		if w := s.do(req{method: "POST", path: p, form: url.Values{"confirm": {"yes"}, "version": {"1.5.0"}}, hdr: hx}); w.Code != 401 {
			t.Errorf("POST %s без сессии: %d", p, w.Code)
		}
		cross := map[string]string{"HX-Request": "true", "Origin": "https://evil.example"}
		w := s.do(req{method: "POST", path: p, form: url.Values{"confirm": {"yes"}, "version": {"1.5.0"}, "present": {"1"}}, hdr: cross, cookies: []*http.Cookie{s.sid}})
		if w.Code != http.StatusForbidden {
			t.Errorf("кросс-доменный POST %s: %d", p, w.Code)
		}
	}
	if s.upd.stages != 0 {
		t.Fatal("Stage вызван без сессии или с чужого origin")
	}
	if items, _ := s.st.Outbox().Pending(context.Background(), 5); len(items) != 0 {
		t.Fatal("тест уведомления поставлен без сессии")
	}
	if w := s.call("POST", "/system/install", url.Values{"confirm": {"yes"}, "version": {"1.5.0"}}, false); w.Code != 400 {
		t.Errorf("не htmx POST: %d", w.Code)
	}
	if w := s.call("GET", "/system/upload", nil, false); w.Code != http.StatusSeeOther {
		t.Errorf("не htmx GET: %d", w.Code)
	}
}

func TestSystemPage(t *testing.T) {
	s := newSysFx(t, nil)
	if _, err := s.svc.Check(context.Background(), api.Actor{User: "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.Audit().Append(context.Background(), auditLogin("alice")); err != nil {
		t.Fatal(err)
	}
	w := s.call("GET", "/system", nil, false)
	if w.Code != 200 {
		t.Fatalf("code=%d", w.Code)
	}
	body := w.Body.String()
	assertStrictCSP(t, body)
	for _, want := range []string{
		"<title>Система — tgproxy</title>", `aria-current="page"`, "Обновление сервера", "Установлено", "v1.4.1", "Доступно", "v1.5.0",
		"Проверено", "сегодня", "GitHub Releases", "Через HTTP-прокси", "Через агента", "Загрузить файл", "vasyakrg/tgproxy-server",
		`aria-label="Проверить сейчас"`, `aria-label="Загрузить файл обновления"`, "Установить v1.5.0",
		"tgproxy_1.5.0_amd64.deb · 15,0 МБ", "подпись minisign", "sha256", "проверяется при установке", "откат на v1.4.1",
		"Что нового в v1.5.0", "&lt;b&gt;жирный&lt;/b&gt;",
		"Уведомления в Telegram", "бот 7012345678 подключён", `aria-label="Отправить тест"`, "telegram_id", "alice", "включена", "bob", "не задан",
		"Какие события отправлять", "Агент недоступен", "Сертификат входа истекает", `hx-post="/system/notify/events"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(body, "<b>жирный</b>") {
		t.Error("release notes не экранированы")
	}
	if strings.Contains(body, `hx-trigger="every`) {
		t.Error("опрос без staged не нужен")
	}
	if got := strings.Count(body, `name="event"`); got != len(notify.Catalog()) {
		t.Errorf("переключателей %d, want %d", got, len(notify.Catalog()))
	}
}

func auditLogin(user string) store.AuditEntry {
	return store.AuditEntry{At: time.Now().Add(-time.Hour), Actor: user, Action: auth.AuditLoginOK, Target: user}
}

func TestSystemUpdatesDisabledPage(t *testing.T) {
	s := newSysFx(t, func(c *api.SystemConfig, n *api.NotificationsConfig, _ *fakeUpd) {
		c.Updater = nil
		n.Sender, n.BotID = nil, ""
	})
	w := s.call("GET", "/system", nil, false)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Обновления выключены в конфиге") || strings.Contains(body, "Установить v") {
		t.Fatalf("code=%d", w.Code)
	}
	if !strings.Contains(body, "notify.bot_token_file") || strings.Contains(body, `aria-label="Отправить тест"`) {
		t.Error("без бота кнопки теста быть не должно")
	}
	for _, p := range []string{"/system/check", "/system/install", "/system/upload"} {
		w := s.call("POST", p, url.Values{"confirm": {"yes"}, "version": {"1.5.0"}}, true)
		if w.Code != 200 || !strings.Contains(w.Header().Get("HX-Trigger"), "toast") {
			t.Errorf("%s: %d %s", p, w.Code, w.Header().Get("HX-Trigger"))
		}
	}
	if w := s.call("GET", "/system/install", nil, true); w.Code != 200 {
		t.Errorf("GET install: %d", w.Code)
	}
	if w := s.call("POST", "/system/notify/test", nil, true); w.Code != 200 || !strings.Contains(w.Header().Get("HX-Trigger"), uni("не настроены")) {
		t.Errorf("test: %d %s", w.Code, w.Header().Get("HX-Trigger"))
	}
}

func TestSystemCheck(t *testing.T) {
	s := newSysFx(t, nil)
	w := s.call("POST", "/system/check", nil, true)
	if w.Code != 200 {
		t.Fatalf("code=%d", w.Code)
	}
	hasToast(t, w, "ok", uni("Доступна версия v1.5.0"))
	if !strings.Contains(w.Body.String(), `id="sys-update"`) || !strings.Contains(w.Body.String(), "Установить v1.5.0") {
		t.Error("карточка не обновилась")
	}
	// нечего ставить
	s.upd.rel.Version = "1.4.1"
	hasToast(t, s.call("POST", "/system/check", nil, true), "info", uni("последняя версия"))
	// ошибка источника
	s.upd.checkErr = errors.New("dial tcp: i/o timeout")
	w = s.call("POST", "/system/check", nil, true)
	hasToast(t, w, "err", uni("Источник обновлений не ответил"))
	if !strings.Contains(w.Body.String(), "i/o timeout") {
		t.Error("причина ошибки не показана в карточке")
	}
}

func TestSystemInstallFlow(t *testing.T) {
	s := newSysFx(t, nil)
	s.call("POST", "/system/check", nil, true)

	w := s.call("GET", "/system/install", nil, true)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Установить v1.5.0?") || !strings.Contains(body, `name="confirm" value="yes"`) || !strings.Contains(body, "откат на v1.4.1") {
		t.Fatalf("диалог: %d %s", w.Code, body)
	}
	// без confirm — 400, Stage не вызван
	if w = s.call("POST", "/system/install", url.Values{"version": {"1.5.0"}}, true); w.Code != 400 || s.upd.stages != 0 {
		t.Fatalf("без confirm: %d stages=%d", w.Code, s.upd.stages)
	}
	if w = s.call("POST", "/system/install", url.Values{"version": {"junk"}, "confirm": {"yes"}}, true); w.Code != 400 || s.upd.stages != 0 {
		t.Fatalf("плохая версия: %d", w.Code)
	}
	// подтверждённая установка
	w = s.call("POST", "/system/install", url.Values{"version": {"v1.5.0"}, "confirm": {"yes"}}, true)
	if w.Code != 200 || s.upd.stages != 1 {
		t.Fatalf("install: %d stages=%d", w.Code, s.upd.stages)
	}
	hasToast(t, w, "ok", uni("поставлена в очередь"))
	body = w.Body.String()
	if !strings.Contains(body, `id="sys-modal-wrap"`) || !strings.Contains(body, `hx-swap-oob="true"`) ||
		!strings.Contains(body, `hx-trigger="every 5s"`) || strings.Contains(body, "Установить v1.5.0</button>") {
		t.Fatalf("карточка после установки: %s", body)
	}
	// повторное нажатие — второй request не создаётся
	w = s.call("POST", "/system/install", url.Values{"version": {"1.5.0"}, "confirm": {"yes"}}, true)
	if s.upd.stages != 1 {
		t.Fatalf("Stage вызван повторно: %d", s.upd.stages)
	}
	hasToast(t, w, "warn", uni("уже поставлено в очередь"))
	// диалог больше не предлагается
	if w = s.call("GET", "/system/install", nil, true); !strings.Contains(w.Body.String(), "Нет версии для установки") {
		t.Errorf("диалог при staged: %s", w.Body)
	}
	// опрос карточки
	if w = s.call("GET", "/system/update", nil, true); w.Code != 200 || !strings.Contains(w.Body.String(), "ожидает установки") {
		t.Errorf("карточка: %d", w.Code)
	}
	if w = s.call("GET", "/system/update", nil, false); w.Code != http.StatusSeeOther {
		t.Errorf("не htmx: %d", w.Code)
	}
}

func TestSystemInstallErrors(t *testing.T) {
	s := newSysFx(t, nil)
	s.call("POST", "/system/check", nil, true)
	s.upd.stageErr = fmt.Errorf("%w", verify.ErrBadSignature)
	w := s.call("POST", "/system/install", url.Values{"version": {"1.5.0"}, "confirm": {"yes"}}, true)
	hasToast(t, w, "err", uni("не прошёл проверку"))
	if w.Code != 200 || s.upd.stages != 0 {
		t.Fatalf("%d", w.Code)
	}
	s.upd.stageErr = updater.ErrBusy
	hasToast(t, s.call("POST", "/system/install", url.Values{"version": {"1.5.0"}, "confirm": {"yes"}}, true), "warn", uni("уже выполняется"))
}

func TestSystemInstallResultShown(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "result.json")
	if err := os.WriteFile(rp, []byte(`{"version":"1.5.0","ok":false,"rolled_back":true,"error":"healthz timeout","at":"2026-03-01T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newSysFx(t, func(c *api.SystemConfig, _ *api.NotificationsConfig, _ *fakeUpd) { c.ResultPath = rp })
	body := s.call("GET", "/system", nil, false).Body.String()
	if !strings.Contains(body, "не удалась, выполнен откат") || !strings.Contains(body, "healthz timeout") || !strings.Contains(body, "alert-warn") {
		t.Errorf("итог установки не показан")
	}
	if err := os.WriteFile(rp, []byte(`{"version":"1.5.0","ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if body = s.call("GET", "/system", nil, false).Body.String(); !strings.Contains(body, "v1.5.0 установлена") || !strings.Contains(body, "alert-ok") {
		t.Errorf("успех не показан")
	}
	if err := os.WriteFile(rp, []byte(`{"version":"1.5.0","ok":false,"error":"dpkg failed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if body = s.call("GET", "/system", nil, false).Body.String(); !strings.Contains(body, "не удалась") || !strings.Contains(body, "alert-err") {
		t.Errorf("сбой не показан")
	}
}

func TestSystemUpload(t *testing.T) {
	s := newSysFx(t, nil)
	if w := s.call("GET", "/system/upload", nil, true); w.Code != 200 || !strings.Contains(w.Body.String(), `enctype="multipart/form-data"`) ||
		!strings.Contains(w.Body.String(), "до 100 МБ") {
		t.Fatalf("форма: %d", w.Code)
	}
	empty := func() bool {
		ents, _ := os.ReadDir(s.upload)
		return len(ents) == 0
	}
	// без .minisig
	rel := s.release("1.6.0", s.key)
	delete(rel, "signature")
	w := s.multipart("/system/upload", rel, nil)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "нужны все три файла") || !empty() {
		t.Fatalf("без minisig: %d %s", w.Code, w.Body)
	}
	// чужая подпись
	_, other, _ := minisign.GenerateKey(rand.Reader)
	w = s.multipart("/system/upload", s.release("1.6.0", other), nil)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "подпись checksums.txt не принята") || !empty() {
		t.Fatalf("чужая подпись: %d %s", w.Code, w.Body)
	}
	// не multipart
	if w = s.call("POST", "/system/upload", url.Values{"a": {"b"}}, true); w.Code != 400 {
		t.Errorf("не multipart: %d", w.Code)
	}
	// кросс-доменная загрузка
	if w = s.multipart("/system/upload", s.release("1.6.0", s.key), map[string]string{"Origin": "https://evil.example"}); w.Code != 403 || !empty() {
		t.Fatalf("cross-origin: %d", w.Code)
	}
	// успешная загрузка
	w = s.multipart("/system/upload", s.release("1.6.0", s.key), nil)
	if w.Code != 200 {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	hasToast(t, w, "ok", uni("подпись проверена"))
	if s.upd.src != "" || empty() || s.svc.Version().Uploaded != "1.6.0" {
		t.Fatalf("источник=%q uploaded=%q", s.upd.src, s.svc.Version().Uploaded)
	}
	// загруженная версия ставится кнопкой «Установить»
	if b := s.call("GET", "/system", nil, false).Body.String(); !strings.Contains(b, "Установить v1.6.0") {
		t.Fatal("нет кнопки установки загруженной версии")
	}
}

func TestSystemUploadTooLarge(t *testing.T) {
	s := newSysFx(t, func(c *api.SystemConfig, _ *api.NotificationsConfig, _ *fakeUpd) { c.MaxUpload = 1 << 10 })
	w := s.multipart("/system/upload", s.release("1.6.0", s.key), nil)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "больше допустимого") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if ents, _ := os.ReadDir(s.upload); len(ents) != 0 {
		t.Fatal("остались файлы")
	}
}

func TestSystemNotifyTestAndEvents(t *testing.T) {
	s := newSysFx(t, nil)
	w := s.call("POST", "/system/notify/test", nil, true)
	hasToast(t, w, "ok", uni("поставлено в очередь"))
	items, _ := s.st.Outbox().Pending(context.Background(), 5)
	if len(items) != 1 || items[0].Type != notify.TestType || !strings.Contains(items[0].Text, "alice") {
		t.Fatalf("outbox: %+v", items)
	}
	hasToast(t, s.call("POST", "/system/notify/test", nil, true), "warn", uni("совсем недавно"))
	if items, _ = s.st.Outbox().Pending(context.Background(), 5); len(items) != 1 {
		t.Fatal("повторный тест создал второе сообщение")
	}

	// выключаем два типа: остальные чекбоксы остаются отмеченными
	form := url.Values{"present": {"1"}}
	for _, e := range notify.Catalog() {
		if e.Type != notify.Overload && e.Type != notify.AgentEnrolled {
			form.Add("event", string(e.Type))
		}
	}
	w = s.call("POST", "/system/notify/events", form, true)
	if w.Code != http.StatusNoContent {
		t.Fatalf("events: %d %s", w.Code, w.Body)
	}
	hasToast(t, w, "ok", uni("сохранены"))
	body := s.call("GET", "/system", nil, false).Body.String()
	if strings.Contains(body, `value="overload" checked`) || !strings.Contains(body, `value="agent_down" checked`) {
		t.Errorf("переключатели не соответствуют сохранённым")
	}
	if s.nsvc == nil {
		t.Fatal()
	}
	// неизвестный тип и форма без present
	bad := url.Values{"present": {"1"}, "event": {"nope"}}
	if w = s.call("POST", "/system/notify/events", bad, true); w.Code != 400 {
		t.Errorf("неизвестный тип: %d", w.Code)
	}
	if w = s.call("POST", "/system/notify/events", url.Values{"event": {"agent_down"}}, true); w.Code != 400 {
		t.Errorf("без present: %d", w.Code)
	}
}

type brokenToggles struct{ setErr, statesErr error }

func (b brokenToggles) States(context.Context) (map[notify.AlertType]bool, error) {
	return nil, b.statesErr
}
func (b brokenToggles) Set(context.Context, map[notify.AlertType]bool) error { return b.setErr }

func TestSystemPageStates(t *testing.T) {
	s := newSysFx(t, func(c *api.SystemConfig, n *api.NotificationsConfig, u *fakeUpd) {
		u.st.Source, u.st.Available, u.st.LastError = "agent", "1.5.0", "подпись отклонена"
		u.rel.Assets = []updater.Asset{{Name: "tgproxy_1.5.0_amd64.deb", Size: 5 << 10}}
		c.Source = api.SourceInfo{Kind: "agent", Detail: "fra-1"}
		n.Admins = usersDir{"alice": {TelegramID: 111, TOTPSecretEnc: "x"}, "bob": {Disabled: true}}
		n.Toggles = brokenToggles{statesErr: errors.New("db down")}
	})
	if _, err := s.st.Outbox().Enqueue(context.Background(), store.OutboxItem{DedupKey: "k", Type: "agent_down", State: store.OutboxFiring}); err != nil {
		t.Fatal(err)
	}
	s.call("POST", "/system/check", nil, true)
	s.upd.st.LastError = "подпись отклонена"
	body := s.call("GET", "/system", nil, false).Body.String()
	for _, want := range []string{
		"fra-1", "5 КБ", "подпись отклонена", `data-status="failed"`, "отключён", "в очереди: 1", "Не удалось прочитать настройки уведомлений",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
}

func TestSystemPageStagedChecksOK(t *testing.T) {
	s := newSysFx(t, func(_ *api.SystemConfig, _ *api.NotificationsConfig, u *fakeUpd) {
		u.st.Available, u.st.Staged, u.st.Source = "1.5.0", "1.5.0", "upload"
		u.rel.Assets = []updater.Asset{{Name: "tgproxy_1.5.0_amd64.deb", Size: 300}}
	})
	s.call("POST", "/system/check", nil, true)
	body := s.call("GET", "/system", nil, false).Body.String()
	if strings.Count(body, `data-status="ok"`) != 3 || !strings.Contains(body, "300 Б") || !strings.Contains(body, `hx-trigger="every 5s"`) {
		t.Errorf("чеклист staged-пакета")
	}
}

func TestSystemNotifyEventsSaveFailure(t *testing.T) {
	s := newSysFx(t, func(_ *api.SystemConfig, n *api.NotificationsConfig, _ *fakeUpd) {
		n.Toggles = okThenBroken{}
	})
	w := s.call("POST", "/system/notify/events", url.Values{"present": {"1"}, "event": {"agent_down"}}, true)
	if w.Code != 200 || w.Header().Get("HX-Retarget") != "#sys-events" || w.Header().Get("HX-Reswap") != "outerHTML" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	hasToast(t, w, "err", uni("Не удалось сохранить"))
	if !strings.Contains(w.Body.String(), `id="sys-events"`) {
		t.Error("форма не возвращена")
	}
}

type okThenBroken struct{}

func (okThenBroken) States(context.Context) (map[notify.AlertType]bool, error) {
	out := map[notify.AlertType]bool{}
	for _, e := range notify.Catalog() {
		out[e.Type] = true
	}
	return out, nil
}
func (okThenBroken) Set(context.Context, map[notify.AlertType]bool) error {
	return errors.New("disk full")
}

func TestSystemNotifyTestFailure(t *testing.T) {
	s := newSysFx(t, func(_ *api.SystemConfig, n *api.NotificationsConfig, _ *fakeUpd) { n.Sender = badSender{} })
	hasToast(t, s.call("POST", "/system/notify/test", nil, true), "err", uni("Не удалось поставить тест"))
}

type badSender struct{}

func (badSender) SendTest(context.Context, string) error { return errors.New("db down") }
