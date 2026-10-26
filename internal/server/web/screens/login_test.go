package screens_test

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
)

var hx = map[string]string{"HX-Request": "true"}

func newLoginFx(t *testing.T, passwordOnly bool) *fx {
	t.Helper()
	f := newFx(t, passwordOnly)
	screens.MountLogin(f.rt, screens.LoginDeps{Auth: f.a, ClientIP: func(r *http.Request) string {
		if ip := r.Header.Get("X-Test-IP"); ip != "" {
			return ip
		}
		return "203.0.113.7"
	}})
	f.rt.Mount("GET /secret", f.a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})))
	return f
}

func pwForm(user, pw string) url.Values { return url.Values{"username": {user}, "password": {pw}} }

var alertRe = regexp.MustCompile(`(?s)<div class="alert alert-err" role="alert">(.*?)</div>`)

func alertText(body string) string {
	m := alertRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestLoginPageFull(t *testing.T) {
	f := newLoginFx(t, false)
	w := f.do(req{method: "GET", path: "/login"})
	if w.Code != 200 {
		t.Fatalf("code=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"<!doctype html>", "Вход в панель", "Продолжить", `hx-post="/login/password"`,
		`action="/login/password"`, `autocomplete="username"`, `autocomplete="current-password"`,
		"После 10 неудачных попыток вход блокируется на 15 минут", `id="login-card"`} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(body, `class="sidebar"`) {
		t.Error("на странице входа не должно быть сайдбара")
	}
	assertStrictCSP(t, body)
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP=%q", csp)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("нет no-store")
	}
}

func TestLoginTwoStepHTMX(t *testing.T) {
	f := newLoginFx(t, false)
	w := f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "alice-pw"), hdr: hx})
	if w.Code != 200 {
		t.Fatalf("шаг 1: code=%d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if strings.Contains(body, "<html") {
		t.Error("htmx получил целую страницу, нужен фрагмент")
	}
	for _, want := range []string{"Код подтверждения", `inputmode="numeric"`, `autocomplete="one-time-code"`, "Войти", "← Другой пользователь", `hx-post="/login/totp"`} {
		if !strings.Contains(body, want) {
			t.Errorf("шаг 2: нет %q", want)
		}
	}
	assertStrictCSP(t, body)
	pc := respCookie(w, auth.PendingCookie)
	if pc == nil || !pc.HttpOnly || !pc.Secure || pc.SameSite != http.SameSiteStrictMode || pc.Path != "/" || pc.MaxAge <= 0 {
		t.Fatalf("pending cookie: %+v", pc)
	}
	if strings.Contains(body, pc.Value) {
		t.Error("pending-токен утёк в HTML")
	}

	// шаг 2: код с пробелом в середине допустим
	code := f.code()
	w = f.do(req{method: "POST", path: "/login/totp", form: url.Values{"code": {code[:3] + " " + code[3:]}}, hdr: hx, cookies: []*http.Cookie{pc}})
	if w.Code != 200 || w.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("шаг 2: code=%d HX-Redirect=%q body=%s", w.Code, w.Header().Get("HX-Redirect"), w.Body)
	}
	sid := respCookie(w, auth.SessionCookie)
	if sid == nil || !sid.HttpOnly || !sid.Secure || sid.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie: %+v", sid)
	}
	if c := respCookie(w, auth.PendingCookie); c == nil || c.MaxAge >= 0 {
		t.Error("pending cookie должна сбрасываться")
	}
	if got := f.do(req{method: "GET", path: "/secret", cookies: []*http.Cookie{{Name: sid.Name, Value: sid.Value}}}); got.Code != 200 {
		t.Errorf("сессия не работает: %d", got.Code)
	}
	// уже вошёл -> /login перенаправляет на /
	if got := f.do(req{method: "GET", path: "/login", cookies: []*http.Cookie{{Name: sid.Name, Value: sid.Value}}}); got.Code != 302 || got.Header().Get("Location") != "/" {
		t.Errorf("GET /login с сессией: %d %q", got.Code, got.Header().Get("Location"))
	}
}

func TestLoginWithoutJS(t *testing.T) {
	f := newLoginFx(t, false)
	w := f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "alice-pw")})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<!doctype html>") || !strings.Contains(w.Body.String(), "Код подтверждения") {
		t.Fatalf("без htmx нужна полная страница шага 2: %d", w.Code)
	}
	pc := respCookie(w, auth.PendingCookie)
	w = f.do(req{method: "POST", path: "/login/totp", form: url.Values{"code": {f.code()}}, cookies: []*http.Cookie{pc}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" || respCookie(w, auth.SessionCookie) == nil {
		t.Fatalf("code=%d loc=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestLoginErrorDoesNotRevealWhatIsWrong(t *testing.T) {
	f := newLoginFx(t, false)
	unknown := f.do(req{method: "POST", path: "/login/password", form: pwForm("nobody", "x"), hdr: hx})
	badPass := f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "wrong"), hdr: hx})
	if unknown.Code != 401 || badPass.Code != 401 {
		t.Errorf("code=%d/%d", unknown.Code, badPass.Code)
	}
	a, b := alertText(unknown.Body.String()), alertText(badPass.Body.String())
	if a == "" || a != b {
		t.Fatalf("сообщения различаются: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "Неверный логин, пароль или код. Осталось попыток: ") {
		t.Errorf("сообщение: %q", a)
	}
	if respCookie(unknown, auth.PendingCookie) != nil || respCookie(badPass, auth.PendingCookie) != nil {
		t.Error("pending не должен выдаваться при ошибке")
	}
	if strings.Contains(badPass.Body.String(), "wrong") || strings.Contains(unknown.Body.String(), `value="x"`) {
		t.Error("пароль не должен возвращаться в HTML")
	}
	if !strings.Contains(badPass.Body.String(), `value="alice"`) {
		t.Error("логин должен подставляться обратно")
	}

	// неверный код — то же сообщение, шаг 2 остаётся
	ok := f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "alice-pw"), hdr: hx})
	pc := respCookie(ok, auth.PendingCookie)
	bad := f.do(req{method: "POST", path: "/login/totp", form: url.Values{"code": {"000000"}}, hdr: hx, cookies: []*http.Cookie{pc}})
	if bad.Code != 401 || !strings.Contains(bad.Body.String(), "Код подтверждения") {
		t.Fatalf("code=%d", bad.Code)
	}
	if got := alertText(bad.Body.String()); !strings.HasPrefix(got, "Неверный логин, пароль или код. Осталось попыток: ") {
		t.Errorf("сообщение: %q", got)
	}
}

func TestLoginRateLimitAndLockout(t *testing.T) {
	f := newLoginFx(t, false)
	var last string
	for range 5 {
		w := f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "bad"), hdr: hx})
		last = w.Body.String()
	}
	if !strings.Contains(last, "Осталось попыток: 5") {
		t.Errorf("после 5 неудач должно остаться 5: %s", alertText(last))
	}
	w := f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "alice-pw"), hdr: hx})
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" || !strings.Contains(w.Body.String(), "Слишком много попыток") {
		t.Fatalf("6-я попытка в минуту: %d %q %s", w.Code, w.Header().Get("Retry-After"), alertText(w.Body.String()))
	}

	// ещё 5 неудач с другого IP (лимит 5/мин считается на IP+user) -> порог 10 -> блокировка
	other := map[string]string{"HX-Request": "true", "X-Test-IP": "198.51.100.9"}
	for range 5 {
		f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "bad"), hdr: other})
	}
	third := map[string]string{"HX-Request": "true", "X-Test-IP": "198.51.100.10"}
	w = f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "alice-pw"), hdr: third})
	if w.Code != 429 || w.Header().Get("Retry-After") != "900" {
		t.Fatalf("lockout: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	if got := alertText(w.Body.String()); got != "Вход временно заблокирован, попробуйте через 15 мин." {
		t.Errorf("сообщение: %q", got)
	}
	if respCookie(w, auth.PendingCookie) != nil {
		t.Error("при блокировке pending не выдаётся")
	}
}

func TestLoginPasswordOnlyMode(t *testing.T) {
	f := newLoginFx(t, true)
	w := f.do(req{method: "POST", path: "/login/password", form: pwForm("bob", "bob-pw"), hdr: hx})
	if w.Code != 200 || w.Header().Get("HX-Redirect") != "/" || respCookie(w, auth.SessionCookie) == nil {
		t.Fatalf("allow_password_only: шаг TOTP должен пропускаться: %d %s", w.Code, w.Body)
	}
	// у alice TOTP настроен -> второй шаг остаётся
	w = f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "alice-pw"), hdr: hx})
	if !strings.Contains(w.Body.String(), "Код подтверждения") {
		t.Error("у пользователя с TOTP второй шаг обязателен")
	}
}

func TestLoginTOTPNotConfigured(t *testing.T) {
	f := newLoginFx(t, false)
	w := f.do(req{method: "POST", path: "/login/password", form: pwForm("bob", "bob-pw"), hdr: hx})
	if w.Code != 403 || !strings.Contains(w.Body.String(), "tgproxy totp enroll") || respCookie(w, auth.SessionCookie) != nil {
		t.Fatalf("code=%d %s", w.Code, w.Body)
	}
}

func TestLoginPendingMissingOrReset(t *testing.T) {
	f := newLoginFx(t, false)
	w := f.do(req{method: "POST", path: "/login/totp", form: url.Values{"code": {"123456"}}, hdr: hx})
	if w.Code != 401 || !strings.Contains(w.Body.String(), "Сессия входа истекла") || !strings.Contains(w.Body.String(), "Вход в панель") {
		t.Fatalf("без pending: %d %s", w.Code, w.Body)
	}

	ok := f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "alice-pw"), hdr: hx})
	pc := respCookie(ok, auth.PendingCookie)
	w = f.do(req{method: "POST", path: "/login/reset", hdr: hx, cookies: []*http.Cookie{pc}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Вход в панель") {
		t.Fatalf("reset htmx: %d", w.Code)
	}
	if c := respCookie(w, auth.PendingCookie); c == nil || c.MaxAge >= 0 {
		t.Error("reset должен сбрасывать pending cookie")
	}
	// старый pending больше не работает
	w = f.do(req{method: "POST", path: "/login/totp", form: url.Values{"code": {f.code()}}, hdr: hx, cookies: []*http.Cookie{pc}})
	if w.Code != 401 || respCookie(w, auth.SessionCookie) != nil {
		t.Errorf("pending после reset должен быть недействителен: %d", w.Code)
	}
	// без JS -> 303 /login
	w = f.do(req{method: "POST", path: "/login/reset", cookies: []*http.Cookie{pc}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("reset без htmx: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestLogout(t *testing.T) {
	f := newLoginFx(t, false)
	sid := f.sessionCookie("alice")
	w := f.do(req{method: "POST", path: "/logout", form: url.Values{"csrf": {"x"}}, cookies: []*http.Cookie{sid}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("logout: %d %q", w.Code, w.Header().Get("Location"))
	}
	if c := respCookie(w, auth.SessionCookie); c == nil || c.MaxAge >= 0 {
		t.Error("cookie сессии должна сбрасываться")
	}
	if got := f.do(req{method: "GET", path: "/secret", cookies: []*http.Cookie{sid}}); got.Code != 302 {
		t.Errorf("сессия должна быть инвалидирована в БД: %d", got.Code)
	}
	// htmx-вариант
	sid2 := f.sessionCookie("alice")
	w = f.do(req{method: "POST", path: "/logout", hdr: hx, cookies: []*http.Cookie{sid2}})
	if w.Header().Get("HX-Redirect") != "/login" {
		t.Errorf("HX-Redirect=%q", w.Header().Get("HX-Redirect"))
	}
	// без сессии не падает
	if w = f.do(req{method: "POST", path: "/logout"}); w.Code != http.StatusSeeOther {
		t.Errorf("logout без сессии: %d", w.Code)
	}
}

func TestLoginCrossOriginRejected(t *testing.T) {
	f := newLoginFx(t, false)
	w := f.do(req{method: "POST", path: "/login/password", form: pwForm("alice", "alice-pw"),
		hdr: map[string]string{"Sec-Fetch-Site": "cross-site"}})
	if w.Code != 403 {
		t.Errorf("cross-site POST: %d", w.Code)
	}
}

func TestLoginGolden(t *testing.T) {
	cases := map[string]screens.LoginView{
		"login_card_password": {},
		"login_card_error":    {Username: "alice", Message: "Неверный логин, пароль или код. Осталось попыток: 3."},
		"login_card_totp":     {Step: screens.StepTOTP},
		"login_card_locked":   {Message: "Вход временно заблокирован, попробуйте через 15 мин."},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) { accGolden(t, name, screens.LoginCard(v)) })
	}
}
