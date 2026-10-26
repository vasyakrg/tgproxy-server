package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func httpLogin(t *testing.T, e *env) (sid *http.Cookie) {
	t.Helper()
	w := e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"alice-pw"}`, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"totp_required":true`) {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	pend := findCookie(w, PendingCookie)
	if pend == nil || !pend.HttpOnly || !pend.Secure {
		t.Fatalf("pending cookie: %+v", pend)
	}
	if strings.Contains(w.Body.String(), pend.Value) {
		t.Fatal("pending token leaked into body")
	}
	w = e.do("POST", "/api/v1/auth/totp", `{"code":"`+e.code(0)+`"}`, nil, pend)
	if w.Code != 200 {
		t.Fatalf("totp: %d %s", w.Code, w.Body)
	}
	return findCookie(w, SessionCookie)
}

func TestCookieFlags(t *testing.T) {
	e := newEnv(t, false)
	c := httpLogin(t, e)
	if c == nil || c.Name != "__Host-sid" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie: %+v", c)
	}
	if c.MaxAge <= 0 || c.MaxAge > int(SessionAbsTTL.Seconds()) {
		t.Fatalf("maxage %d", c.MaxAge)
	}
	// Set-Cookie строкой
	w := e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"alice-pw"}`, nil)
	w = e.do("POST", "/api/v1/auth/totp", `{"code":"`+e.code(1)+`"}`, nil, findCookie(w, PendingCookie))
	var line string
	for _, h := range w.Result().Header.Values("Set-Cookie") {
		if strings.HasPrefix(h, "__Host-sid=") {
			line = h
		}
	}
	for _, want := range []string{"Secure", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q missing in %q", want, line)
		}
	}
	// pending очищен
	if p := findCookie(w, PendingCookie); p == nil || p.MaxAge >= 0 {
		t.Fatalf("pending not cleared: %+v", p)
	}
}

func TestMeAndLogoutInvalidates(t *testing.T) {
	e := newEnv(t, false)
	c := httpLogin(t, e)
	w := e.do("GET", "/api/v1/auth/me", "", nil, c)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"username":"alice"`) || !strings.Contains(w.Body.String(), "Alice") {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	if w := e.do("POST", "/api/v1/auth/logout", "", nil, c); w.Code != http.StatusNoContent || findCookie(w, SessionCookie).MaxAge >= 0 {
		t.Fatalf("logout: %d", w.Code)
	}
	if _, err := e.st.Sessions().Get(context.Background(), hashToken(c.Value)); err == nil {
		t.Fatal("session still in DB")
	}
	if w := e.do("GET", "/api/v1/auth/me", "", nil, c); w.Code != 401 {
		t.Fatalf("me after logout: %d", w.Code)
	}
	// повторный logout без сессии — идемпотентен
	if w := e.do("POST", "/api/v1/auth/logout", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("%d", w.Code)
	}
}

func TestIdleTimeout(t *testing.T) {
	e := newEnv(t, false)
	c := httpLogin(t, e)
	e.clock.advance(29 * time.Minute)
	if w := e.do("GET", "/api/v1/auth/me", "", nil, c); w.Code != 200 { // продлевает idle
		t.Fatalf("29m: %d", w.Code)
	}
	e.clock.advance(29 * time.Minute) // 58m от входа, но 29m idle
	if w := e.do("GET", "/api/v1/auth/me", "", nil, c); w.Code != 200 {
		t.Fatalf("sliding: %d", w.Code)
	}
	e.clock.advance(31 * time.Minute)
	if w := e.do("GET", "/api/v1/auth/me", "", nil, c); w.Code != 401 {
		t.Fatalf("idle 31m: %d", w.Code)
	}
}

func TestAbsoluteTimeout(t *testing.T) {
	e := newEnv(t, false)
	c := httpLogin(t, e)
	for i := 0; i < 26; i++ { // каждые 29 минут — idle не истекает
		e.clock.advance(29 * time.Minute)
		if w := e.do("GET", "/api/v1/auth/me", "", nil, c); w.Code != 200 && e.clock.off < SessionAbsTTL {
			t.Fatalf("step %d: %d", i, w.Code)
		}
	}
	if e.clock.off <= SessionAbsTTL {
		t.Fatal("test did not pass 12h")
	}
	if w := e.do("GET", "/api/v1/auth/me", "", nil, c); w.Code != 401 {
		t.Fatalf("abs 12h: %d", w.Code)
	}
}

func TestCrossOriginPostForbidden(t *testing.T) {
	e := newEnv(t, false)
	body := `{"username":"alice","password":"alice-pw"}`
	for _, h := range []map[string]string{
		{"Origin": "https://evil.example"},
		{"Sec-Fetch-Site": "cross-site"},
	} {
		if w := e.do("POST", "/api/v1/auth/login", body, h); w.Code != http.StatusForbidden {
			t.Errorf("%v: %d", h, w.Code)
		}
	}
	// same-origin и не-браузерные клиенты проходят
	if w := e.do("POST", "/api/v1/auth/login", body, map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code != 200 {
		t.Errorf("same-origin: %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, false)
	w := e.do("GET", "/api/v1/auth/me", "", nil)
	h := w.Header()
	if h.Get("Content-Security-Policy") != "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'" ||
		h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", h)
	}
	// SecurityHeaders отдельно
	rec := httptest.NewRecorder()
	SecurityHeaders(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/", nil))
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("SecurityHeaders")
	}
}

func TestRequireAuthModes(t *testing.T) {
	e := newEnv(t, false)
	// API
	if w := e.do("GET", "/api/v1/auth/me", "", nil); w.Code != 401 || !strings.Contains(w.Body.String(), "unauthorized") || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("api: %d", w.Code)
	}
	// htmx
	w := e.do("GET", "/secret", "", map[string]string{"HX-Request": "true"})
	if w.Header().Get("HX-Redirect") != "/login" || w.Code != 401 {
		t.Fatalf("htmx: %d %v", w.Code, w.Header())
	}
	// обычный
	w = e.do("GET", "/secret", "", nil)
	if w.Code != 302 || w.Header().Get("Location") != "/login" {
		t.Fatalf("html: %d", w.Code)
	}
	// с сессией + контекст
	c := httpLogin(t, e)
	if w := e.do("GET", "/secret", "", nil, c); w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("authed: %d", w.Code)
	}
	if _, ok := SessionFromContext(context.Background()); ok {
		t.Fatal("empty ctx has session")
	}
}

func TestRequireAuthInternalError(t *testing.T) {
	e := newEnv(t, false)
	c := httpLogin(t, e)
	e.a.sessions = NewManager(brokenSessions{e.st.Sessions()}, e.clock.now)
	if w := e.do("GET", "/secret", "", nil, c); w.Code != 500 {
		t.Fatalf("%d", w.Code)
	}
}

type brokenSessions struct{ store.SessionRepo }

func (brokenSessions) Get(context.Context, string) (store.Session, error) {
	return store.Session{}, context.DeadlineExceeded
}

func TestHandlerErrors(t *testing.T) {
	e := newEnv(t, false)
	if w := e.do("POST", "/api/v1/auth/login", `not json`, nil); w.Code != 400 {
		t.Errorf("bad json: %d", w.Code)
	}
	if w := e.do("POST", "/api/v1/auth/login", `{"username":"`+strings.Repeat("a", 10000)+`"}`, nil); w.Code != 400 {
		t.Errorf("big body: %d", w.Code)
	}
	if w := e.do("POST", "/api/v1/auth/totp", `bad`, nil); w.Code != 400 {
		t.Errorf("totp bad json: %d", w.Code)
	}
	w := e.do("POST", "/api/v1/auth/totp", `{"code":"123456"}`, nil)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "pending_expired") {
		t.Errorf("no pending: %d %s", w.Code, w.Body)
	}
	w = e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"alice-pw"}`, nil)
	pend := findCookie(w, PendingCookie)
	w = e.do("POST", "/api/v1/auth/totp", `{"code":"000000"}`, nil, pend)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"invalid_code"`) || !strings.Contains(w.Body.String(), `"attempts_left":9`) {
		t.Errorf("bad code: %d %s", w.Code, w.Body)
	}
	w = e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"nope"}`, nil)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"invalid_credentials"`) || !strings.Contains(w.Body.String(), "attempts_left") {
		t.Errorf("bad pw: %d %s", w.Code, w.Body)
	}
	// каждый неверный ответ одинаков для существующего и несуществующего
	a := e.do("POST", "/api/v1/auth/login", `{"username":"nobody","password":"nope"}`, nil).Body.String()
	if !strings.Contains(a, "Неверное имя пользователя или пароль") {
		t.Errorf("msg: %s", a)
	}
}

func TestManagerMisc(t *testing.T) {
	e := newEnv(t, false)
	m := e.a.Sessions()
	ctx := context.Background()
	if _, err := m.Get(httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)); err == nil {
		t.Fatal("no cookie")
	}
	if _, err := m.lookup(ctx, strings.Repeat("a", 200), kindFull); err == nil {
		t.Fatal("long token")
	}
	s, _ := m.Create(ctx, "alice", ip)
	if n, err := m.DestroyUser(ctx, "alice"); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if err := m.Touch(ctx, s); err == nil {
		t.Fatal("touch destroyed")
	}
}
