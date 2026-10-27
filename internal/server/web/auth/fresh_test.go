package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func loginSession(t *testing.T, e *env) (*Session, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	pend, _, err := e.a.PasswordStep(ctx, "alice", "alice-pw", ip)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.a.TOTPStep(ctx, pend, e.code(0), ip)
	if err != nil {
		t.Fatal(err)
	}
	return s, &http.Cookie{Name: SessionCookie, Value: s.Token}
}

func TestLoginMarksFresh(t *testing.T) {
	e := newEnv(t, false)
	s, _ := loginSession(t, e)
	if !e.a.TOTPFresh(context.Background(), s, FreshTOTPWindow) {
		t.Fatal("после входа TOTP свежий")
	}
}

func TestFreshExpires(t *testing.T) {
	e := newEnv(t, false)
	s, _ := loginSession(t, e)
	e.clock.advance(FreshTOTPWindow + time.Second)
	if e.a.TOTPFresh(context.Background(), s, FreshTOTPWindow) {
		t.Fatal("через 5м01с TOTP уже не свежий")
	}
}

func TestRequireFreshTOTP(t *testing.T) {
	e := newEnv(t, false)
	e.mux.Handle("GET /fresh", Protect(e.a.RequireAuth(e.a.RequireFreshTOTP(FreshTOTPWindow)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})))))
	_, c := loginSession(t, e)
	if w := e.do("GET", "/fresh", "", nil, c); w.Code != 200 {
		t.Fatalf("свежий: %d", w.Code)
	}
	e.clock.advance(FreshTOTPWindow + time.Second)
	// idle-сессия за это время не истекла (30м)
	w := e.do("GET", "/fresh", "", nil, c)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"totp_required"`) {
		t.Fatalf("несвежий: %d %s", w.Code, w.Body)
	}
	if w := e.do("GET", "/fresh", "", nil); w.Code != 302 {
		t.Fatalf("без сессии — unauthorized: %d %s", w.Code, w.Body)
	}
}

func TestConfirmTOTPRefreshes(t *testing.T) {
	e := newEnv(t, false)
	s, c := loginSession(t, e)
	e.clock.advance(FreshTOTPWindow + time.Second)
	hdr := map[string]string{"Content-Type": "application/json"}
	if w := e.do("POST", "/api/v1/auth/totp/confirm", `{"code":"000000"}`, hdr, c); w.Code != 401 || !strings.Contains(w.Body.String(), "invalid_code") {
		t.Fatalf("неверный код: %d %s", w.Code, w.Body)
	}
	if e.a.TOTPFresh(context.Background(), s, FreshTOTPWindow) {
		t.Fatal("неверный код не освежает")
	}
	w := e.do("POST", "/api/v1/auth/totp/confirm", `{"code":"`+e.code(1)+`"}`, hdr, c)
	if w.Code != 200 {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	if !e.a.TOTPFresh(context.Background(), s, FreshTOTPWindow) {
		t.Fatal("после confirm свежий")
	}
	// повтор того же кода — replay
	if w := e.do("POST", "/api/v1/auth/totp/confirm", `{"code":"`+e.code(1)+`"}`, hdr, c); w.Code != 401 {
		t.Fatalf("replay: %d", w.Code)
	}
}

func TestConfirmTOTPRequiresSessionAndCSRF(t *testing.T) {
	e := newEnv(t, false)
	if w := e.do("POST", "/api/v1/auth/totp/confirm", `{"code":"1"}`, nil); w.Code != 401 {
		t.Fatalf("без сессии: %d", w.Code)
	}
	_, c := loginSession(t, e)
	if w := e.do("POST", "/api/v1/auth/totp/confirm", `{"code":"1"}`, map[string]string{"Sec-Fetch-Site": "cross-site"}, c); w.Code != 403 {
		t.Fatalf("CSRF: %d", w.Code)
	}
}

func TestLogoutDropsFresh(t *testing.T) {
	e := newEnv(t, false)
	s, _ := loginSession(t, e)
	if err := e.a.Logout(context.Background(), s, ip); err != nil {
		t.Fatal(err)
	}
	if e.a.TOTPFresh(context.Background(), s, FreshTOTPWindow) {
		t.Fatal("после выхода отметка снята")
	}
}

func TestConfirmTOTPErrors(t *testing.T) {
	e := newEnv(t, false)
	s, _ := loginSession(t, e)
	var fe *FailError
	if err := e.a.ConfirmTOTP(context.Background(), s, "bad", ip); !errors.As(err, &fe) {
		t.Fatalf("%v", err)
	}
}
