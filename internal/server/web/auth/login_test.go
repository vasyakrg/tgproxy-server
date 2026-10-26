package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const ip = "203.0.113.7"

func loginOK(t *testing.T, e *env) *Session {
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
	return s
}

func TestTwoStepLoginAndRotation(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	pend, left, err := e.a.PasswordStep(ctx, "alice", "alice-pw", ip)
	if err != nil || left != LockoutThreshold {
		t.Fatalf("%v %d", err, left)
	}
	s, err := e.a.TOTPStep(ctx, pend, e.code(0), ip)
	if err != nil {
		t.Fatal(err)
	}
	if s.Token == pend || s.User != "alice" {
		t.Fatal("session id must differ from pending")
	}
	// pending одноразовый
	if _, err := e.a.TOTPStep(ctx, pend, e.code(1), ip); !errors.Is(err, ErrPendingInvalid) {
		t.Fatalf("pending reuse: %v", err)
	}
	// в БД лежит SHA-256, а не токен
	if _, err := e.st.Sessions().Get(ctx, s.Token); err == nil {
		t.Fatal("raw token stored")
	}
	if _, err := e.st.Sessions().Get(ctx, hashToken(s.Token)); err != nil {
		t.Fatal(err)
	}
}

func TestPendingCannotBeUsedAsSession(t *testing.T) {
	e := newEnv(t, false)
	pend, _, _ := e.a.PasswordStep(context.Background(), "alice", "alice-pw", ip)
	w := e.do("GET", "/secret", "", nil, &http.Cookie{Name: SessionCookie, Value: pend})
	if w.Code != http.StatusFound {
		t.Fatalf("pending accepted as session: %d", w.Code)
	}
}

func TestBadCredentialsDoNotLeak(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	var msgs []string
	for _, c := range [][2]string{{"alice", "wrong"}, {"nobody", "x"}, {"carol", "carol-pw"}} {
		_, left, err := e.a.PasswordStep(ctx, c[0], c[1], ip)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%v: %v", c, err)
		}
		msgs = append(msgs, fmt.Sprint(err, left))
	}
	if msgs[0] != msgs[1] || msgs[1] != msgs[2] {
		t.Fatalf("responses differ: %v", msgs)
	}
	// 3 неудачи на разных именах — у каждого своё число
	_, left, _ := e.a.PasswordStep(ctx, "alice", "wrong", ip)
	if left != LockoutThreshold-2 {
		t.Fatalf("left=%d", left)
	}
}

func TestRateLimit6thAttempt429(t *testing.T) {
	e := newEnv(t, false)
	for i := 1; i <= 5; i++ {
		w := e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"bad"}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"alice-pw"}`, nil)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "rate_limited") || w.Header().Get("Retry-After") == "" {
		t.Fatalf("6th: %d %s", w.Code, w.Body)
	}
	// другой IP не затронут
	e.a.clientIP = func(*http.Request) string { return "198.51.100.1" }
	if w := e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"alice-pw"}`, nil); w.Code != http.StatusOK {
		t.Fatalf("other ip: %d %s", w.Code, w.Body)
	}
}

func TestLockoutAfter10Failures(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	var last error
	for i := 0; i < LockoutThreshold; i++ {
		// разные IP, чтобы не упереться в 5/мин
		_, _, last = e.a.PasswordStep(ctx, "alice", "bad", fmt.Sprintf("10.0.0.%d", i))
	}
	var fe *FailError
	if !errors.As(last, &fe) || fe.AttemptsLeft != 0 {
		t.Fatalf("last: %v", last)
	}
	if e.notifier.count() != 1 || e.notifier.calls[0] != "alice@10.0.0.9" {
		t.Fatalf("notifier: %v", e.notifier.calls)
	}
	// теперь даже верный пароль — lockout, ответ как при блокировке
	if _, _, err := e.a.PasswordStep(ctx, "alice", "alice-pw", "10.0.0.200"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("after lockout: %v", err)
	}
	e.a.clientIP = func(*http.Request) string { return "10.0.0.201" }
	w := e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"alice-pw"}`, nil)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "locked_out") {
		t.Fatalf("http: %d %s", w.Code, w.Body)
	}
	// алерт не дублируется
	if e.notifier.count() != 1 {
		t.Fatal("duplicate alert")
	}
	audit, _ := e.st.Audit().List(ctx, store.AuditQuery{Limit: 100})
	found := false
	for _, a := range audit {
		found = found || a.Action == AuditLoginLockout
	}
	if !found {
		t.Fatal("lockout not audited")
	}
}

func TestLockoutUnknownUserNoAlert(t *testing.T) {
	e := newEnv(t, false)
	for i := 0; i < LockoutThreshold; i++ {
		_, _, _ = e.a.PasswordStep(context.Background(), "ghost", "bad", fmt.Sprintf("10.0.0.%d", i))
	}
	if _, _, err := e.a.PasswordStep(context.Background(), "ghost", "x", "10.0.0.99"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("ghost not locked uniformly: %v", err)
	}
	if e.notifier.count() != 0 {
		t.Fatal("alert for unknown user")
	}
}

func TestSuccessResetsFailures(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _, _ = e.a.PasswordStep(ctx, "alice", "bad", fmt.Sprintf("10.0.0.%d", i))
	}
	loginOK(t, e)
	if _, left, _ := e.a.PasswordStep(ctx, "alice", "bad", "10.1.1.1"); left != LockoutThreshold-1 {
		t.Fatalf("counter not reset: %d", left)
	}
}

func TestTOTPFailuresAndReplay(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	pend, _, _ := e.a.PasswordStep(ctx, "alice", "alice-pw", ip)
	_, err := e.a.TOTPStep(ctx, pend, e.code(3), ip)
	var fe *FailError
	if !errors.As(err, &fe) || !errors.Is(err, ErrInvalidCode) || fe.AttemptsLeft != LockoutThreshold-1 {
		t.Fatalf("bad code: %v", err)
	}
	// повтор уже использованного кода при новом входе
	code := e.code(0)
	if _, err := e.a.TOTPStep(ctx, pend, code, ip); err != nil {
		t.Fatal(err)
	}
	pend2, _, _ := e.a.PasswordStep(ctx, "alice", "alice-pw", "198.51.100.9")
	if _, err := e.a.TOTPStep(ctx, pend2, code, "198.51.100.9"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestTOTPNotConfigured(t *testing.T) {
	e := newEnv(t, false)
	_, _, err := e.a.PasswordStep(context.Background(), "bob", "bob-pw", ip)
	if !errors.Is(err, ErrTOTPNotConfigured) || !strings.Contains(err.Error(), "tgproxy totp enroll") {
		t.Fatalf("%v", err)
	}
	w := e.do("POST", "/api/v1/auth/login", `{"username":"bob","password":"bob-pw"}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "totp_not_configured") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// неверный пароль bob — обычная ошибка, не раскрываем наличие TOTP
	if _, _, err := e.a.PasswordStep(context.Background(), "bob", "bad", ip); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("%v", err)
	}
}

func TestAllowPasswordOnly(t *testing.T) {
	e := newEnv(t, true)
	if e.a.TOTPRequired("bob") || !e.a.TOTPRequired("alice") || !e.a.TOTPRequired("ghost") {
		t.Fatal("TOTPRequired")
	}
	w := e.do("POST", "/api/v1/auth/login", `{"username":"bob","password":"bob-pw"}`, nil)
	if w.Code != http.StatusOK || findCookie(w, SessionCookie) == nil || !strings.Contains(w.Body.String(), `"totp_required":false`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// у alice TOTP по-прежнему обязателен
	w = e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"alice-pw"}`, nil)
	if findCookie(w, SessionCookie) != nil || findCookie(w, PendingCookie) == nil {
		t.Fatal("alice must need TOTP")
	}
}

func TestTOTPStepEdgeCases(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	if _, err := e.a.TOTPStep(ctx, "garbage", "123456", ip); !errors.Is(err, ErrPendingInvalid) {
		t.Fatalf("%v", err)
	}
	// пользователь отключён между шагами
	pend, _, _ := e.a.PasswordStep(ctx, "alice", "alice-pw", ip)
	writeUsers(t, e.path, "users:\n  alice:\n    password: '"+fastHash(t, "alice-pw")+"'\n    disabled: true\n", 0o640)
	if err := e.users.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.TOTPStep(ctx, pend, e.code(0), ip); !errors.Is(err, ErrPendingInvalid) {
		t.Fatalf("%v", err)
	}
}

func TestTOTPStepSecretCorrupt(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	pend, _, _ := e.a.PasswordStep(ctx, "alice", "alice-pw", ip)
	writeUsers(t, e.path, "users:\n  alice:\n    password: '"+fastHash(t, "alice-pw")+"'\n    totp_secret_enc: '!!!'\n", 0o640)
	_ = e.users.Reload() // меняет TOTP -> сессии alice (в т.ч. pending) удалены
	if _, err := e.a.TOTPStep(ctx, pend, "123456", ip); !errors.Is(err, ErrPendingInvalid) {
		t.Fatalf("%v", err)
	}
	pend, _, _ = e.a.PasswordStep(ctx, "alice", "alice-pw", "198.51.100.5")
	if _, err := e.a.TOTPStep(ctx, pend, "123456", "198.51.100.5"); err == nil || errors.Is(err, ErrInvalidCode) {
		t.Fatalf("corrupt secret must be internal error: %v", err)
	}
	w := e.do("POST", "/api/v1/auth/totp", `{"code":"123456"}`, nil, &http.Cookie{Name: PendingCookie, Value: pend})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("%d", w.Code)
	}
}

func TestAuditNoSecrets(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, _, _ = e.a.PasswordStep(ctx, "alice", "SuperSecretPw!", ip)
	_, _, _ = e.a.PasswordStep(ctx, "SuperSecretPw!", "x", ip) // пароль в поле имени
	s := loginOK(t, e)
	_ = e.a.Logout(ctx, s, ip)
	entries, _ := e.st.Audit().List(ctx, store.AuditQuery{Limit: 100})
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
		blob := fmt.Sprintf("%+v", en)
		for _, bad := range []string{"SuperSecretPw!", "alice-pw", e.secret, s.Token} {
			if strings.Contains(blob, bad) {
				t.Fatalf("secret %q in audit: %s", bad, blob)
			}
		}
	}
	for _, a := range []string{AuditLoginFail, AuditLoginOK, AuditLogout} {
		if !seen[a] {
			t.Errorf("no %s", a)
		}
	}
}

func TestAuditBlockedAndNoTOTP(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		_, _, _ = e.a.PasswordStep(ctx, "alice", "bad", ip)
	}
	_, _, _ = e.a.PasswordStep(ctx, "bob", "bob-pw", ip)
	entries, _ := e.st.Audit().List(ctx, store.AuditQuery{Limit: 100})
	blocked, notp := 0, 0
	for _, en := range entries {
		if en.Action == AuditLoginBlocked {
			blocked++
		}
		if en.Action == AuditLoginNoTOTP {
			notp++
		}
	}
	if blocked != 1 || notp != 1 {
		t.Fatalf("blocked=%d notp=%d", blocked, notp)
	}
}

func TestUserChangeKillsSessions(t *testing.T) {
	e := newEnv(t, false)
	s := loginOK(t, e)
	c := &http.Cookie{Name: SessionCookie, Value: s.Token}
	if w := e.do("GET", "/secret", "", nil, c); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	writeUsers(t, e.path, "users:\n  bob:\n    password: '"+fastHash(t, "x")+"'\n", 0o640) // alice удалён
	if err := e.users.Reload(); err != nil {
		t.Fatal(err)
	}
	if w := e.do("GET", "/secret", "", nil, c); w.Code == 200 {
		t.Fatal("session survived user removal")
	}
}

func TestDisabledUserSessionRejected(t *testing.T) {
	e := newEnv(t, false)
	s := loginOK(t, e)
	// disabled без OnChange-инвалидации: подмена снимка напрямую
	f := *e.users.cur.Load()
	u := f.Users["alice"]
	u.Disabled = true
	f.Users = map[string]User{"alice": u}
	e.users.cur.Store(&f)
	if _, err := e.a.Authenticate(reqWith(s.Token)); !errors.Is(err, ErrNoSession) {
		t.Fatalf("%v", err)
	}
}

func reqWith(tok string) *http.Request {
	r, _ := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
	return r
}

func TestRemoteIP(t *testing.T) {
	r, _ := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.RemoteAddr = "192.0.2.1:99"
	if remoteIP(r) != "192.0.2.1" {
		t.Fatal(remoteIP(r))
	}
	r.RemoteAddr = "weird"
	if remoteIP(r) != "weird" {
		t.Fatal(remoteIP(r))
	}
}

func TestLongUsernameTruncated(t *testing.T) {
	e := newEnv(t, false)
	_, _, err := e.a.PasswordStep(context.Background(), strings.Repeat("a", 5000), "x", ip)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
}

func TestRateStateErrors(t *testing.T) {
	e := newEnv(t, false)
	e.a.store = brokenStore{e.st}
	if _, _, err := e.a.PasswordStep(context.Background(), "alice", "alice-pw", ip); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("%v", err)
	}
	w := e.do("POST", "/api/v1/auth/login", `{"username":"alice","password":"x"}`, nil)
	if w.Code != 500 {
		t.Fatalf("%d", w.Code)
	}
}

type brokenStore struct{ Store }

func (b brokenStore) RateState() store.RateStateRepo { return errRateAll{b.Store.RateState()} }

type errRateAll struct{ store.RateStateRepo }

func (errRateAll) Get(context.Context, string) (store.RateWindow, error) {
	return store.RateWindow{}, errors.New("down")
}

func TestIPNet(t *testing.T) {
	for in, want := range map[string]string{
		"10.1.2.3":                  "10.1.2.0/24",
		"::ffff:10.1.2.3":           "10.1.2.0/24",
		"2001:db8:1:2:aaaa:bbbb::1": "2001:db8:1:2::/64",
		"2001:db8:1:2::ffff":        "2001:db8:1:2::/64",
		"garbage":                   "garbage",
	} {
		if got := ipNet(in); got != want {
			t.Errorf("ipNet(%q)=%q want %q", in, got, want)
		}
	}
}

// Чужой хост блокирует админа только в своей подсети: вход из другой подсети работает.
func TestLockoutIsPerUserAndSubnet(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	for i := 0; i < LockoutThreshold; i++ {
		_, _, _ = e.a.PasswordStep(ctx, "alice", "bad", fmt.Sprintf("203.0.113.%d", i))
	}
	if _, _, err := e.a.PasswordStep(ctx, "alice", "alice-pw", "203.0.113.200"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("same /24 must be locked: %v", err)
	}
	if _, _, err := e.a.PasswordStep(ctx, "alice", "alice-pw", "198.51.100.7"); err != nil {
		t.Fatalf("other /24 must pass: %v", err)
	}
	// IPv6: /64 общий, другой /64 свободен
	for i := 0; i < LockoutThreshold; i++ {
		_, _, _ = e.a.PasswordStep(ctx, "alice", "bad", fmt.Sprintf("2001:db8:0:1::%x", i+1))
	}
	if _, _, err := e.a.PasswordStep(ctx, "alice", "alice-pw", "2001:db8:0:1:ffff::1"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("same /64 must be locked: %v", err)
	}
	if _, _, err := e.a.PasswordStep(ctx, "alice", "alice-pw", "2001:db8:0:2::1"); err != nil {
		t.Fatalf("other /64 must pass: %v", err)
	}
	// другой пользователь из заблокированной подсети не затронут
	if _, _, err := e.a.PasswordStep(ctx, "bob", "bad", "203.0.113.5"); errors.Is(err, ErrLockedOut) {
		t.Fatalf("other user must not be locked: %v", err)
	}
}

// Распределённый перебор (много подсетей) упирается в глобальный порог по пользователю.
func TestGlobalUserLockout(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	var last error
	for i := 0; i < LockoutThresholdGlobal; i++ {
		_, _, last = e.a.PasswordStep(ctx, "alice", "bad", fmt.Sprintf("10.%d.0.1", i))
	}
	var fe *FailError
	if !errors.As(last, &fe) || fe.AttemptsLeft != 0 {
		t.Fatalf("last: %v", last)
	}
	if e.notifier.count() != 1 {
		t.Fatalf("alert count %d", e.notifier.count())
	}
	if _, _, err := e.a.PasswordStep(ctx, "alice", "alice-pw", "172.16.0.1"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("global lockout expected: %v", err)
	}
}
