package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

// fastHash — дешёвый argon2id для тестов.
func fastHash(t testing.TB, pw string) string {
	t.Helper()
	h, err := Hash(pw, HashParams{M: 64, T: 1, P: 1, SaltLen: 16, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fakeSealer — подмена KEK: проверяет AAD.
type fakeSealer struct{}

func (fakeSealer) Seal(pt, aad []byte) ([]byte, error) {
	return append(append([]byte{}, aad...), append([]byte{'|'}, pt...)...), nil
}

func (fakeSealer) Open(ct, aad []byte) ([]byte, error) {
	p := append(append([]byte{}, aad...), '|')
	if !bytes.HasPrefix(ct, p) {
		return nil, errors.New("aad mismatch")
	}
	return ct[len(p):], nil
}

type fakeNotifier struct {
	mu    sync.Mutex
	calls []string
}

func (n *fakeNotifier) LoginLockout(_ context.Context, user, ip string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, user+"@"+ip)
}

func (n *fakeNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.calls)
}

type env struct {
	t        *testing.T
	a        *Auth
	st       *memtest.Store
	users    *Users
	path     string
	notifier *fakeNotifier
	totp     *TOTP
	secret   string // секрет alice
	clock    *clock
	mux      *http.ServeMux
}

type clock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.off += d
}

func writeUsers(t testing.TB, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T, passwordOnly bool) *env {
	t.Helper()
	e := &env{t: t, st: memtest.New(), notifier: &fakeNotifier{}, clock: &clock{}}
	e.totp = NewTOTP(fakeSealer{}, e.st.RateState(), "tgproxy")
	enr, err := e.totp.Enroll("alice")
	if err != nil {
		t.Fatal(err)
	}
	e.secret = enr.Secret
	e.path = filepath.Join(t.TempDir(), "users.yml")
	writeUsers(t, e.path, fmt.Sprintf(`users:
  alice:
    displayname: Alice
    password: '%s'
    email: alice@example.test
    totp_secret_enc: '%s'
  bob:
    password: '%s'
  carol:
    password: '%s'
    disabled: true
    totp_secret_enc: '%s'
`, fastHash(t, "alice-pw"), enr.Sealed, fastHash(t, "bob-pw"), fastHash(t, "carol-pw"), enr.Sealed), 0o640)
	e.users, err = LoadUsers(e.path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.a = New(Options{
		Users: e.users, Store: e.st, TOTP: e.totp, Notifier: e.notifier,
		AllowPasswordOnly: passwordOnly, Now: e.clock.now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	e.mux = http.NewServeMux()
	e.a.Routes(e.mux)
	e.mux.Handle("GET /secret", e.a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})))
	return e
}

// code возвращает TOTP-код alice для шага относительно текущего времени.
func (e *env) code(delta int) string {
	step := e.clock.now().Unix()/30 + int64(delta)
	c, err := hotp.GenerateCodeCustom(e.secret, uint64(step), hotp.ValidateOpts{Digits: 6}) //nolint:gosec // тест
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) do(method, path, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, path, bytes.NewBufferString(body))
	r.RemoteAddr = "203.0.113.7:4000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func findCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func chmod(p string, mode uint32) error { return os.Chmod(p, os.FileMode(mode)) }

// errRate — RateStateRepo, у которого SetNX/Incr падают.
type errRate struct{ store.RateStateRepo }

func (errRate) SetNX(context.Context, string, []byte, time.Duration) (bool, error) {
	return false, errors.New("rate down")
}

func (errRate) Incr(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("rate down")
}
