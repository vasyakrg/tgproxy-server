package screens_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"

	"github.com/vasyakrg/tgproxy-server/internal/server/web"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

// fxSealer — подмена KEK.
type fxSealer struct{}

func (fxSealer) Seal(pt, aad []byte) ([]byte, error) {
	return append(append([]byte{}, aad...), append([]byte{'|'}, pt...)...), nil
}

func (fxSealer) Open(ct, aad []byte) ([]byte, error) {
	p := append(append([]byte{}, aad...), '|')
	if !bytes.HasPrefix(ct, p) {
		return nil, errors.New("aad mismatch")
	}
	return ct[len(p):], nil
}

type fxClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *fxClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

// fx — web-роутер + настоящий auth.Auth на memtest.
type fx struct {
	t      *testing.T
	st     *memtest.Store
	a      *auth.Auth
	rt     *web.Router
	secret string
	clock  *fxClock
}

func newFx(t *testing.T, passwordOnly bool) *fx {
	t.Helper()
	f := &fx{t: t, st: memtest.New(), clock: &fxClock{}}
	tp := auth.NewTOTP(fxSealer{}, f.st.RateState(), "tgproxy")
	enr, err := tp.Enroll("alice")
	if err != nil {
		t.Fatal(err)
	}
	f.secret = enr.Secret
	hash := func(pw string) string {
		h, err := auth.Hash(pw, auth.HashParams{M: 64, T: 1, P: 1, SaltLen: 16, KeyLen: 32})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	path := filepath.Join(t.TempDir(), "users.yml")
	content := fmt.Sprintf("users:\n  alice:\n    password: '%s'\n    totp_secret_enc: '%s'\n  bob:\n    password: '%s'\n",
		hash("alice-pw"), enr.Sealed, hash("bob-pw"))
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil { //nolint:gosec // тест
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // тест
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	users, err := auth.LoadUsers(path, quiet)
	if err != nil {
		t.Fatal(err)
	}
	f.a = auth.New(auth.Options{
		Users: users, Store: f.st, TOTP: tp, AllowPasswordOnly: passwordOnly, Now: f.clock.now, Logger: quiet,
	})
	f.rt = web.NewRouter(web.Deps{Version: "v1.4.1", Session: nil})
	return f
}

// code возвращает действующий TOTP-код alice.
func (f *fx) code() string {
	step := f.clock.now().Unix() / 30
	c, err := hotp.GenerateCodeCustom(f.secret, uint64(step), hotp.ValidateOpts{Digits: 6}) //nolint:gosec // тест
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// sessionCookie создаёт полную сессию пользователя.
func (f *fx) sessionCookie(user string) *http.Cookie {
	f.t.Helper()
	s, err := f.a.Sessions().Create(context.Background(), user, "203.0.113.7")
	if err != nil {
		f.t.Fatal(err)
	}
	return &http.Cookie{Name: auth.SessionCookie, Value: s.Token}
}

type req struct {
	method, path string
	form         url.Values
	hdr          map[string]string
	cookies      []*http.Cookie
}

func (f *fx) do(r req) *httptest.ResponseRecorder {
	f.t.Helper()
	body := ""
	if r.form != nil {
		body = r.form.Encode()
	}
	hr := httptest.NewRequestWithContext(context.Background(), r.method, r.path, strings.NewReader(body))
	hr.RemoteAddr = "203.0.113.7:4000"
	if r.form != nil {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range r.hdr {
		hr.Header.Set(k, v)
	}
	for _, c := range r.cookies {
		hr.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.rt.ServeHTTP(w, hr)
	return w
}

func respCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
