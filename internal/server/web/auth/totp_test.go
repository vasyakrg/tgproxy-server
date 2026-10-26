package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

func TestEnroll(t *testing.T) {
	tt := NewTOTP(fakeSealer{}, nil, "")
	enr, err := tt.Enroll("alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enr.URI, "otpauth://totp/tgproxy:alice?") || !strings.Contains(enr.URI, "secret="+enr.Secret) {
		t.Fatalf("uri: %s", enr.URI)
	}
	raw, err := base64.StdEncoding.DecodeString(enr.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := (fakeSealer{}).Open(raw, []byte("totp:alice")); err != nil || string(pt) != enr.Secret {
		t.Fatalf("open: %v %s", err, pt)
	}
	if _, err := (fakeSealer{}).Open(raw, []byte("totp:mallory")); err == nil {
		t.Fatal("AAD must bind the user")
	}
	qr, err := enr.QR()
	if err != nil || !strings.Contains(qr, "█") || strings.Count(qr, "\n") < 10 {
		t.Fatalf("qr: %v\n%s", err, qr)
	}
}

type failSealer struct{ fakeSealer }

func (failSealer) Seal(_, _ []byte) ([]byte, error) { return nil, errors.New("boom") }

func TestEnrollSealError(t *testing.T) {
	if _, err := NewTOTP(failSealer{}, nil, "x").Enroll("a"); err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	e := newEnv(t, false)
	u, _ := e.users.Get("alice")
	ctx := context.Background()
	now := time.Now()
	code := func(d int) string {
		e.clock.off = 0
		return e.code(d)
	}

	// вне окна ±1: ±2 шага
	for _, d := range []int{-2, 2} {
		if err := e.totp.Verify(ctx, "alice", u.TOTPSecretEnc, code(d), now); !errors.Is(err, ErrTOTPInvalid) {
			t.Errorf("delta %d: %v", d, err)
		}
	}
	// в окне: -1, 0, +1 (каждый шаг — один раз)
	for _, d := range []int{-1, 0, 1} {
		if err := e.totp.Verify(ctx, "alice", u.TOTPSecretEnc, code(d), now); err != nil {
			t.Errorf("delta %d: %v", d, err)
		}
	}
	// повтор
	if err := e.totp.Verify(ctx, "alice", u.TOTPSecretEnc, code(0), now); !errors.Is(err, ErrTOTPReplayed) {
		t.Errorf("replay: %v", err)
	}
	// формат
	for _, c := range []string{"", "12345", "1234567", "abcdef"} {
		if err := e.totp.Verify(ctx, "alice", u.TOTPSecretEnc, c, now); !errors.Is(err, ErrTOTPInvalid) {
			t.Errorf("code %q: %v", c, err)
		}
	}
}

func TestVerifyErrors(t *testing.T) {
	e := newEnv(t, false)
	u, _ := e.users.Get("alice")
	ctx := context.Background()
	if err := e.totp.Verify(ctx, "alice", "%%%", "123456", time.Now()); err == nil {
		t.Error("bad base64")
	}
	// чужой пользователь: AAD не совпадает
	if err := e.totp.Verify(ctx, "bob", u.TOTPSecretEnc, "123456", time.Now()); err == nil {
		t.Error("AAD mismatch accepted")
	}
	// без хранилища anti-replay верный код не принимается
	noState := NewTOTP(fakeSealer{}, nil, "x")
	if err := noState.Verify(ctx, "alice", u.TOTPSecretEnc, e.code(0), time.Now()); err == nil || errors.Is(err, ErrTOTPInvalid) {
		t.Errorf("no state: %v", err)
	}
	// ошибка хранилища
	st := memtest.New()
	bad := NewTOTP(fakeSealer{}, errRate{st.RateState()}, "x")
	if err := bad.Verify(ctx, "alice", u.TOTPSecretEnc, e.code(0), time.Now()); err == nil || errors.Is(err, ErrTOTPInvalid) {
		t.Errorf("state error: %v", err)
	}
}
