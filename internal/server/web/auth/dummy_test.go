package auth

import (
	"context"
	"sort"
	"testing"
	"time"
)

func median(f func(), n int) time.Duration {
	ds := make([]time.Duration, n)
	for i := range ds {
		s := time.Now()
		f()
		ds[i] = time.Since(s)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[n/2]
}

// Время ответа для несуществующего пользователя сопоставимо с существующим (±30%).
func TestUnknownUserTimingComparable(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	e := newEnv(t, false)
	realHash, err := Hash("alice-pw", DefaultHashParams())
	if err != nil {
		t.Fatal(err)
	}
	writeUsers(t, e.path, "users:\n  alice:\n    password: '"+realHash+"'\n    totp_secret_enc: x\n", 0o640)
	if err := e.users.Reload(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	i := 0
	step := func(user string) func() {
		return func() {
			i++
			_ = e.st.RateState().Delete(ctx, "login:fail:"+userKey(user))
			ip := "198.51.100." + string(rune('0'+i%9)) // обходим rate-limit разными IP
			_, _, _ = e.a.PasswordStep(ctx, user, "wrong-password", ip+string(rune('a'+i%26)))
		}
	}
	step("alice")() // прогрев
	known := median(step("alice"), 7)
	unknown := median(step("nobody"), 7)
	ratio := float64(unknown) / float64(known)
	if ratio < 0.7 || ratio > 1.3 {
		t.Fatalf("timing ratio %.2f (known %v, unknown %v)", ratio, known, unknown)
	}
}
