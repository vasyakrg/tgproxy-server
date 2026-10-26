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

// Время ответа для несуществующего пользователя сопоставимо с существующим.
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
			ip := "198.51.100." + string(rune('0'+i%9)) + string(rune('a'+i%26)) // обходим rate-limit разными «IP»
			_ = e.st.RateState().Delete(ctx, failKey(user, ip))
			_ = e.st.RateState().Delete(ctx, failKeyGlobal(user))
			_, _, _ = e.a.PasswordStep(ctx, user, "wrong-password", ip)
		}
	}
	// Прогрев обеих веток (включая ленивую генерацию фиктивного хеша) и
	// чередование замеров: последовательные серии искажаются ростом давления
	// GC (каждый argon2 — 64 МиБ), особенно под -race на CI.
	step("alice")()
	step("nobody")()
	const n = 9
	var ks, us []time.Duration
	for range n {
		ks = append(ks, median(step("alice"), 1))
		us = append(us, median(step("nobody"), 1))
	}
	sortD := func(d []time.Duration) time.Duration {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return d[len(d)/2]
	}
	known, unknown := sortD(ks), sortD(us)
	ratio := float64(unknown) / float64(known)
	if ratio < 0.6 || ratio > 1.6 {
		t.Fatalf("timing ratio %.2f (known %v, unknown %v)", ratio, known, unknown)
	}
}
