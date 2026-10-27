package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func newPurgeFx(t *testing.T) *mtFx {
	t.Helper()
	f := newMtFx(t)
	svc := api.NewErrorsPurgeService(f.st.Errors(), f.st.Audit(), nil, f.clock.now)
	(&api.ErrorsAPI{Purge: svc, ClientIP: func(*http.Request) string { return "203.0.113.7" }}).
		Routes(f.mux.ServeMux, func(h http.Handler) http.Handler { return auth.Protect(f.a.RequireAuth(h)) })
	return f
}

// seedAges кладёт по одной записи на каждый возраст (в часах).
func seedAges(t *testing.T, f *mtFx, hours ...int) {
	t.Helper()
	for i, h := range hours {
		_, err := f.st.Errors().Append(context.Background(), store.ErrorEvent{
			At: f.clock.now().Add(-time.Duration(h) * time.Hour), RequestID: fmt.Sprintf("r%d", i), Outcome: store.OutcomeRetried, Phase: "dial",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func remaining(t *testing.T, f *mtFx) int {
	t.Helper()
	l, err := f.st.Errors().List(context.Background(), store.ErrorQuery{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return len(l)
}

func TestErrorsPurgeAuthCSRF(t *testing.T) {
	f := newPurgeFx(t)
	seedAges(t, f, 1)
	if code, _ := f.call("POST", "/api/v1/errors/purge", `{"keep_days":0}`, false); code != 401 {
		t.Fatalf("без сессии: %d", code)
	}
	if code, _ := f.call("POST", "/api/v1/errors/purge", `{"keep_days":0}`, true, "Sec-Fetch-Site", "cross-site"); code != 403 {
		t.Fatalf("cross-site: %d", code)
	}
	if remaining(t, f) != 1 {
		t.Fatal("журнал изменился без авторизации/CSRF")
	}
}

func TestErrorsPurgeValidation(t *testing.T) {
	f := newPurgeFx(t)
	seedAges(t, f, 1, 100)
	for _, b := range []string{``, `{}`, `{"keep_days":null}`, `{"keep_days":7}`, `{"keep_days":-1}`, `{"keep_days":"3"}`, `{"keep_days":3,"x":1}`} {
		if code, body := f.call("POST", "/api/v1/errors/purge", b, true); code != 400 && code != 422 {
			t.Errorf("%q: %d %s", b, code, body)
		}
	}
	if remaining(t, f) != 2 {
		t.Fatal("невалидный запрос стёр записи")
	}
}

func TestErrorsPurgeKeepDays(t *testing.T) {
	// возрасты в часах: 1ч, ровно N суток (граница) ±1ч, 40 суток
	for _, days := range []int{3, 5, 15, 30} {
		t.Run(fmt.Sprintf("%dd", days), func(t *testing.T) {
			f := newPurgeFx(t)
			seedAges(t, f, 1, days*24-1, days*24+1, 40*24)
			code, body := f.call("POST", "/api/v1/errors/purge", fmt.Sprintf(`{"keep_days":%d}`, days), true)
			wantDeleted := 2 // N*24+1 ч и 40 суток; N*24-1 ч и 1 ч остаются
			if code != 200 || decodeMap(t, body)["deleted"].(float64) != float64(wantDeleted) {
				t.Fatalf("%d %s", code, body)
			}
			if remaining(t, f) != 2 {
				t.Fatalf("осталось %d", remaining(t, f))
			}
			es, _ := f.st.Audit().List(context.Background(), store.AuditQuery{Limit: 100})
			found := false
			for _, e := range es {
				if e.Action == api.AuditErrorsPurge {
					found = true
					if !strings.Contains(e.Detail, fmt.Sprintf("keep_days=%d deleted=%d", days, wantDeleted)) || e.Actor != "alice" {
						t.Fatalf("аудит: %+v", e)
					}
				}
			}
			if !found {
				t.Fatal("нет аудита errors.purge")
			}
		})
	}
}

func TestErrorsPurgeAll(t *testing.T) {
	f := newPurgeFx(t)
	seedAges(t, f, 1, 50, 5000)
	code, body := f.call("POST", "/api/v1/errors/purge", `{"keep_days":0}`, true)
	if code != 200 || decodeMap(t, body)["deleted"].(float64) != 3 || remaining(t, f) != 0 {
		t.Fatalf("%d %s", code, body)
	}
	// пустой журнал — не ошибка
	if code, body = f.call("POST", "/api/v1/errors/purge", `{"keep_days":0}`, true); code != 200 || decodeMap(t, body)["deleted"].(float64) != 0 {
		t.Fatalf("%d %s", code, body)
	}
}
