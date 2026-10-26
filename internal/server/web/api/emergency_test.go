package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type fakeEmergency struct {
	calls [][2]string
	err   error
}

func (f *fakeEmergency) EmergencyUpdate(_ context.Context, id, version string) (string, error) {
	f.calls = append(f.calls, [2]string{id, version})
	if f.err != nil {
		return "", f.err
	}
	return "job1", nil
}

func newEmergencyEnv(t *testing.T) (*http.ServeMux, *fakeEmergency, *memtest.Store) {
	t.Helper()
	mux, fe, st := http.NewServeMux(), &fakeEmergency{}, memtest.New()
	svc := &api.EmergencyService{Updater: fe, Audit: st.Audit(), Now: func() time.Time { return t0 }}
	(&api.EmergencyAPI{Service: svc}).Routes(mux, nil)
	return mux, fe, st
}

func postEmergency(mux *http.ServeMux, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body)))
	return rec
}

func TestEmergencyAPIStartAudited(t *testing.T) {
	mux, fe, st := newEmergencyEnv(t)
	rec := postEmergency(mux, "/api/v1/agents/ams-2/emergency-update?confirm=yes", `{"version":"v1.4.1"}`)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"id":"job1"`) ||
		!strings.Contains(rec.Body.String(), "/api/v1/install-jobs/job1/events") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(fe.calls) != 1 || fe.calls[0] != [2]string{"ams-2", "1.4.1"} {
		t.Fatalf("calls %v", fe.calls)
	}
	au, _ := st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 1 || au[0].Action != api.AuditAgentEmergency || au[0].Target != "ams-2" || !strings.Contains(au[0].Detail, "job=job1") {
		t.Fatalf("audit %+v", au)
	}
}

func TestEmergencyAPIRejects(t *testing.T) {
	cases := []struct {
		name, path, body string
		err              error
		code             int
		kind             string
	}{
		{"без confirm", "/api/v1/agents/a1/emergency-update", `{"version":"1.4.1"}`, nil, 400, "confirm_required"},
		{"confirm=no", "/api/v1/agents/a1/emergency-update?confirm=no", `{"version":"1.4.1"}`, nil, 400, "confirm_required"},
		{"мусорный JSON", "/api/v1/agents/a1/emergency-update?confirm=yes", `{`, nil, 400, "bad_request"},
		{"лишнее поле", "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"1.4.1","x":1}`, nil, 400, "bad_request"},
		{"нет ssh_host", "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"1.4.1"}`, installer.ErrNoSSHTarget, 409, "no_ssh_target"},
		{"занято", "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"1.4.1"}`, installer.ErrEmergencyBusy, 409, "busy"},
		{"ключ хоста не закреплён", "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"1.4.1"}`, &installer.ErrHostKeyUnknown{}, 409, "host_key_unknown"},
		{"нет агента", "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"1.4.1"}`, store.ErrNotFound, 404, "not_found"},
		{"плохой id", "/api/v1/agents/a%20b/emergency-update?confirm=yes", `{"version":"1.4.1"}`, nil, 404, "not_found"},
		{"плохая версия", "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"x"}`, installer.ErrBadVersion, 422, "bad_version"},
		{"нет релиза", "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"9.9.9"}`, installer.ErrNoPackage, 422, "no_package"},
		{"прочее", "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"1.4.1"}`, errors.New("secret detail"), 500, "internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mux, fe, st := newEmergencyEnv(t)
			fe.err = c.err
			rec := postEmergency(mux, c.path, c.body)
			if rec.Code != c.code || !strings.Contains(rec.Body.String(), `"error":"`+c.kind+`"`) {
				t.Fatalf("%d %s, want %d %s", rec.Code, rec.Body, c.code, c.kind)
			}
			if strings.Contains(rec.Body.String(), "secret detail") {
				t.Fatal("внутренняя ошибка утекла в ответ")
			}
			if au, _ := st.Audit().List(context.Background(), store.AuditQuery{}); len(au) != 0 {
				t.Fatalf("аудит при отказе: %+v", au)
			}
			if c.err == nil && len(fe.calls) != 0 {
				t.Fatalf("установщик вызван без подтверждения: %v", fe.calls)
			}
		})
	}
}

func TestEmergencyAPINotConfigured(t *testing.T) {
	mux := http.NewServeMux()
	(&api.EmergencyAPI{Service: &api.EmergencyService{}}).Routes(mux, nil)
	rec := postEmergency(mux, "/api/v1/agents/a1/emergency-update?confirm=yes", `{"version":"1.4.1"}`)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
