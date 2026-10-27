package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/enroll"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

const enrollToken = "TOKEN-ONLY-IN-CMDLINE-abcdef"

// fakeIssuer создаёт запись в репозитории так же, как enroll.Service: в БД только хеш.
type fakeIssuer struct {
	repo store.EnrollmentRepo
	err  error
	reqs []enroll.IssueRequest
}

func (f *fakeIssuer) IssueFor(ctx context.Context, req enroll.IssueRequest) (enroll.Issued, error) {
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return enroll.Issued{}, f.err
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s%d", enrollToken, len(f.reqs))))
	id := fmt.Sprintf("%016x", len(f.reqs))
	exp := t0.Add(req.TTL)
	err := f.repo.Create(ctx, store.Enrollment{ID: id, TokenHash: h[:], Name: req.Name, Weight: req.Weight, CreatedBy: req.CreatedBy, CreatedAt: t0, ExpiresAt: exp})
	return enroll.Issued{ID: id, Token: enrollToken, Cmdline: "sudo TGP_ENROLL_TOKEN=" + enrollToken + " tgproxy agent enroll", CmdlineInstalled: "tgproxy agent enroll", ExpiresAt: exp}, err
}

func newEnrollEnv(t *testing.T) (*http.ServeMux, *fakeIssuer, *memtest.Store, *bytes.Buffer) {
	t.Helper()
	st := memtest.New()
	fi := &fakeIssuer{repo: st.Enrollments()}
	logs := &bytes.Buffer{}
	lg := slog.New(slog.NewTextHandler(logs, nil))
	svc := api.NewEnrollService(api.EnrollConfig{Issuer: fi, Enrollments: st.Enrollments(), Audit: st.Audit(), Logger: lg, Now: func() time.Time { return t0 }})
	mux := http.NewServeMux()
	(&api.EnrollAPI{Service: svc, Log: lg}).Routes(mux, nil)
	return mux, fi, st, logs
}

func doJSON(mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body)))
	return rec
}

func TestEnrollCreateListRevoke(t *testing.T) {
	mux, fi, st, logs := newEnrollEnv(t)
	rec := doJSON(mux, "POST", "/api/v1/enrollments", `{"name":"waw-2","weight":80,"ttl_minutes":30}`)
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var created map[string]string
	decode(t, rec, &created)
	if created["cmdline_installed"] == "" || !strings.Contains(created["cmdline"], enrollToken) || created["id"] == "" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%v %v", created, rec.Header())
	}
	if r := fi.reqs[0]; r.Name != "waw-2" || r.Weight != 80 || r.TTL != 30*time.Minute {
		t.Errorf("req %+v", r)
	}
	// токен показывается один раз: в списке и логах его нет
	rec = doJSON(mux, "GET", "/api/v1/enrollments", "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), enrollToken) || !strings.Contains(rec.Body.String(), "waw-2") {
		t.Errorf("list: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(logs.String(), enrollToken) {
		t.Error("токен в логах")
	}
	// отзыв требует подтверждения
	path := "/api/v1/enrollments/" + created["id"]
	if c := doJSON(mux, "DELETE", path, "").Code; c != 400 {
		t.Fatalf("без confirm: %d", c)
	}
	if p, _ := st.Enrollments().ListPending(context.Background(), t0); len(p) != 1 {
		t.Fatal("токен отозван без подтверждения")
	}
	if c := doJSON(mux, "DELETE", path+"?confirm=yes", "").Code; c != 204 {
		t.Fatalf("revoke: %d", c)
	}
	if p, _ := st.Enrollments().ListPending(context.Background(), t0); len(p) != 0 {
		t.Fatal("токен не отозван")
	}
	if c := doJSON(mux, "DELETE", path+"?confirm=yes", "").Code; c != 404 {
		t.Errorf("повторный отзыв: %d", c)
	}
	if c := doJSON(mux, "DELETE", "/api/v1/enrollments/NOT-HEX?confirm=yes", "").Code; c != 404 {
		t.Errorf("bad id: %d", c)
	}
	au, _ := st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 1 || au[0].Action != api.AuditEnrollRevoke {
		t.Errorf("audit %+v", au)
	}
}

func TestEnrollDefaultsAndValidation(t *testing.T) {
	mux, fi, _, _ := newEnrollEnv(t)
	if c := doJSON(mux, "POST", "/api/v1/enrollments", `{"name":"a"}`).Code; c != 201 {
		t.Fatalf("defaults: %d", c)
	}
	if r := fi.reqs[0]; r.Weight != api.DefaultWeight || r.TTL != time.Hour {
		t.Errorf("умолчания: %+v", r)
	}
	for _, body := range []string{`{"name":""}`, `{"name":"bad name"}`, `{"name":"a","weight":-1}`, `{"name":"a","ttl_minutes":99999}`, `{"name":"a","weight":5000}`} {
		rec := doJSON(mux, "POST", "/api/v1/enrollments", body)
		if rec.Code != 422 {
			t.Errorf("%s: %d", body, rec.Code)
		}
	}
	if c := doJSON(mux, "POST", "/api/v1/enrollments", `{"name":"a","x":1}`).Code; c != 400 {
		t.Errorf("unknown field: %d", c)
	}
	if len(fi.reqs) != 1 {
		t.Errorf("issuer вызван при невалидном вводе: %d", len(fi.reqs))
	}
	fi.err = fmt.Errorf("x: %w", store.ErrInvalid)
	if c := doJSON(mux, "POST", "/api/v1/enrollments", `{"name":"a"}`).Code; c != 422 {
		t.Errorf("invalid от сервиса: %d", c)
	}
	fi.err = errors.New("db down")
	rec := doJSON(mux, "POST", "/api/v1/enrollments", `{"name":"a"}`)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "db down") {
		t.Errorf("internal: %d %s", rec.Code, rec.Body)
	}
}

func TestEnrollNotConfigured(t *testing.T) {
	svc := api.NewEnrollService(api.EnrollConfig{})
	mux := http.NewServeMux()
	(&api.EnrollAPI{Service: svc}).Routes(mux, nil)
	for _, c := range [][3]string{{"GET", "/api/v1/enrollments", ""}, {"POST", "/api/v1/enrollments", `{"name":"a"}`}, {"DELETE", "/api/v1/enrollments/ab?confirm=yes", ""}} {
		if got := doJSON(mux, c[0], c[1], c[2]).Code; got != http.StatusNotImplemented {
			t.Errorf("%s %s: %d", c[0], c[1], got)
		}
	}
	if svc.Configured() {
		t.Error("configured")
	}
}

func TestEnrollWrapRequiresSession(t *testing.T) {
	st := memtest.New()
	svc := api.NewEnrollService(api.EnrollConfig{Issuer: &fakeIssuer{repo: st.Enrollments()}, Enrollments: st.Enrollments(), Audit: st.Audit()})
	deny := api.Wrap(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	})
	mux := http.NewServeMux()
	(&api.EnrollAPI{Service: svc}).Routes(mux, deny)
	ins := http.NewServeMux()
	(&api.InstallAPI{Service: api.NewInstallService(api.InstallConfig{Installer: &fakeInstaller{}})}).Routes(ins, deny)
	for _, h := range []struct {
		mux  http.Handler
		m, p string
	}{
		{mux, "GET", "/api/v1/enrollments"},
		{mux, "POST", "/api/v1/enrollments"},
		{mux, "DELETE", "/api/v1/enrollments/ab"},
		{ins, "POST", "/api/v1/install-jobs"},
		{ins, "GET", "/api/v1/install-jobs/x"},
		{ins, "GET", "/api/v1/install-jobs/x/events"},
		{ins, "POST", "/api/v1/hostkeys/probe"},
	} {
		if c := doJSON(h.mux, h.m, h.p, "{}").Code; c != 401 {
			t.Errorf("%s %s без сессии: %d", h.m, h.p, c)
		}
	}
}

// Реальная обвязка Protect+RequireAuth: без сессии 401, кросс-сайтовые изменяющие запросы 403,
// отзыв и выпуск не происходят; с сессией отзыв пишет аудит с актором и IP.
func TestEnrollmentsAPIAuthAndCSRF(t *testing.T) {
	f := newAcFx(t)
	fi := &fakeIssuer{repo: f.st.Enrollments()}
	svc := api.NewEnrollService(api.EnrollConfig{Issuer: fi, Enrollments: f.st.Enrollments(), Audit: f.st.Audit(), Now: func() time.Time { return t0 }})
	(&api.EnrollAPI{Service: svc, ClientIP: func(*http.Request) string { return "203.0.113.7" }}).Routes(f.mux, f.wrap)

	for _, c := range [][2]string{{"GET", "/api/v1/enrollments"}, {"POST", "/api/v1/enrollments"}, {"DELETE", "/api/v1/enrollments/ab?confirm=yes"}} {
		if code, _, _ := f.call(c[0], c[1], `{}`, false); code != 401 {
			t.Errorf("%s %s без сессии: %d", c[0], c[1], code)
		}
	}
	code, body, _ := f.call("POST", "/api/v1/enrollments", `{"name":"nat-x"}`, true)
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	id := decodeMap(t, body)["id"].(string) //nolint:forcetypeassert // тест
	for _, c := range [][2]string{{"POST", "/api/v1/enrollments"}, {"DELETE", "/api/v1/enrollments/" + id + "?confirm=yes"}} {
		if code, _, _ := f.call(c[0], c[1], `{"name":"y"}`, true, "Sec-Fetch-Site", "cross-site"); code != 403 {
			t.Errorf("cross-site %s: %d", c[0], code)
		}
	}
	if p, _ := f.st.Enrollments().ListPending(context.Background(), t0); len(p) != 1 {
		t.Fatalf("cross-site запросы изменили токены: %+v", p)
	}
	code, body, _ = f.call("GET", "/api/v1/enrollments", "", true)
	if code != 200 || strings.Contains(body, "token_hash") || !strings.Contains(body, `"name":"nat-x"`) || !strings.Contains(body, `"created_by":"alice"`) {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, _, _ = f.call("DELETE", "/api/v1/enrollments/"+id+"?confirm=yes", "", true); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	au, _ := f.st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 1 || au[0].Action != api.AuditEnrollRevoke || au[0].Actor != "alice" || au[0].IP != "203.0.113.7" || au[0].Target != id {
		t.Fatalf("audit: %+v", au)
	}
}

type fakeAgentSrc []agents.State

func (f fakeAgentSrc) List() []agents.State { return f }
func (f fakeAgentSrc) Get(id string) (agents.State, bool) {
	for _, s := range f {
		if s.Agent.ID == id {
			return s, true
		}
	}
	return agents.State{}, false
}

func tokHash(id string) []byte { h := sha256.Sum256([]byte("st-" + id)); return h[:] }

func TestEnrollStatusMatching(t *testing.T) {
	st := memtest.New()
	ctx := context.Background()
	repo := st.Enrollments()
	mk := func(id, name string, ttl time.Duration) {
		t.Helper()
		if err := repo.Create(ctx, store.Enrollment{ID: id, TokenHash: tokHash(id), Name: name, Weight: 100, CreatedAt: t0, ExpiresAt: t0.Add(ttl)}); err != nil {
			t.Fatal(err)
		}
	}
	mk("a1", "waw-2", time.Hour)
	if _, err := repo.Consume(ctx, tokHash("a1"), t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reverse := func(id string, up bool, created time.Time) agents.State {
		return agents.State{Agent: store.Agent{ID: id, Name: "waw-2", Mode: store.ModeReverse, CreatedAt: created}, Up: up}
	}
	src := fakeAgentSrc{reverse("waw-2-old", true, t0.Add(-24*time.Hour))} // агент, созданный до токена, не засчитывается
	svc := api.NewEnrollService(api.EnrollConfig{Enrollments: repo, Agents: src, Now: func() time.Time { return t0.Add(2 * time.Minute) }})
	got, err := svc.Status(ctx, "a1")
	if err != nil || got.State != api.EnrollEnrolled || got.AgentID != "" {
		t.Fatalf("старый агент: %+v %v", got, err)
	}
	svc = api.NewEnrollService(api.EnrollConfig{Enrollments: repo, Agents: append(src, reverse("waw-2", false, t0.Add(time.Minute))), Now: func() time.Time { return t0 }})
	if got, _ = svc.Status(ctx, "a1"); got.State != api.EnrollEnrolled || got.AgentID != "waw-2" {
		t.Fatalf("down: %+v", got)
	}
	svc = api.NewEnrollService(api.EnrollConfig{Enrollments: repo, Agents: append(src, reverse("waw-2", true, t0.Add(time.Minute))), Now: func() time.Time { return t0 }})
	if got, _ = svc.Status(ctx, "a1"); got.State != api.EnrollConnected || got.AgentID != "waw-2" {
		t.Fatalf("up: %+v", got)
	}
	// без реестра дальше enrolled не идём
	svc = api.NewEnrollService(api.EnrollConfig{Enrollments: repo, Now: func() time.Time { return t0 }})
	if got, _ = svc.Status(ctx, "a1"); got.State != api.EnrollEnrolled {
		t.Fatalf("без реестра: %+v", got)
	}
	// waiting / expired / revoked
	mk("b2", "x", time.Hour)
	if got, _ = svc.Status(ctx, "b2"); got.State != api.EnrollWaiting || got.Left != time.Hour {
		t.Fatalf("waiting: %+v", got)
	}
	svc = api.NewEnrollService(api.EnrollConfig{Enrollments: repo, Now: func() time.Time { return t0.Add(2 * time.Hour) }})
	if got, _ = svc.Status(ctx, "b2"); got.State != api.EnrollExpired || got.Left != 0 {
		t.Fatalf("expired: %+v", got)
	}
	if got, _ = svc.Status(ctx, "zz"); got.State != api.EnrollRevoked {
		t.Fatalf("revoked: %+v", got)
	}
	if _, err = api.NewEnrollService(api.EnrollConfig{}).Status(ctx, "a1"); !errors.Is(err, api.ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
}
