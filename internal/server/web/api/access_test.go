package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

var acKeyRe = regexp.MustCompile(`tgp_[0-9A-Za-z]{24}`)

type acSealer struct{}

func (acSealer) Seal(pt, aad []byte) ([]byte, error) {
	return append(append([]byte{}, aad...), append([]byte{'|'}, pt...)...), nil
}

func (acSealer) Open(ct, aad []byte) ([]byte, error) {
	p := append(append([]byte{}, aad...), '|')
	if !bytes.HasPrefix(ct, p) {
		return nil, errors.New("aad mismatch")
	}
	return ct[len(p):], nil
}

type acMux struct{ *http.ServeMux }

func (m acMux) Mount(pattern string, h http.Handler) { m.Handle(pattern, h) }

type acFx struct {
	t    *testing.T
	st   *memtest.Store
	mux  acMux
	sid  *http.Cookie
	logs *bytes.Buffer
	wrap api.Wrap
}

func newAcFx(t *testing.T) *acFx {
	t.Helper()
	st := memtest.New()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	hash, err := auth.Hash("pw", auth.HashParams{M: 64, T: 1, P: 1, SaltLen: 16, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "users.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("users:\n  alice:\n    password: '%s'\n", hash)), 0o640); err != nil { //nolint:gosec // тест
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // тест
		t.Fatal(err)
	}
	users, err := auth.LoadUsers(path, quiet)
	if err != nil {
		t.Fatal(err)
	}
	a := auth.New(auth.Options{Users: users, Store: st, TOTP: auth.NewTOTP(acSealer{}, st.RateState(), "t"), AllowPasswordOnly: true, Logger: quiet})
	s, err := a.Sessions().Create(context.Background(), "alice", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(h http.Handler) http.Handler { return auth.Protect(a.RequireAuth(h)) }
	f := &acFx{t: t, st: st, wrap: wrap, mux: acMux{http.NewServeMux()}, sid: &http.Cookie{Name: auth.SessionCookie, Value: s.Token}, logs: &bytes.Buffer{}}
	logger := slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := api.NewAccessService(st.AccessRules(), st.Audit(), logger, func() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) })
	(&api.AccessAPI{
		Service:  svc,
		ClientIP: func(*http.Request) string { return "203.0.113.7" },
		BaseURL:  func() string { return "https://tgproxy.test/" },
		Stats: func(name string) (int64, time.Time, bool) {
			if name == "seen" {
				return 42, time.Date(2026, 3, 1, 11, 0, 0, 0, time.UTC), true
			}
			return 0, time.Time{}, false
		},
	}).Routes(f.mux, f.wrap)
	return f
}

func (f *acFx) call(method, path, body string, withSession bool, hdr ...string) (int, string, http.Header) {
	f.t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.7:1"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	if withSession {
		r.AddCookie(f.sid)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w.Code, w.Body.String(), w.Header()
}

func decodeMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("json: %v: %s", err, s)
	}
	return m
}

func TestAPIRequiresAuth(t *testing.T) {
	f := newAcFx(t)
	for _, c := range [][2]string{{"GET", "/api/v1/access-rules"}, {"POST", "/api/v1/access-rules"}, {"PATCH", "/api/v1/access-rules/1"}, {"DELETE", "/api/v1/access-rules/1"}} {
		if code, _, _ := f.call(c[0], c[1], `{}`, false); code != 401 {
			t.Errorf("%s %s без сессии: %d", c[0], c[1], code)
		}
	}
	if code, _, _ := f.call("POST", "/api/v1/access-rules", `{"name":"x","cidrs":["10.0.0.0/8"]}`, true, "Sec-Fetch-Site", "cross-site"); code != 403 {
		t.Errorf("cross-site POST: %d", code)
	}
}

func TestAPICreateReturnsKeyOnlyOnce(t *testing.T) {
	f := newAcFx(t)
	code, body, h := f.call("POST", "/api/v1/access-rules", `{"name":"crm","with_key":true,"cidrs":["10.0.0.0/8"],"rps":30}`, true)
	if code != 201 {
		t.Fatalf("code=%d %s", code, body)
	}
	if h.Get("Cache-Control") != "no-store" || h.Get("Location") != "/api/v1/access-rules/1" {
		t.Errorf("заголовки: %v", h)
	}
	m := decodeMap(t, body)
	key, _ := m["key"].(string)
	if !acKeyRe.MatchString(key) || m["base_url"] != "https://tgproxy.test/k/"+key || m["kind"] != "network+key" || m["key_prefix"] != key[:8] {
		t.Fatalf("ответ создания: %s", body)
	}
	if _, has := m["key_hash"]; has {
		t.Error("хеш наружу не отдаётся")
	}
	// в БД — только хеш
	r, err := f.st.AccessRules().Get(context.Background(), 1)
	if err != nil || !bytes.Equal(r.KeyHash, access.HashKey(key)) {
		t.Fatalf("repo: %+v %v", r, err)
	}
	// список, GET после создания, логи, аудит — без ключа
	_, list, _ := f.call("GET", "/api/v1/access-rules", "", true)
	if strings.Contains(list, key) || acKeyRe.MatchString(list) || strings.Contains(list, `"key":`) {
		t.Errorf("ключ в списке: %s", list)
	}
	if strings.Contains(f.logs.String(), key) {
		t.Error("ключ в логах")
	}
	au, _ := f.st.Audit().List(context.Background(), store.AuditQuery{})
	if len(au) != 1 || au[0].Action != api.AuditRuleCreate || au[0].Actor != "alice" || au[0].IP != "203.0.113.7" ||
		strings.Contains(au[0].Detail+au[0].Target, key) || strings.Contains(au[0].Detail, "tgp_") {
		t.Errorf("аудит: %+v", au)
	}
}

func TestAPINetworkRuleHasNoKey(t *testing.T) {
	f := newAcFx(t)
	code, body, _ := f.call("POST", "/api/v1/access-rules", `{"name":"seen","cidrs":["10.20.0.0/16","192.168.1.5"]}`, true)
	if code != 201 {
		t.Fatalf("code=%d %s", code, body)
	}
	m := decodeMap(t, body)
	if _, has := m["key"]; has || m["base_url"] != "https://tgproxy.test" || m["has_key"] != false || m["kind"] != "network" {
		t.Errorf("ответ: %s", body)
	}
	cidrs := m["cidrs"].([]any) //nolint:forcetypeassert // тест
	if len(cidrs) != 2 || cidrs[1] != "192.168.1.5/32" {
		t.Errorf("cidrs: %v", cidrs)
	}
	_, list, _ := f.call("GET", "/api/v1/access-rules", "", true)
	items := decodeMap(t, list)["items"].([]any)[0].(map[string]any) //nolint:forcetypeassert // тест
	if items["requests_24h"] != float64(42) || items["last_seen"] != "2026-03-01T11:00:00Z" {
		t.Errorf("статистика: %s", list)
	}
}

func TestAPIValidation422(t *testing.T) {
	f := newAcFx(t)
	cases := []struct{ name, body, field string }{
		{"невалидный CIDR", `{"name":"x","cidrs":["10.0.0.0/33"]}`, "cidrs"},
		{"не сеть", `{"name":"x","cidrs":["bogus"]}`, "cidrs"},
		{"без сети и ключа", `{"name":"x"}`, "cidrs"},
		{"без сети и ключа, пустой список", `{"name":"x","cidrs":[]}`, "cidrs"},
		{"0.0.0.0/0 без ключа", `{"name":"x","cidrs":["0.0.0.0/0"]}`, "cidrs"},
		{"::/0 без ключа", `{"name":"x","cidrs":["::/0"]}`, "cidrs"},
		{"биты хоста", `{"name":"x","cidrs":["10.1.2.3/8"]}`, "cidrs"},
		{"плохое имя", `{"name":"bad/name","cidrs":["10.0.0.0/8"]}`, "name"},
		{"пустое имя", `{"cidrs":["10.0.0.0/8"]}`, "name"},
		{"отрицательный rps", `{"name":"x","cidrs":["10.0.0.0/8"],"rps":-5}`, "rps"},
		{"огромный rps", `{"name":"x","cidrs":["10.0.0.0/8"],"rps":1e12}`, "rps"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := f.call("POST", "/api/v1/access-rules", tc.body, true)
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("code=%d %s", code, body)
			}
			m := decodeMap(t, body)
			fields, _ := m["fields"].(map[string]any)
			if m["error"] != "validation" || fields[tc.field] == nil || fields[tc.field] == "" {
				t.Errorf("нет ошибки поля %s: %s", tc.field, body)
			}
		})
	}
	if rs, _ := f.st.AccessRules().List(context.Background()); len(rs) != 0 {
		t.Errorf("созданы невалидные правила: %d", len(rs))
	}
	// 0.0.0.0/0 с ключом разрешён
	if code, body, _ := f.call("POST", "/api/v1/access-rules", `{"name":"any","cidrs":["0.0.0.0/0"],"with_key":true}`, true); code != 201 {
		t.Errorf("0.0.0.0/0 с ключом: %d %s", code, body)
	}
	// дубликат имени
	code, body, _ := f.call("POST", "/api/v1/access-rules", `{"name":"any","cidrs":["10.0.0.0/8"]}`, true)
	if code != 422 || decodeMap(t, body)["fields"].(map[string]any)["name"] == nil { //nolint:forcetypeassert // тест
		t.Errorf("дубликат: %d %s", code, body)
	}
	// некорректный JSON / неизвестные поля -> 400
	for _, b := range []string{`{`, `{"name":"x","cidrs":["10.0.0.0/8"],"key_hash":"aa"}`, `[]`} {
		if code, _, _ := f.call("POST", "/api/v1/access-rules", b, true); code != 400 {
			t.Errorf("%s: %d", b, code)
		}
	}
}

func TestAPIPatchAndDelete(t *testing.T) {
	f := newAcFx(t)
	f.call("POST", "/api/v1/access-rules", `{"name":"office","cidrs":["10.0.0.0/8"],"rps":5}`, true)
	f.call("POST", "/api/v1/access-rules", `{"name":"crm","with_key":true}`, true)
	before, _ := f.st.AccessRules().Version(context.Background())

	code, body, _ := f.call("PATCH", "/api/v1/access-rules/1", `{"cidrs":["172.16.0.0/12"],"rps":9,"enabled":false,"name":"office2"}`, true)
	if code != 200 {
		t.Fatalf("code=%d %s", code, body)
	}
	m := decodeMap(t, body)
	if m["name"] != "office2" || m["rps"] != float64(9) || m["enabled"] != false || m["cidrs"].([]any)[0] != "172.16.0.0/12" { //nolint:forcetypeassert // тест
		t.Errorf("ответ: %s", body)
	}
	if after, _ := f.st.AccessRules().Version(context.Background()); after == before {
		t.Error("версия правил должна расти (инвалидация кеша access)")
	}
	r, _ := f.st.AccessRules().Get(context.Background(), 1)
	if r.Name != "office2" || r.Enabled || r.RPS != 9 {
		t.Errorf("repo: %+v", r)
	}
	// частичное: только rps
	if code, _, _ = f.call("PATCH", "/api/v1/access-rules/1", `{"rps":1}`, true); code != 200 {
		t.Errorf("partial: %d", code)
	}
	if r, _ = f.st.AccessRules().Get(context.Background(), 1); r.Name != "office2" || r.RPS != 1 || len(r.CIDRs) != 1 {
		t.Errorf("partial repo: %+v", r)
	}
	// сети убрать у правила с ключом можно, у сетевого — нельзя
	if code, _, _ = f.call("PATCH", "/api/v1/access-rules/2", `{"cidrs":[]}`, true); code != 200 {
		t.Errorf("ключевое без сетей: %d", code)
	}
	code, body, _ = f.call("PATCH", "/api/v1/access-rules/1", `{"cidrs":[]}`, true)
	if code != 422 || decodeMap(t, body)["fields"].(map[string]any)["cidrs"] == nil { //nolint:forcetypeassert // тест
		t.Errorf("сеть без сетей: %d %s", code, body)
	}
	if code, _, _ = f.call("PATCH", "/api/v1/access-rules/1", `{"cidrs":["0.0.0.0/0"]}`, true); code != 422 {
		t.Errorf("0.0.0.0/0 без ключа через PATCH: %d", code)
	}
	if code, _, _ = f.call("PATCH", "/api/v1/access-rules/1", `{"cidrs":["nope"]}`, true); code != 422 {
		t.Errorf("невалидный CIDR через PATCH: %d", code)
	}
	if code, _, _ = f.call("PATCH", "/api/v1/access-rules/99", `{"rps":1}`, true); code != 404 {
		t.Errorf("patch 404: %d", code)
	}
	if code, _, _ = f.call("PATCH", "/api/v1/access-rules/abc", `{"rps":1}`, true); code != 404 {
		t.Errorf("patch abc: %d", code)
	}
	if code, _, _ = f.call("PATCH", "/api/v1/access-rules/1", `{"key":"x"}`, true); code != 400 {
		t.Errorf("ключ менять нельзя: %d", code)
	}

	if code, body, _ = f.call("DELETE", "/api/v1/access-rules/2", "", true); code != 204 || body != "" {
		t.Fatalf("delete: %d %q", code, body)
	}
	if _, err := f.st.AccessRules().Get(context.Background(), 2); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("правило должно быть удалено: %v", err)
	}
	if code, _, _ = f.call("DELETE", "/api/v1/access-rules/2", "", true); code != 404 {
		t.Errorf("повторное удаление: %d", code)
	}
	au, _ := f.st.Audit().List(context.Background(), store.AuditQuery{})
	got := map[string]int{}
	for _, e := range au {
		got[e.Action]++
	}
	if got[api.AuditRuleCreate] != 2 || got[api.AuditRuleUpdate] != 3 || got[api.AuditRuleDelete] != 1 {
		t.Errorf("аудит: %v", got)
	}
}

func TestParseHelpers(t *testing.T) {
	if got := api.SplitCIDRs("10.0.0.0/8\r\n 192.168.0.0/16, fd00::/8;;  \n"); len(got) != 3 {
		t.Errorf("SplitCIDRs: %q", got)
	}
	for in, want := range map[string]float64{"": 0, " 12,5 ": 12.5, "30": 30} {
		if v, e := api.ParseRPS(in); v != want || e != "" {
			t.Errorf("ParseRPS(%q)=%v,%q", in, v, e)
		}
	}
	for _, bad := range []string{"x", "NaN", "Inf", "0x10", "1_0", "1e999"} {
		if _, e := api.ParseRPS(bad); e == "" {
			t.Errorf("ParseRPS(%q) должен отвергаться", bad)
		}
	}
	p, fe := api.ParseCIDRs([]string{"10.0.0.0/8", "10.0.0.0/8", "::1"})
	if len(p) != 2 || fe != nil || p[1].String() != "::1/128" {
		t.Errorf("ParseCIDRs: %v %v", p, fe)
	}
	long := make([]string, 300)
	for i := range long {
		long[i] = "10.0.0.0/8"
	}
	if _, fe := api.ParseCIDRs(long); fe == nil {
		t.Error("слишком много сетей")
	}
	if got := api.BaseURLFor("https://h//", ""); got != "https://h" {
		t.Errorf("BaseURLFor: %q", got)
	}
}
