package api_test

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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/link"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

var mtKeyRe = regexp.MustCompile(`ee[0-9a-f]{32,}`)

type mtClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *mtClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *mtClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.off += d
}

type mtFx struct {
	t     *testing.T
	st    *memtest.Store
	a     *auth.Auth
	sess  *auth.Session
	mux   acMux
	sid   *http.Cookie
	logs  *bytes.Buffer
	clock *mtClock
	ep    api.MTProtoEndpoint
}

func newMtFx(t *testing.T) *mtFx {
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
	clk := &mtClock{}
	f := &mtFx{t: t, st: st, clock: clk, mux: acMux{http.NewServeMux()}, logs: &bytes.Buffer{},
		ep: api.MTProtoEndpoint{Host: "tg.example.test", Port: 443, Domain: "tg.example.test", Enabled: true}}
	f.a = auth.New(auth.Options{Users: users, Store: st, TOTP: auth.NewTOTP(acSealer{}, st.RateState(), "t"), AllowPasswordOnly: true, Logger: quiet, Now: clk.now})
	f.sess, err = f.a.Sessions().Create(context.Background(), "alice", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	f.sid = &http.Cookie{Name: auth.SessionCookie, Value: f.sess.Token}
	logger := slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := api.NewMTProtoService(st.MTProtoSecrets(), st.Audit(), acSealer{}, func() api.MTProtoEndpoint { return f.ep }, logger, clk.now)
	wrap := func(h http.Handler) http.Handler { return auth.Protect(f.a.RequireAuth(h)) }
	(&api.MTProtoAPI{
		Service: svc, ClientIP: func(*http.Request) string { return "203.0.113.7" },
		ActiveConns: func(name string) int {
			if name == "busy" {
				return 7
			}
			return 0
		},
		Fresh: api.NewFreshTOTP(f.a),
	}).Routes(f.mux, wrap)
	return f
}

func (f *mtFx) call(method, path, body string, withSession bool, hdr ...string) (int, string) {
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
	return w.Code, w.Body.String()
}

func (f *mtFx) fresh() {
	f.t.Helper()
	if err := f.a.MarkTOTPFresh(context.Background(), f.sess); err != nil {
		f.t.Fatal(err)
	}
}

func (f *mtFx) create(name string) map[string]any {
	f.t.Helper()
	code, body := f.call("POST", "/api/v1/mtproto/secrets", fmt.Sprintf(`{"name":%q}`, name), true)
	if code != 201 {
		f.t.Fatalf("create: %d %s", code, body)
	}
	return decodeMap(f.t, body)
}

func (f *mtFx) auditActions() []string {
	es, err := f.st.Audit().List(context.Background(), store.AuditQuery{Limit: 100})
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Action)
	}
	return out
}

func TestMTProtoRequiresAuthAndCSRF(t *testing.T) {
	f := newMtFx(t)
	for _, c := range [][2]string{
		{"GET", "/api/v1/mtproto/secrets"}, {"POST", "/api/v1/mtproto/secrets"},
		{"PATCH", "/api/v1/mtproto/secrets/1"}, {"DELETE", "/api/v1/mtproto/secrets/1?confirm=yes"},
		{"POST", "/api/v1/mtproto/secrets/1/rotate"}, {"GET", "/api/v1/mtproto/secrets/1/link"},
		{"POST", "/api/v1/mtproto/secrets/1/purge?confirm=yes"}, {"POST", "/api/v1/mtproto/secrets/purge-revoked?confirm=yes"},
	} {
		if code, _ := f.call(c[0], c[1], `{}`, false); code != 401 {
			t.Errorf("%s %s без сессии: %d", c[0], c[1], code)
		}
	}
	for _, c := range [][3]string{
		{"POST", "/api/v1/mtproto/secrets", `{"name":"x"}`},
		{"PATCH", "/api/v1/mtproto/secrets/1", `{"enabled":false}`},
		{"DELETE", "/api/v1/mtproto/secrets/1?confirm=yes", ``},
		{"POST", "/api/v1/mtproto/secrets/1/purge?confirm=yes", ``},
		{"POST", "/api/v1/mtproto/secrets/purge-revoked?confirm=yes", ``},
		{"POST", "/api/v1/mtproto/secrets/1/rotate", `{}`},
	} {
		if code, _ := f.call(c[0], c[1], c[2], true, "Sec-Fetch-Site", "cross-site"); code != 403 {
			t.Errorf("cross-site %s %s: %d", c[0], c[1], code)
		}
	}
}

func TestMTProtoCreateReturnsLinkOnce(t *testing.T) {
	f := newMtFx(t)
	code, body := f.call("POST", "/api/v1/mtproto/secrets", `{"name":"team","cidrs":["10.0.0.0/8"],"max_conns":5}`, true)
	if code != 201 {
		t.Fatalf("%d %s", code, body)
	}
	m := decodeMap(t, body)
	ln, _ := m["link"].(map[string]any)
	tg, _ := ln["tg"].(string)
	if !strings.HasPrefix(tg, "tg://proxy?server=tg.example.test&port=443&secret=ee") || !strings.HasPrefix(ln["https"].(string), "https://t.me/proxy?") {
		t.Fatalf("link: %v", ln)
	}
	if !strings.HasPrefix(ln["qr_svg"].(string), "<svg") {
		t.Fatal("нет qr_svg")
	}
	host, port, key, domain, err := link.Parse(tg)
	if err != nil || host != "tg.example.test" || port != 443 || domain != "tg.example.test" {
		t.Fatalf("parse: %v %s %d %s", err, host, port, domain)
	}
	keyHex := fmt.Sprintf("%x", key[:])
	if m["prefix"] != keyHex[:4] || m["max_conns"].(float64) != 5 || m["disabled"] != false {
		t.Fatalf("поля: %v", m)
	}
	// секрет в БД зашифрован и расшифровывается под AAD "mtproto/<id>"
	row, _ := f.st.MTProtoSecrets().Get(context.Background(), int64(m["id"].(float64)))
	pt, err := acSealer{}.Open(row.SecretEnc, []byte(fmt.Sprintf("mtproto/%d", row.ID)))
	if err != nil || !bytes.Equal(pt, key[:]) {
		t.Fatalf("seal: %v", err)
	}
	// список — только префикс
	_, list := f.call("GET", "/api/v1/mtproto/secrets", "", true)
	if strings.Contains(list, keyHex) || mtKeyRe.MatchString(list) || strings.Contains(list, `"link"`) || strings.Contains(list, "tg://") {
		t.Fatalf("список выдал ключ: %s", list)
	}
	if !strings.Contains(list, `"prefix":"`+keyHex[:4]+`"`) {
		t.Fatalf("нет префикса: %s", list)
	}
	// ключа нет ни в аудите, ни в логах
	es, _ := f.st.Audit().List(context.Background(), store.AuditQuery{Limit: 10})
	for _, e := range es {
		if strings.Contains(e.Detail+e.Target, keyHex) {
			t.Fatalf("ключ в аудите: %+v", e)
		}
	}
	if strings.Contains(f.logs.String(), keyHex) {
		t.Fatal("ключ в логах")
	}
	if got := f.auditActions(); len(got) != 1 || got[0] != api.AuditMTProtoCreate {
		t.Fatalf("аудит: %v", got)
	}
}

func TestMTProtoCreateValidation(t *testing.T) {
	f := newMtFx(t)
	f.create("dup")
	for body, want := range map[string]string{
		`{"name":""}`:                    "name",
		`{"name":"-x-","cidrs":[]}`:      "name",
		`{"name":"ok","cidrs":["nope"]}`: "cidrs",
		`{"name":"ok","max_conns":-1}`:   "max_conns",
		`{"name":"dup"}`:                 "name",
		`{"name":"ok","unknown":1}`:      "",
	} {
		code, resp := f.call("POST", "/api/v1/mtproto/secrets", body, true)
		if want == "" {
			if code != 400 {
				t.Errorf("%s: %d", body, code)
			}
			continue
		}
		if code != 422 || !strings.Contains(resp, `"`+want+`"`) {
			t.Errorf("%s: %d %s", body, code, resp)
		}
	}
}

func TestMTProtoDisabledFlagAndNoEndpoint(t *testing.T) {
	f := newMtFx(t)
	f.ep.Enabled = false
	code, body := f.call("POST", "/api/v1/mtproto/secrets", `{"name":"early"}`, true)
	if code != 201 || decodeMap(t, body)["disabled"] != true {
		t.Fatalf("disabled: %d %s", code, body)
	}
	_, list := f.call("GET", "/api/v1/mtproto/secrets", "", true)
	if decodeMap(t, list)["disabled"] != true {
		t.Fatalf("list: %s", list)
	}
	f.ep.Domain = ""
	code, body = f.call("POST", "/api/v1/mtproto/secrets", `{"name":"nolink"}`, true)
	m := decodeMap(t, body)
	if code != 201 || m["link"] != nil || m["link_error"] != "endpoint_not_configured" {
		t.Fatalf("без fronting_domain: %d %s", code, body)
	}
}

func TestMTProtoLinkRequiresFreshTOTP(t *testing.T) {
	f := newMtFx(t)
	m := f.create("lnk")
	id := int(m["id"].(float64))
	path := fmt.Sprintf("/api/v1/mtproto/secrets/%d/link", id)
	code, body := f.call("GET", path, "", true)
	if code != 401 || !strings.Contains(body, `"totp_required"`) {
		t.Fatalf("без свежего TOTP: %d %s", code, body)
	}
	if got := f.auditActions(); len(got) != 1 {
		t.Fatalf("отказ не должен писать reveal: %v", got)
	}
	f.fresh()
	code, body = f.call("GET", path, "", true)
	if code != 200 {
		t.Fatalf("со свежим: %d %s", code, body)
	}
	lk := decodeMap(t, body)
	if lk["tg"] != m["link"].(map[string]any)["tg"] || !strings.HasPrefix(lk["qr_svg"].(string), "<svg") {
		t.Fatalf("ссылка не совпала: %s", body)
	}
	got := f.auditActions()
	if len(got) != 2 || got[0] != api.AuditMTProtoReveal && got[1] != api.AuditMTProtoReveal {
		t.Fatalf("аудит: %v", got)
	}
	es, _ := f.st.Audit().List(context.Background(), store.AuditQuery{Limit: 10})
	for _, e := range es {
		if mtKeyRe.MatchString(e.Detail + e.Target) {
			t.Fatalf("ключ в аудите: %+v", e)
		}
	}
	// через 5 минут и секунду — снова нужен TOTP
	f.clock.advance(auth.FreshTOTPWindow + time.Second)
	if code, body = f.call("GET", path, "", true); code != 401 || !strings.Contains(body, "totp_required") {
		t.Fatalf("протухший: %d %s", code, body)
	}
	if code, _ = f.call("GET", "/api/v1/mtproto/secrets/999/link", "", true); code != 401 {
		t.Fatalf("несвежий + несуществующий: %d", code)
	}
}

func TestMTProtoLinkNilFreshFailsClosed(t *testing.T) {
	f := newMtFx(t)
	mux := acMux{http.NewServeMux()}
	svc := api.NewMTProtoService(f.st.MTProtoSecrets(), f.st.Audit(), acSealer{}, func() api.MTProtoEndpoint { return f.ep }, nil, nil)
	(&api.MTProtoAPI{Service: svc}).Routes(mux, nil)
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/mtproto/secrets/1/link", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("без Fresh: %d", w.Code)
	}
}

func TestMTProtoRevokeNeedsConfirm(t *testing.T) {
	f := newMtFx(t)
	id := int(f.create("gone")["id"].(float64))
	p := fmt.Sprintf("/api/v1/mtproto/secrets/%d", id)
	for _, q := range []string{"", "?confirm=no", "?confirm=1"} {
		if code, body := f.call("DELETE", p+q, "", true); code != 400 || !strings.Contains(body, "confirm_required") {
			t.Fatalf("%q: %d %s", q, code, body)
		}
	}
	if row, _ := f.st.MTProtoSecrets().Get(context.Background(), int64(id)); row.RevokedAt != nil {
		t.Fatal("отозван без confirm")
	}
	if code, _ := f.call("DELETE", p+"?confirm=yes", "", true); code != 204 {
		t.Fatalf("confirm=yes: %d", code)
	}
	row, _ := f.st.MTProtoSecrets().Get(context.Background(), int64(id))
	if row.RevokedAt == nil || row.Enabled {
		t.Fatalf("не отозван: %+v", row)
	}
	_, list := f.call("GET", "/api/v1/mtproto/secrets", "", true)
	if !strings.Contains(list, `"status":"revoked"`) {
		t.Fatalf("статус: %s", list)
	}
	if code, _ := f.call("DELETE", "/api/v1/mtproto/secrets/999?confirm=yes", "", true); code != 404 {
		t.Fatalf("нет секрета: %d", code)
	}
	f.fresh()
	if code, _ := f.call("GET", p+"/link", "", true); code != 404 {
		t.Fatalf("link отозванного: %d", code)
	}
	if got := f.auditActions(); got[len(got)-1] != api.AuditMTProtoRevoke && got[0] != api.AuditMTProtoRevoke {
		t.Fatalf("аудит: %v", got)
	}
}

func TestMTProtoRotate(t *testing.T) {
	f := newMtFx(t)
	old := f.create("rot")
	oldID := int(old["id"].(float64))
	oldTG := old["link"].(map[string]any)["tg"]
	p := fmt.Sprintf("/api/v1/mtproto/secrets/%d/rotate", oldID)

	code, body := f.call("POST", p, `{"grace":"1h"}`, true)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	nw := decodeMap(t, body)
	if int(nw["id"].(float64)) == oldID || nw["name"] != "rot" || nw["link"].(map[string]any)["tg"] == oldTG {
		t.Fatalf("новый секрет: %v", nw)
	}
	if int(nw["rotated_from"].(float64)) != oldID {
		t.Fatalf("rotated_from: %v", nw)
	}
	row, _ := f.st.MTProtoSecrets().Get(context.Background(), int64(oldID))
	if row.GraceUntil == nil || row.RevokedAt == nil {
		t.Fatalf("старый без grace: %+v", row)
	}
	if d := row.GraceUntil.Sub(f.clock.now()); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("grace_until: %v", d)
	}
	_, list := f.call("GET", "/api/v1/mtproto/secrets", "", true)
	if !strings.Contains(list, `"status":"grace"`) {
		t.Fatalf("grace-статус: %s", list)
	}
	// ротация без тела: grace 0 -> старый сразу не принимается
	nid := int(nw["id"].(float64))
	if code, body = f.call("POST", fmt.Sprintf("/api/v1/mtproto/secrets/%d/rotate", nid), ``, true); code != 200 {
		t.Fatalf("без тела: %d %s", code, body)
	}
	prev, _ := f.st.MTProtoSecrets().Get(context.Background(), int64(nid))
	if prev.RevokedAt == nil || prev.Active(f.clock.now()) {
		t.Fatalf("grace=0: %+v", prev)
	}
	// отозванный не ротируется; плохой grace
	if code, _ = f.call("POST", p, `{}`, true); code != 422 {
		t.Fatalf("ротация отозванного: %d", code)
	}
	cur := decodeMap(t, body)
	cp := fmt.Sprintf("/api/v1/mtproto/secrets/%d/rotate", int(cur["id"].(float64)))
	for _, g := range []string{`{"grace":"abc"}`, `{"grace":"-1h"}`, `{"grace":"9999h"}`} {
		if code, _ = f.call("POST", cp, g, true); code != 422 {
			t.Errorf("%s: %d", g, code)
		}
	}
	if code, _ = f.call("POST", "/api/v1/mtproto/secrets/999/rotate", `{}`, true); code != 404 {
		t.Fatalf("404: %d", code)
	}
	found := 0
	for _, a := range f.auditActions() {
		if a == api.AuditMTProtoRotate {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("аудит rotate: %d", found)
	}
}

func TestMTProtoPatchAndActiveConns(t *testing.T) {
	f := newMtFx(t)
	id := int(f.create("busy")["id"].(float64))
	p := fmt.Sprintf("/api/v1/mtproto/secrets/%d", id)
	code, body := f.call("PATCH", p, `{"name":"renamed","cidrs":["192.0.2.0/24"],"max_conns":9,"enabled":false}`, true)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	m := decodeMap(t, body)
	if m["name"] != "renamed" || m["enabled"] != false || m["status"] != "disabled" || m["max_conns"].(float64) != 9 {
		t.Fatalf("patch: %v", m)
	}
	if code, _ = f.call("PATCH", p, `{"max_conns":-5}`, true); code != 422 {
		t.Fatalf("валидация: %d", code)
	}
	if code, _ = f.call("PATCH", "/api/v1/mtproto/secrets/999", `{}`, true); code != 404 {
		t.Fatalf("404: %d", code)
	}
	if code, _ = f.call("PATCH", "/api/v1/mtproto/secrets/abc", `{}`, true); code != 404 {
		t.Fatalf("bad id: %d", code)
	}
	f.call("PATCH", p, `{"name":"busy"}`, true)
	_, list := f.call("GET", "/api/v1/mtproto/secrets", "", true)
	if !strings.Contains(list, `"active_conns":7`) {
		t.Fatalf("active_conns: %s", list)
	}
	f.call("DELETE", p+"?confirm=yes", "", true)
	if code, _ = f.call("PATCH", p, `{"enabled":true}`, true); code != 422 {
		t.Fatalf("правка отозванного: %d", code)
	}
}

func TestResolveMTProtoEndpoint(t *testing.T) {
	cases := []struct {
		name, host, base, proxy, listen string
		pubPort                         int
		wantHost                        string
		wantPort                        int
	}{
		{"shared, хост из base_url", "", "https://tg.example.test/", "0.0.0.0:8443", "shared", 0, "tg.example.test", 8443},
		{"public_host/public_port", "mt.example.test", "https://tg.example.test", ":443", "shared", 4443, "mt.example.test", 4443},
		{"dedicated", "", "https://tg.example.test", ":443", "198.51.100.2:8444", 0, "tg.example.test", 8444},
	}
	for _, c := range cases {
		m := config.MTProtoConfig{PublicHost: c.host, Listen: c.listen, PublicPort: c.pubPort, FrontingDomain: "tg.example.test", Enabled: true}
		ep := api.ResolveMTProtoEndpoint(m, c.base, c.proxy)
		if ep.Host != c.wantHost || ep.Port != c.wantPort {
			t.Errorf("%s: %+v", c.name, ep)
		}
	}
}

func (f *mtFx) count(action string) int {
	n := 0
	for _, a := range f.auditActions() {
		if a == action {
			n++
		}
	}
	return n
}

func TestMTProtoPurge(t *testing.T) {
	f := newMtFx(t)
	ctx := context.Background()
	live := int(f.create("live")["id"].(float64))
	p := fmt.Sprintf("/api/v1/mtproto/secrets/%d/purge", live)

	for _, q := range []string{"", "?confirm=no"} {
		if code, body := f.call("POST", p+q, "", true); code != 400 || !strings.Contains(body, "confirm_required") {
			t.Fatalf("%q: %d %s", q, code, body)
		}
	}
	// активный — отказ, секрет остаётся
	if code, body := f.call("POST", p+"?confirm=yes", "", true); code != 409 || !strings.Contains(body, "still_active") {
		t.Fatalf("активный: %d %s", code, body)
	}
	// grace не истёк — тоже отказ
	rot := f.call2(t, "POST", p[:len(p)-len("purge")]+"rotate", `{"grace":"1m"}`)
	if code, _ := f.call("POST", p+"?confirm=yes", "", true); code != 409 {
		t.Fatalf("grace: %d", code)
	}
	if _, err := f.st.MTProtoSecrets().Get(ctx, int64(live)); err != nil {
		t.Fatal("секрет удалён раньше времени")
	}
	// grace истёк — можно
	f.clock.advance(2 * time.Minute)
	if code, body := f.call("POST", p+"?confirm=yes", "", true); code != 204 {
		t.Fatalf("grace истёк: %d %s", code, body)
	}
	if _, err := f.st.MTProtoSecrets().Get(ctx, int64(live)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("не удалён: %v", err)
	}
	if code, _ := f.call("POST", p+"?confirm=yes", "", true); code != 404 {
		t.Fatalf("повтор: %d", code)
	}
	if f.count(api.AuditMTProtoPurge) != 1 {
		t.Fatalf("аудит: %v", f.auditActions())
	}
	// новый (ротированный) остаётся и работает
	if _, err := f.st.MTProtoSecrets().Get(ctx, int64(rot["id"].(float64))); err != nil {
		t.Fatal(err)
	}

	// массовое: отозванные удаляются, активные — нет
	a := int(f.create("a")["id"].(float64))
	b := int(f.create("b")["id"].(float64))
	f.create("c")
	for _, id := range []int{a, b} {
		if code, _ := f.call("DELETE", fmt.Sprintf("/api/v1/mtproto/secrets/%d?confirm=yes", id), "", true); code != 204 {
			t.Fatal(code)
		}
	}
	if code, body := f.call("POST", "/api/v1/mtproto/secrets/purge-revoked", "", true); code != 400 {
		t.Fatalf("без confirm: %d %s", code, body)
	}
	code, body := f.call("POST", "/api/v1/mtproto/secrets/purge-revoked?confirm=yes", "", true)
	if code != 200 || decodeMap(t, body)["deleted"].(float64) != 2 {
		t.Fatalf("bulk: %d %s", code, body)
	}
	left, _ := f.st.MTProtoSecrets().List(ctx)
	if len(left) != 2 { // ротированный "live" и "c"
		t.Fatalf("осталось %d", len(left))
	}
	if f.count(api.AuditMTProtoPurge) != 3 {
		t.Fatalf("аудит bulk: %v", f.auditActions())
	}
	if _, body = f.call("POST", "/api/v1/mtproto/secrets/purge-revoked?confirm=yes", "", true); decodeMap(t, body)["deleted"].(float64) != 0 {
		t.Fatalf("повторный bulk: %s", body)
	}
}

func (f *mtFx) call2(t *testing.T, method, path, body string) map[string]any {
	t.Helper()
	code, out := f.call(method, path, body, true)
	if code != 200 {
		t.Fatalf("%s %s: %d %s", method, path, code, out)
	}
	return decodeMap(t, out)
}
