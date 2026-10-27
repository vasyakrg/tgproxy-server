package api_test

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/ban"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func newBanFx(t *testing.T) (*acFx, *ban.Manager) {
	t.Helper()
	f := newAcFx(t)
	mgr, err := ban.New(context.Background(), f.st.Bans(), ban.Options{
		Config:  config.BanConfig{Enabled: true, Threshold: 5, Window: time.Minute, Duration: time.Hour, ResetAfter: time.Hour, MaxTracked: 100},
		Protect: ban.StaticProtector{Trusted: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Wait)
	svc := api.NewBansService(mgr, f.st.Audit(), nil, nil)
	(&api.BansAPI{Service: svc, ClientIP: func(*http.Request) string { return "203.0.113.7" },
		Country: func(string) string { return "NL" }}).Routes(f.mux, f.wrap)
	return f, mgr
}

func TestBansAPIAuthAndCSRF(t *testing.T) {
	f, _ := newBanFx(t)
	for _, c := range [][2]string{{"GET", "/api/v1/bans"}, {"POST", "/api/v1/bans"}, {"DELETE", "/api/v1/bans/1"}} {
		if code, _, _ := f.call(c[0], c[1], `{}`, false); code != 401 {
			t.Errorf("%s %s без сессии: %d", c[0], c[1], code)
		}
	}
	for _, c := range [][2]string{{"POST", "/api/v1/bans"}, {"DELETE", "/api/v1/bans/1"}} {
		if code, _, _ := f.call(c[0], c[1], `{"ip":"8.8.8.8","permanent":true}`, true, "Sec-Fetch-Site", "cross-site"); code != 403 {
			t.Errorf("cross-site %s: %d", c[0], code)
		}
	}
	if bans, _ := f.st.Bans().ListActive(context.Background(), time.Now()); len(bans) != 0 {
		t.Fatalf("cross-site запросы создали баны: %+v", bans)
	}
}

func TestBansAPICreateListDeleteAudit(t *testing.T) {
	f, mgr := newBanFx(t)
	code, body, _ := f.call("POST", "/api/v1/bans", `{"ip":"198.51.100.20","duration":"7d","comment":"сканер"}`, true)
	if code != 201 {
		t.Fatalf("%d %s", code, body)
	}
	m := decodeMap(t, body)
	if m["ip"] != "198.51.100.20" || m["source"] != "manual" || m["actor"] != "alice" || m["country"] != "NL" ||
		m["comment"] != "сканер" || m["remaining_sec"] == nil || m["expires_at"] == nil {
		t.Fatalf("ответ: %s", body)
	}
	if !mgr.Banned(netip.MustParseAddr("198.51.100.20")) {
		t.Fatal("бан не применился сразу")
	}
	code, body, _ = f.call("POST", "/api/v1/bans", `{"ip":"2001:db8:1:2::77","permanent":true}`, true)
	if code != 201 || decodeMap(t, body)["ip"] != "2001:db8:1:2::/64" || decodeMap(t, body)["expires_at"] != nil {
		t.Fatalf("v6 permanent: %d %s", code, body)
	}
	code, body, _ = f.call("GET", "/api/v1/bans", "", true)
	items := decodeMap(t, body)["items"].([]any) //nolint:forcetypeassert // тест
	if code != 200 || len(items) != 2 {
		t.Fatalf("list: %d %s", code, body)
	}
	id := int(items[0].(map[string]any)["id"].(float64)) //nolint:forcetypeassert // тест
	if code, _, _ := f.call("DELETE", "/api/v1/bans/"+itoa(id), "", true); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _, _ := f.call("DELETE", "/api/v1/bans/"+itoa(id), "", true); code != 404 {
		t.Fatalf("повторный delete: %d", code)
	}
	if code, _, _ := f.call("DELETE", "/api/v1/bans/abc", "", true); code != 404 {
		t.Fatalf("кривой id: %d", code)
	}
	au, _ := f.st.Audit().List(context.Background(), store.AuditQuery{})
	var created, deleted int
	for _, e := range au {
		if e.Actor != "alice" || e.IP != "203.0.113.7" {
			t.Errorf("аудит: %+v", e)
		}
		switch e.Action {
		case api.AuditBanCreate:
			created++
		case api.AuditBanDelete:
			deleted++
		}
	}
	if created != 2 || deleted != 1 {
		t.Fatalf("аудит create=%d delete=%d: %+v", created, deleted, au)
	}
}

func TestBansAPIValidation(t *testing.T) {
	f, _ := newBanFx(t)
	cases := []struct{ name, body, field string }{
		{"не IP", `{"ip":"bogus","duration":"1h"}`, "ip"},
		{"пустой IP", `{"duration":"1h"}`, "ip"},
		{"маска вместо IP", `{"ip":"10.0.0.0/8","duration":"1h"}`, "ip"},
		{"нет срока", `{"ip":"8.8.8.8"}`, "duration"},
		{"срок и навсегда", `{"ip":"8.8.8.8","duration":"1h","permanent":true}`, "duration"},
		{"кривой срок", `{"ip":"8.8.8.8","duration":"soon"}`, "duration"},
		{"отрицательный срок", `{"ip":"8.8.8.8","duration":"-1h"}`, "duration"},
		{"слишком долго", `{"ip":"8.8.8.8","duration":"400d"}`, "duration"},
		{"длинный комментарий", `{"ip":"8.8.8.8","duration":"1h","comment":"` + strings.Repeat("я", 201) + `"}`, "comment"},
		{"доверенный прокси", `{"ip":"192.0.2.15","permanent":true}`, "ip"},
		{"loopback", `{"ip":"127.0.0.1","permanent":true}`, "ip"},
		{"приватный", `{"ip":"10.1.2.3","duration":"1h"}`, "ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := f.call("POST", "/api/v1/bans", tc.body, true)
			fields, _ := decodeMap(t, body)["fields"].(map[string]any)
			if code != http.StatusUnprocessableEntity || fields[tc.field] == nil {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
	for _, b := range []string{`{`, `{"ip":"8.8.8.8","duration":"1h","evil":1}`} {
		if code, _, _ := f.call("POST", "/api/v1/bans", b, true); code != 400 {
			t.Errorf("%s: %d", b, code)
		}
	}
	if bans, _ := f.st.Bans().ListActive(context.Background(), time.Now()); len(bans) != 0 {
		t.Errorf("невалидный ввод создал баны: %+v", bans)
	}
}

func TestParseBanDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 168 * time.Hour, "30m": 30 * time.Minute} {
		if got, err := api.ParseBanDuration(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0d", "-1d", "d", "1.5d", "999d", "x"} {
		if _, err := api.ParseBanDuration(bad); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
