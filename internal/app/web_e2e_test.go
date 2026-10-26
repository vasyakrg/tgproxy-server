package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
)

var webKeyRe = regexp.MustCompile(`tgp_[0-9A-Za-z]{24}`)

// adminClient — клиент админки с ручным хранением сессионной cookie (__Host-sid — Secure,
// cookiejar не отправляет её по http) и без следования редиректам.
type adminClient struct {
	t      *testing.T
	base   string
	cookie *http.Cookie
	hc     *http.Client
}

func newAdminClient(t *testing.T, base string) *adminClient {
	return &adminClient{t: t, base: base, hc: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// adminResp — ответ админки с уже прочитанным телом.
type adminResp struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie
}

func (c *adminClient) do(method, path string, hdr map[string]string, body io.Reader) (adminResp, string) {
	c.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return adminResp{StatusCode: resp.StatusCode, Header: resp.Header, Cookies: resp.Cookies()}, string(b)
}

func (c *adminClient) form(path string, v url.Values, hdr map[string]string) (adminResp, string) {
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for k, val := range hdr {
		h[k] = val
	}
	return c.do("POST", path, h, strings.NewReader(v.Encode()))
}

func (c *adminClient) login() {
	c.t.Helper()
	resp, body := c.form("/login/password", url.Values{"username": {"admin"}, "password": {testPassword}}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		c.t.Fatalf("login: %d %s", resp.StatusCode, body)
	}
	for _, ck := range resp.Cookies {
		if ck.Name == auth.SessionCookie {
			c.cookie = ck
		}
	}
	if c.cookie == nil {
		c.t.Fatal("login: no session cookie")
	}
}

func TestE2EAdminUI(t *testing.T) {
	// петля 127.0.0.0/8 не в правилах: бот проходит только по ключу из UI
	e := newE2E(t, e2eOpts{rules: []config.AccessRule{localRule("10.0.0.0/8")}})
	c := newAdminClient(t, e.adminURL)

	// без сессии: страница -> 302 /login, API -> 401
	resp, _ := c.do("GET", "/", nil, nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET / without session: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ = c.do("GET", "/api/v1/stats/summary", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("summary without session: %d", resp.StatusCode)
	}
	if resp, _ = c.form("/login/password", url.Values{"username": {"admin"}, "password": {"wrong"}}, nil); resp.StatusCode == http.StatusSeeOther {
		t.Fatal("wrong password accepted")
	}
	// healthz/readyz остаются без авторизации
	if r, _ := e.adminGet("/healthz"); r.StatusCode != 200 {
		t.Fatalf("healthz: %d", r.StatusCode)
	}

	// вход -> Обзор с KPI и именем пользователя в сайдбаре
	c.login()
	resp, body := c.do("GET", "/", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Обзор") || !strings.Contains(body, "admin") {
		t.Fatalf("GET /: %d\n%.400s", resp.StatusCode, body)
	}
	if resp, body = c.do("GET", "/system", nil, nil); resp.StatusCode != 200 || !strings.Contains(body, "Будет в") {
		t.Fatalf("stub /system: %d", resp.StatusCode)
	}
	if resp, body = c.do("GET", "/agents", nil, nil); resp.StatusCode != 200 || strings.Contains(body, "Будет в") || !strings.Contains(body, "local") {
		t.Fatalf("/agents: %d\n%.400s", resp.StatusCode, body)
	}
	resp, body = c.do("GET", "/api/v1/stats/summary", nil, nil)
	var sum map[string]any
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &sum) != nil || sum["rps"] == nil {
		t.Fatalf("summary: %d %s", resp.StatusCode, body)
	}

	// бот пока не проходит; создаём правило-ключ с Unicode-именем через форму
	tokenPath := "/bot" + testToken + "/getMe"
	const ruleName = "Бот Alpha 1"
	resp, body = c.form("/access", url.Values{"name": {ruleName}, "with_key": {"1"}}, map[string]string{"HX-Request": "true"})
	key := webKeyRe.FindString(body)
	if resp.StatusCode != 200 || key == "" || !strings.Contains(body, "http://127.0.0.1:8080/k/"+key) {
		t.Fatalf("create rule: %d\n%.600s", resp.StatusCode, body)
	}
	// ключ виден один раз
	if _, list := c.do("GET", "/access", nil, nil); strings.Contains(list, key) {
		t.Fatal("key shown again on /access")
	}
	// бот проходит без рестарта и без ожидания периодического обновления
	if r, b := e.do("GET", "/k/"+key+tokenPath, nil, nil); r.StatusCode != 200 {
		t.Fatalf("bot by new key: %d %s", r.StatusCode, b)
	}
	if r, _ := e.do("GET", tokenPath, nil, nil); r.StatusCode != 403 {
		t.Fatalf("bot without key: %d", r.StatusCode)
	}
	// счётчик по правилу
	resp, body = c.do("GET", "/api/v1/access-rules", nil, nil)
	var rules struct {
		Items []struct {
			Name        string `json:"name"`
			Requests24h *int64 `json:"requests_24h"`
		} `json:"items"`
	}
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &rules) != nil {
		t.Fatalf("access-rules: %d %s", resp.StatusCode, body)
	}
	var seen bool
	for _, r := range rules.Items {
		if r.Name == ruleName && r.Requests24h != nil && *r.Requests24h == 1 {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("no requests_24h=1 for %q: %s", ruleName, body)
	}

	// кросс-доменный POST -> 403
	resp, _ = c.form("/access", url.Values{"name": {"evil"}, "with_key": {"1"}},
		map[string]string{"HX-Request": "true", "Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST: %d", resp.StatusCode)
	}

	// выход гасит сессию
	if resp, _ = c.form("/logout", url.Values{}, nil); resp.StatusCode >= 400 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp, _ = c.do("GET", "/", nil, nil); resp.StatusCode != http.StatusFound {
		t.Fatalf("GET / after logout: %d", resp.StatusCode)
	}
}

// Остановка единственного агента: отказ «нет агентов» попадает в журнал ошибок (phase=no_agents)
// и в KPI экрана «Ошибки».
func TestE2EAdminErrorsAfterAgentStopped(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	c := newAdminClient(t, e.adminURL)
	c.login()

	e.agents[0].stop(t)
	e.waitFor(10*time.Second, "agent down", func() bool { st, _ := e.srv.reg.Get("local"); return !st.Up })
	if r, _ := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); r.StatusCode != 502 {
		t.Fatalf("getMe without agents: %d", r.StatusCode)
	}

	var items []struct {
		Phase string `json:"phase"`
		Code  int    `json:"code"`
	}
	e.waitFor(5*time.Second, "no_agents error in log", func() bool {
		resp, body := c.do("GET", "/api/v1/errors", nil, nil)
		var page struct {
			Items []struct {
				Phase string `json:"phase"`
				Code  int    `json:"code"`
			} `json:"items"`
		}
		if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &page) != nil {
			return false
		}
		items = page.Items
		return len(items) > 0
	})
	if items[0].Phase != "no_agents" || items[0].Code != 502 {
		t.Fatalf("error event: %+v", items[0])
	}

	resp, body := c.do("GET", "/errors", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "нет агентов") || !strings.Contains(body, "no_agents") {
		t.Fatalf("/errors: %d\n%.800s", resp.StatusCode, body)
	}
	if !regexp.MustCompile(`нет агентов[\s\S]{0,300}?>1<`).MatchString(body) {
		t.Fatalf("KPI «нет агентов» is not 1:\n%.2000s", body)
	}
}
