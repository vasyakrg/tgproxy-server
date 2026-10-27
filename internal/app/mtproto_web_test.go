package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/mtproto/probe"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
)

var jsonHdr = map[string]string{"Content-Type": "application/json"}

// keyFromLink достаёт 16-байтный ключ из tg://proxy?...&secret=ee<key><domain>.
func keyFromLink(t *testing.T, link string) (key [16]byte) {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	sec := u.Query().Get("secret")
	if !strings.HasPrefix(sec, "ee") || len(sec) < 2+32 {
		t.Fatalf("secret в ссылке: %q", sec)
	}
	b, err := hex.DecodeString(sec[2:34])
	if err != nil {
		t.Fatal(err)
	}
	copy(key[:], b)
	return key
}

func (c *adminClient) jsonBody(method, path, body string) (adminResp, string) {
	return c.do(method, path, jsonHdr, strings.NewReader(body))
}

// mtAdminClient — клиент админки стенда MTProto: с TLS входа админка отдаётся по https.
func mtAdminClient(t *testing.T, m *mtEnv) *adminClient {
	t.Helper()
	c := newAdminClient(t, strings.Replace(m.adminURL, "http://", "https://", 1))
	c.hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // тестовый самоподписанный сертификат
	t.Cleanup(c.hc.CloseIdleConnections)
	return c
}

func TestE2EMTProtoWebAPIAndUI(t *testing.T) {
	m := newMTEnv(t, mtOpts{})
	c := mtAdminClient(t, m)

	// без сессии — 401
	if r, b := c.do("GET", "/api/v1/mtproto/secrets", nil, nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("secrets без сессии: %d %s", r.StatusCode, b)
	}
	if r, _ := c.do("GET", "/api/v1/mtproto/stats", nil, nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stats без сессии: %d", r.StatusCode)
	}
	c.login()

	// создание: ссылка возвращается один раз
	r, body := c.jsonBody("POST", "/api/v1/mtproto/secrets", `{"name":"main"}`)
	if r.StatusCode >= 300 {
		t.Fatalf("create: %d %s", r.StatusCode, body)
	}
	var created struct {
		ID   int64 `json:"id"`
		Link *struct {
			TG    string `json:"tg"`
			HTTPS string `json:"https"`
		} `json:"link"`
		LinkError string `json:"link_error"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	if created.Link == nil || !strings.HasPrefix(created.Link.TG, "tg://proxy?") {
		t.Fatalf("ссылка не вернулась: %s", body)
	}
	key := keyFromLink(t, created.Link.TG)
	m.probeOK(key) // секрет из API работает на живом MTProto

	// ссылка без свежего TOTP — 401 totp_required, после подтверждения — ссылка
	linkPath := "/api/v1/mtproto/secrets/" + strconv.FormatInt(created.ID, 10) + "/link"
	// вход только что подтвердил TOTP; «состариваем» отметку (ключ: totp:fresh:sha256(токен))
	sum := sha256.Sum256([]byte(c.cookie.Value))
	if err := m.srv.st.RateState().Delete(context.Background(), "totp:fresh:"+hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if r, b := c.do("GET", linkPath, nil, nil); r.StatusCode != http.StatusUnauthorized || !strings.Contains(b, "totp_required") {
		t.Fatalf("link без свежего TOTP: %d %s", r.StatusCode, b)
	}
	if r, b := c.jsonBody("POST", "/api/v1/auth/totp/confirm", `{"code":"000000"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("totp confirm: %d %s", r.StatusCode, b)
	}
	r, body = c.do("GET", linkPath, nil, nil)
	if r.StatusCode != http.StatusOK || !strings.Contains(body, "tg://proxy?") {
		t.Fatalf("link после confirm: %d %s", r.StatusCode, body)
	}

	// список: ключа нет, есть счётчик соединений
	r, body = c.do("GET", "/api/v1/mtproto/secrets", nil, nil)
	if r.StatusCode != http.StatusOK || !strings.Contains(body, `"main"`) || strings.Contains(body, hex.EncodeToString(key[:])) {
		t.Fatalf("list: %d %s", r.StatusCode, body)
	}

	// вкладка рендерится
	r, body = c.do("GET", "/mtproto", nil, nil)
	if r.StatusCode != http.StatusOK || !strings.Contains(body, "main") {
		t.Fatalf("/mtproto: %d", r.StatusCode)
	}
	if strings.Contains(body, hex.EncodeToString(key[:])) {
		t.Fatal("ключ секрета в HTML списка")
	}

	// матрица: агент стенда с DC 2
	m.waitFor(15*time.Second, "агент local в матрице", func() bool {
		_, b := c.do("GET", "/api/v1/mtproto/stats", nil, nil)
		var st api.MTProtoStats
		if json.Unmarshal([]byte(b), &st) != nil || !st.Enabled {
			return false
		}
		for _, a := range st.Agents {
			if a.AgentID == "local" && a.Capable {
				for _, d := range a.DC {
					if d.DC == 2 && d.Up {
						return st.Totals.SecretsActive == 1
					}
				}
			}
		}
		return false
	})

	// отзыв через API рвёт живое соединение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := probe.Dial(ctx, m.mtAddr, key, mtDomain, probe.DefaultDC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Exchange(5 * time.Second); err != nil {
		t.Fatalf("обмен до отзыва: %v", err)
	}
	m.waitFor(5*time.Second, "активное соединение в API", func() bool {
		_, b := c.do("GET", "/api/v1/mtproto/secrets", nil, nil)
		return strings.Contains(b, `"active_conns":1`)
	})
	dropped := make(chan time.Time, 1)
	go func() {
		for {
			if err := conn.Exchange(5 * time.Second); err != nil {
				dropped <- time.Now()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	revokedAt := time.Now()
	if r, b := c.do("DELETE", "/api/v1/mtproto/secrets/"+strconv.FormatInt(created.ID, 10)+"?confirm=yes", nil, nil); r.StatusCode >= 300 {
		t.Fatalf("revoke: %d %s", r.StatusCode, b)
	}
	select {
	case at := <-dropped:
		if d := at.Sub(revokedAt); d > 2*time.Second+1500*time.Millisecond {
			t.Fatalf("соединение разорвано через %s, want ≤ 2s + poll", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("соединение не разорвано после отзыва через API")
	}
}

func TestE2EMTProtoWebDisabled(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	c := newAdminClient(t, e.adminURL)
	c.login()

	// подготовка секретов работает при mtproto.enabled=false
	r, body := c.jsonBody("POST", "/api/v1/mtproto/secrets", `{"name":"spare"}`)
	if r.StatusCode >= 300 || !strings.Contains(body, `"disabled":true`) {
		t.Fatalf("create при выключенном MTProto: %d %s", r.StatusCode, body)
	}
	if r, body = c.do("GET", "/mtproto", nil, nil); r.StatusCode != http.StatusOK || !strings.Contains(body, "spare") {
		t.Fatalf("/mtproto: %d", r.StatusCode)
	}
	r, body = c.do("GET", "/api/v1/mtproto/stats", nil, nil)
	if r.StatusCode != http.StatusOK || !strings.Contains(body, `"enabled":false`) || !strings.Contains(body, `"agents":[]`) {
		t.Fatalf("stats: %d %s", r.StatusCode, body)
	}
	if r, _ = c.do("GET", "/", nil, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("обзор: %d", r.StatusCode)
	}
}
