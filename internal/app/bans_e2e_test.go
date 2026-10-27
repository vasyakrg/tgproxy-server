package app

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Продакшен-сценарий: правило «сеть + ключ», клиент шлёт запросы без ключа. После порога отказов
// клиент банится, и даже запрос с верным ключом получает 403 banned, не доходя до агента.
func TestE2EAutobanThenBannedWithoutAgent(t *testing.T) {
	e := newE2E(t, e2eOpts{
		obs: true,
		mut: func(c *config.ServerConfig) {
			// клиент приходит «извне» через доверенный прокси (loopback банить нельзя)
			c.TrustedProxies = append(c.TrustedProxies, mustPrefix("127.0.0.0/8"))
			c.AccessRules = []config.AccessRule{
				{Name: "lan-key", CIDRs: []netipPrefix{mustPrefix("198.51.100.0/24")}, KeySHA256: keyRule().KeySHA256, KeyHash: keyRule().KeyHash},
				localRule("10.0.0.0/8"),
			}
			c.Ban.Threshold, c.Ban.Window = 5, time.Minute
		},
	})
	xff := func(ip string) http.Header { return http.Header{"X-Forwarded-For": {ip}} }
	attacker := "203.0.113.50" // чужая сеть: no_rule (клиентов из сети правила автобан не трогает)
	for i := range 5 {
		resp, _ := e.do("GET", "/bot"+testToken+"/sendMessage", xff(attacker), nil)
		if resp.StatusCode != 403 {
			t.Fatalf("denial %d: %d", i, resp.StatusCode)
		}
	}
	e.waitFor(5*time.Second, "autoban", func() bool {
		bans, _ := e.srv.st.Bans().ListActive(context.Background(), time.Now())
		return len(bans) == 1
	})
	before := e.tgHits.Load()
	// верный ключ, но IP в бане -> 403 без обращения к агенту
	resp, body := e.do("GET", "/k/"+testKey+"/bot"+testToken+"/getMe", xff(attacker), nil)
	if resp.StatusCode != 403 || !strings.Contains(string(body), "access denied") {
		t.Fatalf("banned request: %d %s", resp.StatusCode, body)
	}
	if e.tgHits.Load() != before {
		t.Fatal("banned request reached Telegram through the agent")
	}
	// сеть и ключ верны -> клиент из разрешённой сети пока проходит
	// (адрес 198.51.100.9 защищён сетью правила и не банится никогда)
	if resp, body := e.do("GET", "/k/"+testKey+"/bot"+testToken+"/getMe", xff("198.51.100.9"), nil); resp.StatusCode != 200 {
		t.Fatalf("legit client: %d %s", resp.StatusCode, body)
	}
	for range 30 { // клиент из сети правила без ключа не банится (защита), но и не проходит
		if resp, _ := e.do("GET", "/bot"+testToken+"/getMe", xff("198.51.100.9"), nil); resp.StatusCode != 403 {
			t.Fatalf("no key: %d", resp.StatusCode)
		}
	}
	e.srv.bans.Wait()
	if bans, _ := e.srv.st.Bans().ListActive(context.Background(), time.Now()); len(bans) != 1 {
		t.Fatalf("protected client banned: %+v", bans)
	}

	// метрика, журнал, аудит, лог
	_, m := e.metrics(metricsBear)
	for _, want := range []string{`tgp_denied_total{reason="no_rule"} 5`, `tgp_denied_total{reason="banned"} 1`, `tgp_denied_total{reason="key_required"} 30`} {
		if !strings.Contains(m, want) {
			t.Fatalf("missing %q in:\n%s", want, grepLines(m, "tgp_denied_total"))
		}
	}
	e.waitFor(5*time.Second, "access errors in journal", func() bool {
		evs, _ := e.srv.st.Errors().List(context.Background(), store.ErrorQuery{Phase: "access", ClientIP: attacker, Limit: 50})
		return len(evs) == 5 && evs[0].Reason == "no_rule"
	})
	au, _ := e.srv.st.Audit().List(context.Background(), store.AuditQuery{})
	var auto bool
	for _, a := range au {
		auto = auto || (a.Action == "ban.auto" && a.Target == attacker+"/32")
	}
	if !auto {
		t.Fatalf("no ban.auto in audit: %+v", au)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "client_ip="+attacker) || !strings.Contains(logs, "reason=no_rule") || strings.Contains(logs, testToken) {
		t.Fatalf("log: client_ip/reason missing or token leaked")
	}
	// снятие бана через менеджер -> клиент снова проходит проверку (правило по-прежнему его не пустит, но не banned)
	bans, _ := e.srv.bans.List(context.Background())
	if _, err := e.srv.bans.Remove(context.Background(), bans[0].ID); err != nil {
		t.Fatal(err)
	}
	if e.srv.bans.Banned(mustAddr(attacker)) {
		t.Fatal("still banned after remove")
	}
}

type netipPrefix = netip.Prefix

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
