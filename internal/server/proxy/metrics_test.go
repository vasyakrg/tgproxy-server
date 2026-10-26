package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/metrics"
	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
)

func TestRequestMetrics(t *testing.T) {
	reg, m := metrics.NewServerRegistry()
	top := metrics.NewTopBots(0)
	e := setupOpts(t, nil, WithRecorder(m), WithBots(top))
	for range 3 {
		if w := e.do("GET", "/bot"+tok+"/getMe", "10.1.2.3:555", nil, nil); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	// отказ в доступе не считается запросом бота
	e.do("GET", "/bot"+tok+"/getMe", "8.8.8.8:1", nil, nil)
	const want = `
# HELP tgp_requests_total Proxied Bot API requests.
# TYPE tgp_requests_total counter
tgp_requests_total{code="200",method="getme",rule="lan"} 3
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "tgp_requests_total"); err != nil {
		t.Fatal(err)
	}
	if st := top.Top(5); len(st) != 1 || st[0].BotID != 123456 || st[0].Requests != 3 {
		t.Fatalf("%+v", st)
	}
}

func TestWebhookBlockedMetric(t *testing.T) {
	reg, m := metrics.NewServerRegistry()
	e := setupOpts(t, func(c *config.ServerConfig) { c.WebhookPolicy = config.WebhookDeny }, WithRecorder(m))
	if w := e.do("GET", "/bot"+tok+"/setWebhook?url=https://x", "10.1.2.3:1", nil, nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	const want = `
# HELP tgp_webhook_blocked_total Blocked setWebhook requests.
# TYPE tgp_webhook_blocked_total counter
tgp_webhook_blocked_total 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "tgp_webhook_blocked_total"); err != nil {
		t.Fatal(err)
	}
}

func TestInternalRequestNotCounted(t *testing.T) {
	reg, m := metrics.NewServerRegistry()
	top := metrics.NewTopBots(0)
	e := setupOpts(t, nil, WithRecorder(m), WithBots(top))
	r := httptest.NewRequestWithContext(notify.InternalContext(context.Background()), http.MethodGet, "/bot"+tok+"/getMe", http.NoBody)
	r.RemoteAddr = "10.1.2.3:1"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if n, _ := testutil.GatherAndCount(reg, "tgp_requests_total"); n != 0 {
		t.Fatal("internal request counted")
	}
	if top.Len() != 0 {
		t.Fatal("internal request in top bots")
	}
}
