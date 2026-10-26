package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/metrics"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
)

func (e *e2e) metrics(bearer string) (int, string) {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, e.metricsURL+"/metrics", http.NoBody)
	if err != nil {
		e.t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *e2e) waitMsg(what string) tgMessage {
	e.t.Helper()
	select {
	case m := <-e.msgs:
		return m
	case <-time.After(15 * time.Second):
		e.t.Fatalf("timeout waiting for telegram message: %s", what)
	}
	return tgMessage{}
}

func TestE2EMetricsHistoryAndAlerts(t *testing.T) {
	e := newE2E(t, e2eOpts{agents: 2, obs: true})
	const n = 6
	for i := 0; i < n; i++ {
		if r, b := e.do("GET", "/bot"+testToken+"/getMe", nil, nil); r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, b)
		}
	}

	// /metrics закрыт bearer-ом
	if code, _ := e.metrics(""); code != http.StatusUnauthorized {
		t.Fatalf("no bearer: %d", code)
	}
	code, body := e.metrics(metricsBear)
	if code != 200 {
		t.Fatalf("metrics: %d", code)
	}
	if want := `tgp_requests_total{code="200",method="getme",rule="net"} 6`; !strings.Contains(body, want) {
		t.Fatalf("missing %q in:\n%s", want, grepLines(body, "tgp_requests_total"))
	}
	if strings.Contains(body, "123456") || strings.Contains(body, testToken) {
		t.Fatal("bot_id leaked into metrics")
	}
	if !strings.Contains(body, `tgp_agent_up{agent="local",mode="dial"} 1`) ||
		!strings.Contains(body, `tgp_agent_up{agent="a2",mode="dial"} 1`) {
		t.Fatalf("agent_up:\n%s", grepLines(body, "tgp_agent_up"))
	}

	// тик сэмплера -> точка в истории
	e.ticks <- time.Now()
	e.waitFor(5*time.Second, "history point", func() bool {
		s, err := e.srv.obs.hq.Timeseries(context.Background(), history.Range1h, "", time.Time{})
		if err != nil {
			return false
		}
		var ok float64
		for _, p := range s.Points {
			ok += p.OKRPS
		}
		return ok > 0
	})

	// агент a2 остановлен -> agent_down приходит админу через оставшийся агент
	e.agents[1].stop(t)
	m := e.waitMsg("agent_down")
	if m.ChatID != obsChatID || !strings.Contains(m.Text, "a2") || !strings.Contains(m.Text, "недоступен") {
		t.Fatalf("%+v", m)
	}
	if strings.Contains(m.Text, notifyToken) {
		t.Fatal("token in alert text")
	}
	_, body = e.metrics(metricsBear)
	if want := `tgp_requests_total{code="200",method="getme",rule="net"} 6`; !strings.Contains(body, want) {
		t.Fatalf("internal request counted:\n%s", grepLines(body, "tgp_requests_total"))
	}
	if strings.Contains(body, "sendmessage") {
		t.Fatalf("internal sendMessage in metrics:\n%s", grepLines(body, "sendmessage"))
	}
	var attempts float64
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "tgp_upstream_attempts_total{") {
			var v float64
			if i := strings.LastIndexByte(l, ' '); i > 0 {
				v = parseFloat(t, l[i+1:])
			}
			attempts += v
		}
	}
	if attempts != n {
		t.Fatalf("internal attempts counted: %v\n%s", attempts, grepLines(body, "tgp_upstream_attempts_total"))
	}

	// восстановление -> resolved
	e.agents[1] = e.startAgent("a2", e.agents[1].addr)
	m = e.waitMsg("resolved")
	if m.ChatID != obsChatID || !strings.Contains(m.Text, "снова доступен") {
		t.Fatalf("%+v", m)
	}
}

func TestMetricsHandlerBearerPolicy(t *testing.T) {
	reg, _ := metrics.NewServerRegistry()
	for _, addr := range []string{"0.0.0.0:9090", ":9090", "10.0.0.5:9090", "[::]:9090"} {
		if _, err := newMetricsHandler(reg, "", addr); !errors.Is(err, metrics.ErrBearerRequired) {
			t.Errorf("%s without bearer: %v", addr, err)
		}
		if _, err := newMetricsHandler(reg, "secret", addr); err != nil {
			t.Errorf("%s with bearer: %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:9090", "[::1]:9090", "localhost:9090"} {
		if _, err := newMetricsHandler(reg, "", addr); err != nil {
			t.Errorf("%s loopback without bearer: %v", addr, err)
		}
	}
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func parseFloat(t *testing.T, s string) float64 {
	t.Helper()
	var v float64
	if _, err := fmt.Sscanf(s, "%g", &v); err != nil {
		t.Fatal(err)
	}
	return v
}
