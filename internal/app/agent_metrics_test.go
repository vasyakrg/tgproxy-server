package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/metrics"
)

func TestAgentMetricsListener(t *testing.T) {
	reg, m := metrics.NewAgentRegistry()
	rec := agentRecorder{m}
	rec.Request("2xx", "")
	rec.Request("proxy_err", "dial")
	rec.UpstreamBytes("up", 7)
	rec.DialError("refused")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ms, err := startAgentMetrics(context.Background(), "127.0.0.1:0", "s3cret", reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.stop(context.Background()) })

	get := func(auth string) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+ms.addr+"/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get(""); code != http.StatusUnauthorized {
		t.Fatalf("no bearer: %d", code)
	}
	if code, _ := get("Bearer wrong"); code != http.StatusUnauthorized {
		t.Fatalf("bad bearer: %d", code)
	}
	code, body := get("Bearer s3cret")
	if code != http.StatusOK {
		t.Fatalf("with bearer: %d", code)
	}
	for _, want := range []string{
		`tgp_agent_requests_total{code_class="2xx",error_phase="none"} 1`,
		`tgp_agent_requests_total{code_class="proxy_err",error_phase="dial"} 1`,
		`tgp_agent_upstream_bytes_total{direction="up"} 7`,
		`tgp_agent_dial_errors_total{kind="refused"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestAgentMetricsBearerRequired(t *testing.T) {
	reg, _ := metrics.NewAgentRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, addr := range []string{":0", "0.0.0.0:0"} {
		if _, err := startAgentMetrics(context.Background(), addr, "", reg, logger); !errors.Is(err, metrics.ErrBearerRequired) {
			t.Fatalf("%s: err %v", addr, err)
		}
	}
	ms, err := startAgentMetrics(context.Background(), "127.0.0.1:0", "", reg, logger)
	if err != nil {
		t.Fatalf("loopback without bearer: %v", err)
	}
	ms.stop(context.Background())
	if _, err := startAgentMetrics(context.Background(), "bad addr", "x", reg, logger); err == nil {
		t.Fatal("want listen error")
	}
}

func TestAgentMetricsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:1": true, "[::1]:1": true, "localhost:1": true,
		":1": false, "0.0.0.0:1": false, "10.0.0.1:1": false, "garbage": false,
	} {
		if got := agentMetricsLoopback(addr); got != want {
			t.Errorf("%s: got %v", addr, got)
		}
	}
}
