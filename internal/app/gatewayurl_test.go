package app

import (
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

func TestGatewayURLPriority(t *testing.T) {
	cfg := config.DefaultServer()
	cfg.Listen.AgentGateway = "127.0.0.1:8444"
	cfg.Server.PublicBaseURL = "https://tg.example.com"
	if u, ok := gatewayURL(cfg, ""); !ok || u != "https://tg.example.com:8444" {
		t.Fatalf("из public_base_url: %q %v", u, ok)
	}
	cfg.Server.AgentGatewayURL = "https://host.docker.internal:8444/"
	if u, ok := gatewayURL(cfg, ""); !ok || u != "https://host.docker.internal:8444" {
		t.Fatalf("agent_gateway_url: %q %v", u, ok)
	}
	if u, _ := gatewayURL(cfg, "https://override:1"); u != "https://override:1" {
		t.Fatalf("override: %q", u)
	}
}

func TestAgentGatewayURLValidation(t *testing.T) {
	for raw, ok := range map[string]bool{
		"": true, "https://host.docker.internal:8444": true, "http://x:1": false, "https://x/path": false, "https://u:p@x": false, "x": false,
	} {
		cfg := config.DefaultServer()
		cfg.Server.AgentGatewayURL = raw
		err := config.ValidateServer(cfg)
		if got := err == nil || !strings.Contains(err.Error(), "agent_gateway_url"); got != ok {
			t.Errorf("%q: err=%v, want ok=%v", raw, err, ok)
		}
	}
}
