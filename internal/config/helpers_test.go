package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// baseServer — минимально валидный серверный конфиг.
const baseServer = `
listen:
  proxy: "127.0.0.1:8080"
  metrics: "127.0.0.1:9090"
tls:
  mode: "off"
`

const baseAgent = `
listen:
  metrics: "127.0.0.1:9443"
tls:
  cert_file: a.crt
  key_file: a.key
  ca_file: ca.crt
`

func parseServer(t *testing.T, yaml string, env ...string) (*ServerConfig, error) {
	t.Helper()
	return parse[ServerConfig]([]byte(yaml), "test.yaml", env)
}

func parseAgent(t *testing.T, yaml string, env ...string) (*AgentConfig, error) {
	t.Helper()
	return parse[AgentConfig]([]byte(yaml), "test.yaml", env)
}

func mustServer(t *testing.T, yaml string, env ...string) *ServerConfig {
	t.Helper()
	c, err := parseServer(t, yaml, env...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return c
}

func wantErr(t *testing.T, err error, substrs ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substrs)
	}
	for _, s := range substrs {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q does not contain %q", err, s)
		}
	}
}

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}
