package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPKIDevAgentsIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := writeServerCfg(t, dir, true)
	if _, err := run(t, "pki", "init", "-c", cfg); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "tls")
	args := []string{"pki", "dev-agents", "-c", cfg, "--out", out, "--agent", "local", "--agent", "local2"}
	if o, err := run(t, args...); err != nil || strings.Count(o, "выпущен") != 2 {
		t.Fatalf("first run: %v %q", err, o)
	}
	for _, f := range []string{"ca.crt", "agent-local.crt", "agent-local.key", "agent-local2.crt", "agent.crt", "agent.key"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if st, _ := os.Stat(filepath.Join(out, "agent-local.key")); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", st.Mode().Perm())
	}
	if o, err := run(t, args...); err != nil || strings.Count(o, "пропуск") != 2 {
		t.Fatalf("second run: %v %q", err, o)
	}
}

func TestAgentsEnrollToken(t *testing.T) {
	dir := t.TempDir()
	cfg := writeServerCfg(t, dir, true)
	if _, err := run(t, "agents", "enroll-token", "-c", cfg, "--name", "nat"); err == nil {
		t.Fatal("token issued without CA")
	}
	out, err := run(t, "pki", "init", "-c", cfg)
	if err != nil {
		t.Fatal(err)
	}
	fp := regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}`).FindString(out)
	out, err = run(t, "agents", "enroll-token", "-c", cfg, "--name", "nat")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"printf %s '", "| sudo tgproxy agent enroll --token-stdin --server https://host.docker.internal:8444", "--ca-fingerprint " + fp} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}
