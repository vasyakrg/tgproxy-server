package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

func writeServerCfg(t *testing.T, dir string, withKEK bool) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(devDir(t), "server.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	s = strings.ReplaceAll(s, "./dev/data/kek", filepath.Join(dir, "kek"))
	s = strings.ReplaceAll(s, "./dev/data/tgproxy.db", filepath.Join(dir, "tgproxy.db"))
	s = strings.ReplaceAll(s, "./dev/tls", dir)
	s = strings.ReplaceAll(s, "./dev/users.yml", filepath.Join(dir, "users.yml"))
	if err := os.WriteFile(filepath.Join(dir, "users.yml"), []byte("users: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if withKEK {
		if err := pki.GenerateKEK(filepath.Join(dir, "kek")); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPKIInitAndFingerprint(t *testing.T) {
	dir := t.TempDir()
	cfg := writeServerCfg(t, dir, true)
	if out, err := run(t, "pki", "fingerprint", "-c", cfg); err == nil || !strings.Contains(err.Error(), "не инициализирован") {
		t.Fatalf("fingerprint before init: %v %q", err, out)
	}
	out, err := run(t, "pki", "init", "-c", cfg)
	if err != nil || !strings.Contains(out, "CA создан") {
		t.Fatalf("init: %v %q", err, out)
	}
	fp := regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}`).FindString(out)
	if fp == "" {
		t.Fatalf("no fingerprint: %q", out)
	}
	out, err = run(t, "pki", "init", "-c", cfg)
	if err != nil || !strings.Contains(out, "уже существует") || !strings.Contains(out, fp) {
		t.Fatalf("init repeat: %v %q", err, out)
	}
	out, err = run(t, "pki", "fingerprint", "-c", cfg)
	if err != nil || strings.TrimSpace(out) != fp {
		t.Fatalf("fingerprint: %v %q want %s", err, out, fp)
	}
}

func TestPKIInitErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := writeServerCfg(t, dir, false)
	if _, err := run(t, "pki", "init", "-c", cfg); err == nil || !strings.Contains(err.Error(), "KEK") {
		t.Fatalf("missing KEK: %v", err)
	}
	if _, err := run(t, "pki", "init", "-c", filepath.Join(dir, "none.yaml")); err == nil {
		t.Fatal("missing config accepted")
	}
	// KEK с правами 0644 отвергается
	kek := filepath.Join(dir, "kek")
	if err := pki.GenerateKEK(kek); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(kek, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "pki", "init", "-c", cfg); err == nil {
		t.Fatal("0644 KEK accepted")
	}
	// другой KEK при существующем CA → ошибка расшифровки
	if err := os.Remove(kek); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateKEK(kek); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "pki", "init", "-c", cfg); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(kek)
	if err := pki.GenerateKEK(kek); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "pki", "fingerprint", "-c", cfg); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("wrong KEK: %v", err)
	}
}
