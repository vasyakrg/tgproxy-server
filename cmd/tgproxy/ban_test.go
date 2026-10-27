package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBanCLI(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(root, "dev"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"server.yaml", "users.yml"} {
		b, err := os.ReadFile(filepath.Join(devDir(t), f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "dev", f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	if _, err := run(t, "pki", "dev-init", "--out", "dev/tls"); err != nil {
		t.Fatal(err)
	}
	with := func(a ...string) []string { return append(a, "-c", "dev/server.yaml") }

	out, err := run(t, with("ban", "add", "--ip", "198.51.100.7", "--duration", "24h", "--comment", "scanner")...)
	if err != nil || !strings.Contains(out, "забанен 198.51.100.7") {
		t.Fatalf("add: %v %q", err, out)
	}
	if _, err := run(t, with("ban", "add", "--ip", "2001:db8:1:2::9", "--permanent")...); err != nil {
		t.Fatal(err)
	}
	out, err = run(t, with("ban", "list")...)
	if err != nil || !strings.Contains(out, "198.51.100.7") || !strings.Contains(out, "2001:db8:1:2::/64") ||
		!strings.Contains(out, "permanent") || !strings.Contains(out, "scanner") {
		t.Fatalf("list: %v %q", err, out)
	}
	for _, bad := range [][]string{
		{"ban", "add", "--ip", "bogus", "--duration", "1h"},
		{"ban", "add", "--ip", "198.51.100.8"},                 // нет срока
		{"ban", "add", "--ip", "127.0.0.1", "--permanent"},     // защита от самоблокировки
		{"ban", "add", "--ip", "10.1.2.3", "--duration", "1h"}, // приватный
		{"ban", "delete"}, // нужен --id или --ip
		{"ban", "delete", "--id", "1", "--ip", "198.51.100.7"}, // оба сразу
		{"ban", "delete", "--ip", "198.51.100.99"},             // нет такого
	} {
		if _, err := run(t, with(bad...)...); err == nil {
			t.Fatalf("%v must fail", bad)
		}
	}
	if out, err = run(t, with("ban", "delete", "--ip", "198.51.100.7")...); err != nil || !strings.Contains(out, "снят") {
		t.Fatalf("delete: %v %q", err, out)
	}
	if out, _ = run(t, with("ban", "list")...); strings.Contains(out, "198.51.100.7") {
		t.Fatalf("ban not deleted: %q", out)
	}
}
