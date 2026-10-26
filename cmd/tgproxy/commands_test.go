package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// devDir — корень репозитория: dev-конфиги используют пути ./dev/...
func devDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "dev")
}

func TestPKIDevInitThenConfigValidateDev(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// конфиги dev/*.yaml ссылаются на ./dev/tls/*: проверяем их в копии дерева
	for _, f := range []string{"server.yaml", "agent.yaml", "users.yml"} {
		b, err := os.ReadFile(filepath.Join(devDir(t), f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "dev"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "dev", f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)

	out, err := run(t, "pki", "dev-init", "--out", "dev/tls", "--agent", "local")
	if err != nil || !strings.Contains(out, "создана") {
		t.Fatalf("dev-init: %v %q", err, out)
	}
	// повтор идемпотентен
	out, err = run(t, "pki", "dev-init", "--out", "dev/tls")
	if err != nil || !strings.Contains(out, "уже существует") {
		t.Fatalf("dev-init repeat: %v %q", err, out)
	}
	for _, c := range [][]string{
		{"config", "validate", "--mode", "server", "-c", "dev/server.yaml"},
		{"config", "validate", "--mode", "agent", "-c", "dev/agent.yaml"},
	} {
		out, err := run(t, c...)
		if err != nil || !strings.Contains(out, "OK") {
			t.Fatalf("%v: %v %q", c, err, out)
		}
	}
}

func TestConfigValidateBroken(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("listen: [not a map\nunknown_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"server", "agent"} {
		if _, err := run(t, "config", "validate", "--mode", mode, "-c", bad); err == nil {
			t.Errorf("%s: expected error", mode)
		}
	}
	if _, err := run(t, "config", "validate", "--mode", "server", "-c", filepath.Join(t.TempDir(), "none.yaml")); err == nil {
		t.Error("missing file: expected error")
	}
	if _, err := run(t, "config", "validate", "--mode", "bogus", "-c", bad); err == nil {
		t.Error("bad mode: expected error")
	}
}

func TestServerAgentRequireConfig(t *testing.T) {
	for _, name := range []string{"server", "agent"} {
		if _, err := run(t, name); err == nil {
			t.Errorf("%s without -c: expected error", name)
		}
	}
}

func TestAgentTelegramURLFlagHidden(t *testing.T) {
	out, err := run(t, "agent", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "telegram-api-url") {
		t.Fatalf("hidden flag leaked into help: %s", out)
	}
}

func TestAccessAndAgentsCLI(t *testing.T) {
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
	cfg := []string{"-c", "dev/server.yaml"}
	with := func(a ...string) []string { return append(a, cfg...) }

	out, err := run(t, with("access", "add", "--name", "ext", "--with-key", "--rps", "2", "--cidr", "10.0.0.0/8")...)
	if err != nil || !strings.Contains(out, "tgp_") || !strings.Contains(out, "/k/tgp_") {
		t.Fatalf("add: %v %q", err, out)
	}
	key := out[strings.Index(out, "tgp_"):]
	key = key[:strings.IndexAny(key, "\n/ ")]

	out, err = run(t, with("access", "list")...)
	if err != nil || !strings.Contains(out, "ext") || !strings.Contains(out, "10.0.0.0/8") {
		t.Fatalf("list: %v %q", err, out)
	}
	if strings.Contains(out, key) {
		t.Fatalf("list leaks the full key: %q", out)
	}
	if _, err := run(t, with("access", "add", "--name", "bad")...); err == nil {
		t.Fatal("rule without cidr and key must fail")
	}
	if _, err := run(t, with("access", "add", "--name", "ext", "--cidr", "10.0.0.0/8")...); err == nil {
		t.Fatal("duplicate name must fail")
	}
	if _, err := run(t, with("access", "add", "--name", "x", "--cidr", "bogus")...); err == nil {
		t.Fatal("bad cidr must fail")
	}
	if _, err := run(t, with("access", "delete")...); err == nil {
		t.Fatal("delete without --name/--id must fail")
	}
	if _, err := run(t, with("access", "delete", "--name", "ext")...); err != nil {
		t.Fatal(err)
	}
	if out, _ = run(t, with("access", "list")...); strings.Contains(out, "ext") {
		t.Fatalf("rule not deleted: %q", out)
	}

	// агенты из БД: пусты, пока сервер ни разу не стартовал (seed делает сервер)
	if out, err = run(t, with("agents", "list")...); err != nil || !strings.Contains(out, "ID") {
		t.Fatalf("agents list: %v %q", err, out)
	}
}
