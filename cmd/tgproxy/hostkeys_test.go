package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func TestHostKeysCLI(t *testing.T) {
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
	cfgPath := "dev/server.yaml"
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	seed, err := app.OpenSQLite(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.HostKeys().Put(ctx, store.HostKey{Host: "10.0.0.5:22", Algo: "ssh-ed25519", Fingerprint: "SHA256:abc", PublicKey: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	_ = seed.Close()

	out, err := run(t, "hostkeys", "list", "-c", cfgPath)
	if err != nil || !strings.Contains(out, "10.0.0.5:22") || !strings.Contains(out, "ssh-ed25519") || !strings.Contains(out, "SHA256:abc") {
		t.Fatalf("list: %v %q", err, out)
	}

	// неизвестный host:port
	if _, err := run(t, "hostkeys", "forget", "1.2.3.4:22", "--yes", "-c", cfgPath); err == nil {
		t.Fatal("unknown host must fail")
	}
	// отказ без подтверждения
	for _, in := range []string{"", "n\n", "\n"} {
		out, err := runIn(t, in, "hostkeys", "forget", "10.0.0.5:22", "-c", cfgPath)
		if err == nil || !strings.Contains(out, "SHA256:abc") {
			t.Fatalf("decline %q: %v %q", in, err, out)
		}
	}
	if out, _ := run(t, "hostkeys", "list", "-c", cfgPath); !strings.Contains(out, "10.0.0.5:22") {
		t.Fatalf("pin removed without confirmation: %q", out)
	}

	// подтверждение в диалоге
	t.Setenv("USER", "tester")
	out, err = runIn(t, "y\n", "hostkeys", "forget", "10.0.0.5:22", "-c", cfgPath)
	if err != nil || !strings.Contains(out, "подтвердить заново") {
		t.Fatalf("forget: %v %q", err, out)
	}
	out, _ = run(t, "hostkeys", "list", "-c", cfgPath)
	if strings.Contains(out, "10.0.0.5:22") {
		t.Fatalf("pin still listed: %q", out)
	}

	// аудит
	st, err := app.OpenSQLite(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	entries, err := st.Audit().List(ctx, store.AuditQuery{Limit: 10})
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit: %v %+v", err, entries)
	}
	if e := entries[0]; e.Action != auth.AuditHostKeyForget || e.Actor != "cli:tester" || e.Target != "10.0.0.5:22" {
		t.Fatalf("audit entry %+v", e)
	}

	// --yes
	_ = st.HostKeys().Put(ctx, store.HostKey{Host: "h:22", Fingerprint: "SHA256:x", PublicKey: []byte{1}})
	if _, err := run(t, "hostkeys", "forget", "h:22", "--yes", "-c", cfgPath); err != nil {
		t.Fatalf("--yes: %v", err)
	}
}
