package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
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

// writeSignedPackage кладёт в downloads подписанный релиз version (amd64) и прописывает в конфиге
// кэш и ключ проверки; buildinfo.Version временно подменяется.
func writeSignedPackage(t *testing.T, dir, cfgPath, version string) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vd := filepath.Join(dir, "packages", version)
	if err := os.MkdirAll(vd, 0o750); err != nil {
		t.Fatal(err)
	}
	deb := []byte("DEB-" + version)
	name := "tgproxy_" + version + "_amd64.deb"
	h := sha256.Sum256(deb)
	sums := []byte(hex.EncodeToString(h[:]) + "  " + name + "\n")
	r := minisign.NewReader(bytes.NewReader(sums))
	_, _ = io.Copy(io.Discard, r)
	sig := r.SignWithComments(priv, "timestamp:1 file:checksums.txt", "t")
	for n, b := range map[string][]byte{name: deb, "checksums.txt": sums, "checksums.txt.minisig": sig} {
		if err := os.WriteFile(filepath.Join(vd, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pt := []byte(pub.String())
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Replace(string(cfg), "downloads_dir: ./dev/data/packages",
		"downloads_dir: "+filepath.Join(dir, "packages")+"\n  pubkeys: [\""+string(pt)+"\"]", 1)
	if out == string(cfg) {
		t.Fatal("downloads_dir not found in dev config")
	}
	if err := os.WriteFile(cfgPath, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	old := buildinfo.Version
	buildinfo.Version = version
	t.Cleanup(func() { buildinfo.Version = old })
}

func TestAgentsEnrollToken(t *testing.T) {
	dir := t.TempDir()
	cfg := writeServerCfg(t, dir, true)
	writeSignedPackage(t, dir, cfg, "1.2.3")
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
	for _, want := range []string{
		"printf %s '", "| sudo tgproxy agent enroll --token-stdin --server https://host.docker.internal:8444", "--ca-fingerprint " + fp,
		"--cacert", "/enroll/package/tgproxy_1.2.3_amd64.deb", "sha256sum -c -", "apt-get install -y", "Если tgproxy уже установлен",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	// только короткая команда
	out, err = run(t, "agents", "enroll-token", "-c", cfg, "--name", "nat2", "--installed")
	if err != nil || strings.Contains(out, "curl") || !strings.Contains(out, "sudo tgproxy agent enroll") {
		t.Fatalf("--installed: %v %q", err, out)
	}
	// нет пакета в кэше → понятная ошибка, токен не выдан
	buildinfo.Version = "9.9.9"
	_, err = run(t, "agents", "enroll-token", "-c", cfg, "--name", "nat3")
	if err == nil || !strings.Contains(err.Error(), "загрузите релиз 9.9.9 в Система → Обновления") {
		t.Fatalf("missing package: %v", err)
	}
}

func TestAgentsEnrollTokenForExistingAgent(t *testing.T) {
	dir := t.TempDir()
	cfg := writeServerCfg(t, dir, true)
	writeSignedPackage(t, dir, cfg, "1.2.3")
	if _, err := run(t, "pki", "init", "-c", cfg); err != nil {
		t.Fatal(err)
	}
	// агента нет → понятная ошибка, токен не выдан
	if _, err := run(t, "agents", "enroll-token", "-c", cfg, "--agent", "ghost", "--installed"); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("missing agent: %v", err)
	}
	if out, _ := run(t, "agents", "enroll-token", "-c", cfg, "--list"); !strings.Contains(out, "ожидающих токенов нет") {
		t.Fatalf("token issued for missing agent: %q", out)
	}
	sc, err := config.LoadServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st, err := app.OpenSQLite(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Agents().Create(context.Background(), store.Agent{ID: "home", Name: "Home", Mode: store.ModeReverse, Weight: 42}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	out, err := run(t, "agents", "enroll-token", "-c", cfg, "--agent", "home", "--installed")
	if err != nil || !strings.Contains(out, "sudo tgproxy agent enroll") || strings.Contains(out, "curl") {
		t.Fatalf("--agent --installed: %v %q", err, out)
	}
	out, err = run(t, "agents", "enroll-token", "-c", cfg, "--agent", "home")
	if err != nil || !strings.Contains(out, "apt-get install") {
		t.Fatalf("--agent: %v %q", err, out)
	}
	if out, err = run(t, "agents", "enroll-token", "-c", cfg, "--list"); err != nil || strings.Count(out, "home") != 2 || !strings.Contains(out, "42") {
		t.Fatalf("list: %v %q", err, out)
	}
	for _, bad := range [][]string{
		{"--agent", "home", "--name", "x"},
		{"--agent", "home", "--weight", "5"},
		{"--agent", "home", "--list"},
	} {
		if _, err := run(t, append([]string{"agents", "enroll-token", "-c", cfg}, bad...)...); err == nil {
			t.Fatalf("%v must fail", bad)
		}
	}
}

func TestAgentsEnrollTokenListRevoke(t *testing.T) {
	dir := t.TempDir()
	cfg := writeServerCfg(t, dir, true)
	writeSignedPackage(t, dir, cfg, "1.2.3")
	if _, err := run(t, "pki", "init", "-c", cfg); err != nil {
		t.Fatal(err)
	}
	if out, err := run(t, "agents", "enroll-token", "-c", cfg, "--list"); err != nil || !strings.Contains(out, "ожидающих токенов нет") {
		t.Fatalf("empty list: %v %q", err, out)
	}
	var tokens []string
	for _, n := range []string{"nat-a", "nat-b", "nat-b"} {
		out, err := run(t, "agents", "enroll-token", "-c", cfg, "--name", n, "--installed")
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, regexp.MustCompile(`printf %s '([^']+)'`).FindStringSubmatch(out)[1])
	}
	out, err := run(t, "agents", "enroll-token", "-c", cfg, "--list")
	if err != nil || strings.Count(out, "nat-") != 3 || !strings.Contains(out, "cli") {
		t.Fatalf("list: %v %q", err, out)
	}
	for _, tok := range tokens {
		if strings.Contains(out, tok) {
			t.Fatalf("list leaks token: %q", out)
		}
	}
	ids := regexp.MustCompile(`(?m)^([0-9a-f]{16})\s+nat-([ab])`).FindAllStringSubmatch(out, -1)
	if len(ids) != 3 {
		t.Fatalf("ids: %q", out)
	}
	for _, bad := range [][]string{
		{"--revoke", "nope"},                   // нет такого
		{"--revoke", "nat-b"},                  // неоднозначное имя
		{"--revoke", "x", "--list"},            // взаимоисключающие
		{"--revoke", "nat-a", "--name", "nat"}, // смешение с выпуском
		{},                                     // ни имени, ни действия
	} {
		if _, err := run(t, append([]string{"agents", "enroll-token", "-c", cfg}, bad...)...); err == nil {
			t.Fatalf("%v must fail", bad)
		}
	}
	if out, err = run(t, "agents", "enroll-token", "-c", cfg, "--revoke", "nat-a"); err != nil || !strings.Contains(out, "отозван") {
		t.Fatalf("revoke by name: %v %q", err, out)
	}
	var bID string
	for _, m := range ids {
		if m[2] == "b" {
			bID = m[1]
			break
		}
	}
	if _, err = run(t, "agents", "enroll-token", "-c", cfg, "--revoke", bID); err != nil {
		t.Fatalf("revoke by id: %v", err)
	}
	if out, err = run(t, "agents", "enroll-token", "-c", cfg, "--list"); err != nil || strings.Count(out, "nat-") != 1 {
		t.Fatalf("list after revoke: %v %q", err, out)
	}
	// повторный отзыв и аудит
	if _, err = run(t, "agents", "enroll-token", "-c", cfg, "--revoke", bID); err == nil {
		t.Fatal("repeated revoke must fail")
	}
	sc, err := config.LoadServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st, err := app.OpenSQLite(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	au, _ := st.Audit().List(context.Background(), store.AuditQuery{})
	n := 0
	for _, e := range au {
		if e.Action == api.AuditEnrollRevoke && strings.HasPrefix(e.Actor, "cli:") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("audit enrollment.revoke: %d (%+v)", n, au)
	}
}
