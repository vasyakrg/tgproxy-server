package main

import (
	"bytes"
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

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
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
