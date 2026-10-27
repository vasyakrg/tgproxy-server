package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/mtproto/link"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const mtLinkTG = `(tg://proxy\?[^\s]+)`

// mtEnv готовит dev-окружение с KEK и блоком mtproto; noKEK убирает pki.kek_file.
func mtEnv(t *testing.T, noKEK bool) func(a ...string) []string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(root, "dev"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"server.yaml", "users.yml"} {
		b, err := os.ReadFile(filepath.Join(devDir(t), f))
		if err != nil {
			t.Fatal(err)
		}
		if f == "server.yaml" {
			s := string(b) + "\nmtproto:\n  enabled: true\n  listen: \"127.0.0.1:8443\"\n  public_host: mt.example.com\n  public_port: 443\n  fronting_domain: tg.example.com\n"
			if noKEK {
				s = strings.Replace(s, "kek_file: ./dev/data/kek", "kek_file: \"\"", 1)
			}
			b = []byte(s)
		}
		if err := os.WriteFile(filepath.Join(root, "dev", f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	if _, err := run(t, "pki", "dev-init", "--out", "dev/tls"); err != nil {
		t.Fatal(err)
	}
	if !noKEK {
		if _, err := run(t, "pki", "kek-init", "--out", "dev/data/kek"); err != nil {
			t.Fatal(err)
		}
	}
	return func(a ...string) []string { return append(a, "-c", "dev/server.yaml") }
}

func TestMTProtoSecretCLI(t *testing.T) {
	with := mtEnv(t, false)
	out, err := run(t, with("mtproto", "secret", "add", "--name", "family", "--cidr", "198.51.100.0/24", "--max-conns", "5")...)
	if err != nil || !strings.Contains(out, "ОДИН раз") {
		t.Fatalf("add: %v %q", err, out)
	}
	tg := regexp.MustCompile(mtLinkTG).FindString(out)
	host, port, key, domain, perr := link.Parse(tg)
	if perr != nil || host != "mt.example.com" || port != 443 || domain != "tg.example.com" {
		t.Fatalf("link: %v %q", perr, out)
	}
	hexKey := regexp.MustCompile(`ee[0-9a-f]{32}`).FindString(out)
	if hexKey == "" {
		t.Fatal("no secret in add output")
	}

	// list: только префикс, ключа нет.
	out, err = run(t, with("mtproto", "secret", "list")...)
	if err != nil || !strings.Contains(out, "family") || strings.Contains(out, hexKey[2:]) || strings.Contains(out, "tg://") {
		t.Fatalf("list leaks or fails: %v %q", err, out)
	}
	if prefix := hexKey[2:6]; !strings.Contains(out, prefix+"…") {
		t.Fatalf("no prefix %s in %q", prefix, out)
	}
	_ = key

	// link по имени и по id даёт ту же ссылку.
	for _, ref := range []string{"family", "1"} {
		out, err = run(t, with("mtproto", "secret", "link", ref)...)
		if err != nil || !strings.Contains(out, tg) || !strings.Contains(out, "https://t.me/proxy?") {
			t.Fatalf("link %s: %v %q", ref, err, out)
		}
	}

	// rotate: новая ссылка, grace.
	out, err = run(t, with("mtproto", "secret", "rotate", "family", "--grace", "1h")...)
	if err != nil || regexp.MustCompile(mtLinkTG).FindString(out) == tg || !strings.Contains(out, "tg://") {
		t.Fatalf("rotate: %v %q", err, out)
	}
	if _, err = run(t, with("mtproto", "secret", "rotate", "nope")...); err == nil {
		t.Fatal("rotate unknown must fail")
	}

	// delete: без --yes и пустого stdin — отмена; с --yes — отзыв.
	if _, err = run(t, with("mtproto", "secret", "delete", "2")...); err == nil {
		t.Fatal("delete without confirmation must fail")
	}
	out, err = run(t, with("mtproto", "secret", "delete", "2", "--yes")...)
	if err != nil || !strings.Contains(out, "отозван") {
		t.Fatalf("delete: %v %q", err, out)
	}
	if _, err = run(t, with("mtproto", "secret", "link", "2")...); err == nil {
		t.Fatal("link of revoked must fail")
	}

	// валидация и дубль имени.
	for _, bad := range [][]string{
		{"mtproto", "secret", "add", "--name", "x", "--cidr", "bogus"},
		{"mtproto", "secret", "add", "--name", "x", "--max-conns", "-1"},
		{"mtproto", "secret", "add", "--name", ""},
	} {
		if _, err = run(t, with(bad...)...); err == nil {
			t.Fatalf("%v must fail", bad)
		}
	}
}

func TestMTProtoSecretCLINoKEK(t *testing.T) {
	with := mtEnv(t, true)
	for _, a := range [][]string{
		{"mtproto", "secret", "add", "--name", "a"},
		{"mtproto", "secret", "link", "a"},
		{"mtproto", "secret", "rotate", "a"},
		{"mtproto", "secret", "delete", "a", "--yes"},
	} {
		_, err := run(t, with(a...)...)
		if err == nil || !strings.Contains(err.Error(), "pki.kek_file") {
			t.Fatalf("%v: want KEK error, got %v", a, err)
		}
	}
}

func TestMTProtoLinkWritesRevealAudit(t *testing.T) {
	with := mtEnv(t, false)
	if _, err := run(t, with("mtproto", "secret", "add", "--name", "a")...); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_USER", "")
	t.Setenv("USER", "tester")
	if _, err := run(t, with("mtproto", "secret", "link", "a")...); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCmd()
	cmd.SetContext(t.Context())
	cfg, st, err := openAdminStore(cmd, "dev/server.yaml")
	if err != nil || cfg == nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ents, err := st.Audit().List(t.Context(), store.AuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range ents {
		if e.Action == "mtproto_secret.reveal" && e.Actor == "cli:tester" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no reveal audit by cli: %+v", ents)
	}
}

func runWithStdin(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestMTProtoProbeFailureNoLeak(t *testing.T) {
	// закрытый порт: проба обязана упасть (код 1), ссылка и ключ не в выводе/ошибке.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	var k [16]byte
	for i := range k {
		k[i] = byte(0xA0 + i)
	}
	tg, _ := link.Build("127.0.0.1", port, k, "tg.example.com")
	hexKey := "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"

	check := func(out string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("probe must fail, out=%q", out)
		}
		all := out + err.Error()
		if strings.Contains(all, hexKey) || strings.Contains(all, "secret=") || strings.Contains(all, "tg://") {
			t.Fatalf("leak: %q", all)
		}
	}
	out, err := run(t, "mtproto", "probe", "--link", tg, "--timeout", "2s")
	check(out, err)
	out, err = runWithStdin(t, tg+"\n", "mtproto", "probe", "--link-stdin", "--timeout", "2s", "--dc", "4")
	check(out, err)

	for _, bad := range [][]string{
		{"mtproto", "probe"},
		{"mtproto", "probe", "--link", "https://evil.example/x?secret=" + hexKey},
		{"mtproto", "probe", "--link", tg, "--link-stdin"},
	} {
		o, e := run(t, bad...)
		check(o, e)
	}
}

func TestRedact(t *testing.T) {
	k := []byte{1, 2, 3}
	err := redact(errString("boom 010203 tg://x"), "tg://x", k)
	if strings.Contains(err.Error(), "010203") || strings.Contains(err.Error(), "tg://x") {
		t.Fatal(err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// fakeTLSServer отвечает на ClientHello корректным ServerHello (HMAC по ключу) и закрывает соединение.
func fakeTLSServer(t *testing.T, key [16]byte) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		clientRandom := body[6:38]
		rec1 := append([]byte{0x16, 3, 3, 0, 46, 2, 0, 0, 42, 3, 3}, make([]byte, 40)...)
		rec2 := []byte{0x14, 3, 3, 0, 1, 1}
		rec3 := append([]byte{0x17, 3, 3, 0, 8}, make([]byte, 8)...)
		all := append(append(append([]byte{}, rec1...), rec2...), rec3...)
		mac := hmac.New(sha256.New, key[:])
		mac.Write(clientRandom)
		mac.Write(all)
		copy(rec1[11:43], mac.Sum(nil))
		_, _ = c.Write(append(append(rec1, rec2...), rec3...))
		// ждём obfuscated2-инициализацию клиента и закрываем (DC нет)
		_, _ = io.Copy(io.Discard, io.LimitReader(c, 1024))
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestMTProtoProbeHandshakeOnly(t *testing.T) {
	var k [16]byte
	for i := range k {
		k[i] = byte(0x10 + i)
	}
	port := fakeTLSServer(t, k)
	tg, _ := link.Build("127.0.0.1", port, k, "tg.example.com")
	out, err := run(t, "mtproto", "probe", "--link", tg, "--handshake-only", "--timeout", "3s")
	if err != nil {
		t.Fatalf("handshake-only must pass: %v out=%q", err, out)
	}
	if strings.Contains(out, "tg://") || strings.Contains(out, "secret=") {
		t.Fatalf("leak: %q", out)
	}
	// без флага DC не отвечает -> ошибка
	port = fakeTLSServer(t, k)
	tg, _ = link.Build("127.0.0.1", port, k, "tg.example.com")
	if _, err := run(t, "mtproto", "probe", "--link", tg, "--timeout", "2s"); err == nil {
		t.Fatal("full probe must fail without DC")
	}
	// неверный ключ -> handshake-only падает
	port = fakeTLSServer(t, k)
	k2 := k
	k2[0] ^= 0xff
	bad, _ := link.Build("127.0.0.1", port, k2, "tg.example.com")
	if _, err := run(t, "mtproto", "probe", "--link", bad, "--handshake-only", "--timeout", "2s"); err == nil {
		t.Fatal("wrong key must fail")
	}
}
