package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"golang.org/x/crypto/ssh"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

func encryptedKey(t *testing.T, pass string) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return pem.EncodeToMemory(blk), sp
}

func TestDialTOFUAndFixedHostKey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := Target{Host: "127.0.0.1", Port: e.host.port(), User: "admin"}
	auth := Auth{PrivateKeyPEM: e.adminPEM}
	pol := HostKeyPolicy{Repo: e.st.HostKeys(), AgentID: "a1", Alerter: e.alerts, Timeout: 5 * time.Second}

	// Не закреплён → ErrHostKeyUnknown с отпечатком, подключение не доверяется.
	_, err := Dial(ctx, target, auth, pol)
	var unk *ErrHostKeyUnknown
	if !errors.As(err, &unk) || unk.Fingerprint != e.fingerprint() || unk.Algo != ssh.KeyAlgoED25519 {
		t.Fatalf("err = %v", err)
	}
	if len(e.alerts.got()) != 0 {
		t.Fatal("алерт на неизвестном ключе не нужен")
	}

	// Закрепили → подключение проходит.
	e.pin()
	cl, err := Dial(ctx, target, auth, pol)
	if err != nil {
		t.Fatal(err)
	}
	_ = cl.Close()

	// Подмена → ErrHostKeyMismatch и алерт.
	other := newHostKey(t)
	e.host.setHostKey(other)
	_, err = Dial(ctx, target, auth, pol)
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
	if got := e.alerts.got(); len(got) != 1 || got[0] != [2]string{"a1", target.Addr()} {
		t.Fatalf("alerts %v", got)
	}
	if !strings.Contains(err.Error(), ssh.FingerprintSHA256(other.PublicKey())) {
		t.Fatalf("в ошибке нет полученного отпечатка: %v", err)
	}
}

func TestDialPinnedAlgoRSAAndBrokenPin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := Target{Host: "127.0.0.1", Port: e.host.port(), User: "admin"}
	pol := HostKeyPolicy{Repo: e.st.HostKeys(), Timeout: 5 * time.Second}
	_ = e.st.HostKeys().Put(ctx, store.HostKey{Host: target.Addr(), Algo: "x", Fingerprint: "SHA256:x", PublicKey: []byte{1, 2, 3}})
	if _, err := Dial(ctx, target, Auth{PrivateKeyPEM: e.adminPEM}, pol); err == nil || !strings.Contains(err.Error(), "повреждён") {
		t.Fatalf("err = %v", err)
	}
	if got := algosFor(mustRSAPub(t)); len(got) != 2 || got[0] != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("rsa algos %v", got)
	}
}

func mustRSAPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	// публичный RSA 2048 из фиксированного wire-представления не нужен: генерируем минимальный.
	k, err := rsaKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDialRejectsBadInputAndNoRepo(t *testing.T) {
	ctx := context.Background()
	st := memtest.New()
	pol := HostKeyPolicy{Repo: st.HostKeys()}
	for _, tg := range []Target{
		{Host: "a b", Port: 22, User: "u"}, {Host: "h", Port: 0, User: "u"}, {Host: "h", Port: 22, User: "U x"},
	} {
		if _, err := Dial(ctx, tg, Auth{Password: []byte("x")}, pol); err == nil {
			t.Fatalf("%+v принят", tg)
		}
	}
	if _, err := Dial(ctx, Target{Host: "h", Port: 22, User: "u"}, Auth{Password: []byte("x")}, HostKeyPolicy{}); err == nil {
		t.Fatal("без Repo принят")
	}
	if _, err := Dial(ctx, Target{Host: "h", Port: 22, User: "u"}, Auth{}, pol); !errors.Is(err, ErrNoAuth) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := ProbeHostKey(ctx, Target{Host: "a;b", Port: 22}); err == nil {
		t.Fatal("probe принял плохой хост")
	}
	if _, _, err := ProbeHostKey(ctx, Target{Host: "h", Port: 99999}); err == nil {
		t.Fatal("probe принял плохой порт")
	}
	// недоступный адрес
	ln, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if _, _, err := ProbeHostKey(ctx, Target{Host: "127.0.0.1", Port: p}); err == nil {
		t.Fatal("probe закрытого порта без ошибки")
	}
	if _, err := Dial(ctx, Target{Host: "127.0.0.1", Port: p, User: "u"}, Auth{Password: []byte("x")}, pol); err == nil {
		t.Fatal("dial закрытого порта без ошибки")
	}
}

func TestPassphraseErrors(t *testing.T) {
	pemKey, _ := encryptedKey(t, keyPassphrase)
	if err := (Auth{PrivateKeyPEM: pemKey}).Validate(); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("без passphrase: %v", err)
	}
	if msg := ErrPassphraseRequired.Error(); !strings.Contains(msg, "passphrase") || !strings.Contains(msg, "зашифрован") {
		t.Fatalf("сообщение непонятное: %q", msg)
	}
	if err := (Auth{PrivateKeyPEM: pemKey, Passphrase: []byte("nope")}).Validate(); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("неверная passphrase: %v", err)
	}
	if err := (Auth{PrivateKeyPEM: pemKey, Passphrase: []byte(keyPassphrase)}).Validate(); err != nil {
		t.Fatalf("верная passphrase: %v", err)
	}
	if err := (Auth{PrivateKeyPEM: []byte("garbage")}).Validate(); err == nil || strings.Contains(err.Error(), "garbage") {
		t.Fatalf("мусорный ключ: %v", err)
	}

	// Через Dial и Install — до любых подключений.
	e := newEnv(t)
	e.pin()
	_, err := Dial(context.Background(), Target{Host: "127.0.0.1", Port: e.host.port(), User: "admin"},
		Auth{PrivateKeyPEM: pemKey}, HostKeyPolicy{Repo: e.st.HostKeys()})
	if !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("Dial: %v", err)
	}
	req := e.request()
	req.Auth = Auth{PrivateKeyPEM: pemKey}
	if _, err := e.inst.Install(context.Background(), req); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("Install: %v", err)
	}
	if e.host.connCount() != 0 {
		t.Fatal("подключение до проверки ключа")
	}
}

func TestAuthZeroAndClone(t *testing.T) {
	a := Auth{Password: []byte("pw"), PrivateKeyPEM: []byte("k"), Passphrase: []byte("p")}
	c := a.Clone()
	c.Zero()
	if c.Password != nil || a.Password[0] != 'p' {
		t.Fatal("Clone должен копировать, Zero — обнулять")
	}
	pw := a.Password
	a.Zero()
	if pw[0] != 0 || pw[1] != 0 {
		t.Fatal("Zero не затёр байты")
	}
	if len(a.secrets()) != 0 {
		t.Fatal("secrets после Zero")
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":                "''",
		"abc-1.2/x_y":     "abc-1.2/x_y",
		"a b":             "'a b'",
		"it's":            `'it'\''s'`,
		"$(rm -rf /)":     "'$(rm -rf /)'",
		"a;b":             "'a;b'",
		"-f=${db:Status}": "'-f=${db:Status}'",
		"*":               "'*'",
		"\n":              "'\n'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMustPathPanicsOnUnsafe(t *testing.T) {
	for _, p := range []string{"relative", "/a b", "/a;b", "/a/../b", "/a$(x)", ""} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("mustPath(%q) не паникует", p)
				}
			}()
			mustPath(p)
		}()
	}
	mustPath("/var/lib/tgproxy-deploy/.ssh/authorized_keys")
}

func TestValidators(t *testing.T) {
	for _, h := range []string{"10.0.0.1", "ams-2.example.com", "host", "2001:db8::1"} {
		if err := validateHost(h); err != nil {
			t.Errorf("%q: %v", h, err)
		}
	}
	for _, h := range []string{"", "-a", "a_b", "a..b", "fe80::1%eth0", strings.Repeat("a", 300), "a b", "h;x"} {
		if validateHost(h) == nil {
			t.Errorf("%q принят", h)
		}
	}
	if validateName("ams-2") != nil || validateName("a b") == nil || validateName("") == nil {
		t.Error("validateName")
	}
	if validateUser("deploy") != nil || validateUser("Root") == nil || validateUser("") == nil {
		t.Error("validateUser")
	}
	if (Target{Host: "::1", Port: 22}).Addr() != "[::1]:22" {
		t.Error("Addr ipv6")
	}
}

func TestCommandErrorAndCapBuffer(t *testing.T) {
	e := &CommandError{Cmd: "x", Code: 3, Stderr: " oops \n"}
	if !strings.Contains(e.Error(), "кодом 3") || !strings.Contains(e.Error(), "oops") {
		t.Fatal(e.Error())
	}
	if !isExit(e) || isExit(errors.New("x")) {
		t.Fatal("isExit")
	}
	b := &capBuffer{max: 4}
	n, _ := b.Write([]byte("abcdefgh"))
	if n != 8 || b.buf.String() != "abcd" {
		t.Fatalf("%d %q", n, b.buf.String())
	}
}

func TestRemoteClosedAndWire(t *testing.T) {
	var r *Remote
	r.Close()
	if _, err := r.Run(context.Background(), cmdIDUser()); err == nil {
		t.Fatal("nil Remote.Run")
	}
	r = &Remote{}
	if _, err := r.sftp(); err == nil {
		t.Fatal("sftp без клиента")
	}
	r = newRemote(nil, "root", Auth{}, "/tmp")
	if line, in := r.wire(cmdDpkgRemove()); line != "/usr/bin/dpkg -r tgproxy" || in != nil {
		t.Fatal(line)
	}
	r = newRemote(nil, "u", Auth{Password: []byte("pw")}, "/tmp")
	if line, in := r.wire(cmdDpkgRemove()); !strings.HasPrefix(line, "sudo -S -p '' ") || string(in) != "pw\n" {
		t.Fatal(line)
	}
	if line, _ := r.wire(cmdSHA256("/tmp/x")); strings.Contains(line, "sudo") {
		t.Fatal("непривилегированная команда через sudo")
	}
}

func TestPackages(t *testing.T) {
	dir := t.TempDir()
	if _, err := findPackages(filepath.Join(dir, "missing"), ""); err == nil {
		t.Fatal("нет каталога")
	}
	if _, err := findPackages(dir, ""); err == nil {
		t.Fatal("пустой кэш")
	}
	_, key, _ := minisign.GenerateKey(rand.Reader)
	writeRelease(t, dir, "1.9.0", key, map[string]string{"amd64": "x"})
	writeRelease(t, dir, "1.10.0", key, map[string]string{"amd64": "x", "arm64": "y"})
	writeRelease(t, dir, "1.10.0-rc1", key, map[string]string{"amd64": "x"})
	writeRelease(t, dir, "0.0.1-snapshot", key, map[string]string{"amd64": "x"})
	// мусор: плоский файл, каталог с плохой версией, чужие имена, deb не той версии
	writeRelease(t, dir, "v2.0.0", key, map[string]string{"amd64": "x"})
	_ = os.WriteFile(filepath.Join(dir, "tgproxy_3.0.0_amd64.deb"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "prev.deb"), []byte("x"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "4.0.0", "tgproxy_4.0.0_amd64.deb"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "1.9.0", "other_1.0_amd64.deb"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "1.9.0", "tgproxy_5.0.0_amd64.deb"), []byte("x"), 0o644)
	p, err := findPackages(dir, "")
	if err != nil || p.version != "1.10.0" || len(p.files) != 2 || p.dir != filepath.Join(dir, "1.10.0") {
		t.Fatalf("%+v %v", p, err)
	}
	if path, name, ok := p.path("arm64"); !ok || name != "tgproxy_1.10.0_arm64.deb" || filepath.Dir(path) != p.dir {
		t.Fatal(path, name, ok)
	}
	if _, _, ok := p.path("mips"); ok {
		t.Fatal("несуществующая архитектура")
	}
	if p, err := findPackages(dir, "1.9.0"); err != nil || p.version != "1.9.0" || len(p.files) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := findPackages(dir, "2.0.0"); err == nil {
		t.Fatal("нет версии")
	}
	for _, c := range []struct {
		a, b string
		sign int
	}{
		{"1.10.0", "1.9.0", 1}, {"1.0", "1.0.0", 0}, {"1.4.1", "1.4.1-rc1", 1}, {"1.4.1-rc1", "1.4.1", -1},
		{"1.4.1-rc2", "1.4.1-rc1", 1}, {"0.0.1-snapshot", "0.0.1-snapshot", 0}, {"2.0.0~beta", "1.9.9", 1},
	} {
		got := compareVersions(c.a, c.b)
		if (got > 0) != (c.sign > 0) || (got < 0) != (c.sign < 0) {
			t.Errorf("compare(%s,%s)=%d, want sign %d", c.a, c.b, got, c.sign)
		}
	}
}

func TestServerKeyCreateLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ssh")
	k1, err := LoadOrCreateServerKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "id_ed25519"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("права ключа: %v %v", st, err)
	}
	if ds, _ := os.Stat(dir); ds.Mode().Perm() != 0o700 {
		t.Fatalf("права каталога %v", ds.Mode().Perm())
	}
	pub, err := os.ReadFile(filepath.Join(dir, "id_ed25519.pub"))
	if err != nil || !strings.HasPrefix(string(pub), "ssh-ed25519 ") {
		t.Fatalf("pub %q %v", pub, err)
	}
	k2, err := LoadOrCreateServerKey(dir)
	if err != nil || string(k1.PublicKey().Marshal()) != string(k2.PublicKey().Marshal()) {
		t.Fatalf("ключ изменился: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "id_ed25519"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateServerKey(dir); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("широкие права приняты: %v", err)
	}
	_ = os.Chmod(filepath.Join(dir, "id_ed25519"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("junk"), 0o600)
	if _, err := LoadOrCreateServerKey(dir); err == nil {
		t.Fatal("мусорный ключ принят")
	}
	if _, err := LoadOrCreateServerKey(filepath.Join(dir, "id_ed25519", "x")); err == nil {
		t.Fatal("каталог внутри файла")
	}
}

func TestRenderSudoers(t *testing.T) {
	s := string(RenderSudoers())
	var rules []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			rules = append(rules, l)
		}
	}
	want := "tgproxy-deploy ALL=(root) NOPASSWD: /usr/bin/tgproxy deploy-helper *"
	if len(rules) != 1 || rules[0] != want {
		t.Fatalf("sudoers: %q", rules)
	}
	if strings.Contains(s, "!") && strings.Contains(strings.Join(rules, ""), "!") {
		t.Fatal("deny-списки запрещены")
	}
}

func TestRenderAgentConfigValidation(t *testing.T) {
	if _, err := RenderAgentConfig(0, "tgproxy-server"); err == nil {
		t.Fatal("порт 0")
	}
	if _, err := RenderAgentConfig(8443, "a\nb"); err == nil {
		t.Fatal("SAN с переводом строки")
	}
	b, err := RenderAgentConfig(9000, "tgproxy-server")
	if err != nil || !strings.Contains(string(b), `"0.0.0.0:9000"`) {
		t.Fatalf("%s %v", b, err)
	}
}

func TestHostKeyInfoLabel(t *testing.T) {
	h := HostKeyInfo{Algo: ssh.KeyAlgoED25519, Fingerprint: "SHA256:abc"}
	if h.Label() != "ED25519 · SHA256:abc" {
		t.Fatal(h.Label())
	}
	for in, want := range map[string]string{
		ssh.KeyAlgoRSA: "RSA", ssh.KeyAlgoRSASHA512: "RSA", ssh.KeyAlgoECDSA256: "ECDSA-256",
		ssh.KeyAlgoECDSA384: "ECDSA-384", ssh.KeyAlgoECDSA521: "ECDSA-521", "weird": "weird",
	} {
		if algoLabel(in) != want {
			t.Errorf("algoLabel(%s)", in)
		}
	}
}

func TestEventFromStore(t *testing.T) {
	ev := eventFromStore(store.InstallJobEvent{ID: 5, JobID: "j", Kind: EventStep, Step: "ssh", Level: StepOK, Message: "m"})
	if ev.Status != StepOK || ev.Level != "info" || ev.Seq != 5 {
		t.Fatalf("%+v", ev)
	}
	ev = eventFromStore(store.InstallJobEvent{ID: 6, Kind: EventLog, Level: "warn"})
	if ev.Status != "" || ev.Level != "warn" {
		t.Fatalf("%+v", ev)
	}
}

func TestLongMessageTruncated(t *testing.T) {
	st := memtest.New()
	_ = st.InstallJobs().Create(context.Background(), store.InstallJob{ID: "j", Host: "h:1", Kind: "install", State: store.InstallRunning})
	l := &liveJob{id: "j", bg: context.Background(), repo: st.InstallJobs(), subs: map[chan Event]struct{}{}, scrubs: [][]byte{[]byte("SECRET")}}
	ev := l.emit(Event{Kind: EventLog, Message: "x SECRET " + strings.Repeat("y", 5000)})
	if len(ev.Message) > maxMessage+4 || strings.Contains(ev.Message, "SECRET") || !strings.HasPrefix(ev.Message, "x *** ") {
		t.Fatalf("%q", ev.Message[:40])
	}
	// БД недоступна для чужого job → событие всё равно возвращается, не паникует (log nil-safe)
	l2 := &liveJob{id: "ghost", bg: context.Background(), repo: st.InstallJobs(), subs: map[chan Event]struct{}{}, log: nopLogger()}
	_ = l2.emit(Event{Kind: EventLog, Message: "z"})
}
