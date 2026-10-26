package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

func TestNewKeyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	key, err := NewKeyFile(p, false, "tgproxy-nonexistent-user")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	b, _ := os.ReadFile(p)
	got, err := parseKeyPEM(b)
	if err != nil || !got.Equal(key) {
		t.Fatalf("roundtrip: %v", err)
	}
	if _, err := NewKeyFile(p, false, ""); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want exists error: %v", err)
	}
	if _, err := NewKeyFile(p, true, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyFile(filepath.Join(dir, "x", "k"), false, ""); err == nil {
		t.Fatal("want error")
	}
	if _, err := NewKeyFile(filepath.Join(dir, "x", "k"), true, ""); err == nil {
		t.Fatal("want error (force)")
	}
	// chown для root/несуществующего — без паники и ошибки
	chownIfRoot(p, "root")
	chownIfRoot(p, "no-such-user-xyz")
}

func TestKeyAndCSRHelpersErrors(t *testing.T) {
	if _, err := BuildCSR(nil, "bad id"); err == nil {
		t.Fatal("want invalid id")
	}
	for _, in := range []string{"", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"} {
		if _, err := parseKeyPEM([]byte(in)); err == nil {
			t.Fatalf("want error for %q", in)
		}
	}
	_, k, _ := pki.NewAgentCSR("a1")
	if _, err := parseKeyPEM(k); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(t.TempDir(), "no", "f"), []byte("x"), 0o600); err == nil {
		t.Fatal("want error")
	}
}

func TestInstallCertFailures(t *testing.T) {
	e := newEnv(t, tgOK())
	_ = postCSR(t, e)
	key := e.agent.pending
	held := e.agent.certs.get()
	// каталог ключа недоступен для записи pending
	orig := e.agent.cfg.TLS
	e.agent.cfg.TLS.KeyFile = filepath.Join(t.TempDir(), "no", "key")
	if err := e.agent.installCert([]byte("x"), key, held); err == nil {
		t.Fatal("want pending write error")
	}
	// каталог cert недоступен
	e.agent.cfg.TLS = orig
	e.agent.cfg.TLS.CertFile = filepath.Join(t.TempDir(), "no", "crt")
	if err := e.agent.installCert([]byte("x"), key, held); err == nil {
		t.Fatal("want cert write error")
	}
	// key — каталог: rename .next → key невозможен
	e.agent.cfg.TLS = orig
	dir := filepath.Join(t.TempDir(), "keydir")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.agent.cfg.TLS.KeyFile = dir
	if err := e.agent.installCert([]byte("x"), key, held); err == nil {
		t.Fatal("want promote error")
	}
}
