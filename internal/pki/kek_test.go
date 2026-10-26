package pki

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newTestKEK(t *testing.T) (*KEK, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sub", "kek")
	if err := GenerateKEK(p); err != nil {
		t.Fatal(err)
	}
	k, err := LoadKEK(p)
	if err != nil {
		t.Fatal(err)
	}
	return k, p
}

func TestKEKGenerateAndPerms(t *testing.T) {
	_, p := newTestKEK(t)
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o400 || st.Size() != KEKSize {
		t.Fatalf("mode=%v size=%d", st.Mode().Perm(), st.Size())
	}
	if err := GenerateKEK(p); !errors.Is(err, ErrKEKExists) {
		t.Fatalf("want ErrKEKExists, got %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
}

func TestKEKGenerateErrors(t *testing.T) {
	dir := t.TempDir()
	// родитель — файл
	f := filepath.Join(dir, "f")
	_ = os.WriteFile(f, nil, 0o600)
	if err := GenerateKEK(filepath.Join(f, "kek")); err == nil {
		t.Fatal("want error for file parent")
	}
	// каталог без права записи
	ro := filepath.Join(dir, "ro")
	_ = os.Mkdir(ro, 0o500)
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if os.Geteuid() != 0 {
		if err := GenerateKEK(filepath.Join(ro, "kek")); err == nil {
			t.Fatal("want error for read-only dir")
		}
	}
	// битая ссылка на месте файла не перезаписывается
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKEK(link); !errors.Is(err, ErrKEKExists) {
		t.Fatalf("want ErrKEKExists for symlink, got %v", err)
	}
}

func TestLoadKEKRejects(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key := bytes.Repeat([]byte{7}, KEKSize)
	if _, err := LoadKEK(write("ok600", key, 0o600)); err != nil {
		t.Fatalf("0600 must be allowed: %v", err)
	}
	for _, m := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		if _, err := LoadKEK(write("bad", key, m)); err == nil {
			t.Errorf("mode %04o must be rejected", m)
		}
	}
	if _, err := LoadKEK(write("short", key[:10], 0o400)); err == nil {
		t.Error("short key must be rejected")
	}
	if _, err := LoadKEK(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file must be rejected")
	}
	if _, err := LoadKEK(dir); err == nil {
		t.Error("directory must be rejected")
	}
}

func TestKEKSealOpen(t *testing.T) {
	k, p := newTestKEK(t)
	pt, aad := []byte("secret ca key"), []byte("ca-key")
	ct, err := k.Seal(pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if ct[0] != kekVersion || bytes.Contains(ct, pt) {
		t.Fatal("bad format")
	}
	got, err := k.Open(ct, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	ct2, _ := k.Seal(pt, aad)
	if bytes.Equal(ct, ct2) {
		t.Fatal("nonce must differ")
	}
	if _, err := k.Open(ct, []byte("other")); err == nil {
		t.Error("wrong aad must fail")
	}
	if _, err := k.Open(ct, nil); err == nil {
		t.Error("missing aad must fail")
	}
	for i := range ct {
		bad := bytes.Clone(ct)
		bad[i] ^= 1
		if _, err := k.Open(bad, aad); err == nil {
			t.Errorf("tampered byte %d accepted", i)
		}
	}
	if _, err := k.Open(ct[:5], aad); err == nil {
		t.Error("short input must fail")
	}
	// другой KEK
	other := filepath.Join(filepath.Dir(p), "kek2")
	if err := GenerateKEK(other); err != nil {
		t.Fatal(err)
	}
	k2, _ := LoadKEK(other)
	if _, err := k2.Open(ct, aad); err == nil {
		t.Error("wrong kek must fail")
	}
	// пустой plaintext
	ct, _ = k.Seal(nil, nil)
	if got, err := k.Open(ct, nil); err != nil || len(got) != 0 {
		t.Errorf("empty: %v %v", got, err)
	}
}

func TestNewKEKBadSize(t *testing.T) {
	if _, err := newKEK([]byte("short")); err == nil {
		t.Fatal("want error")
	}
}
