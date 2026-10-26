package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
)

func runIn(t *testing.T, stdin string, args ...string) (string, error) {
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

func TestHashpwFromStdin(t *testing.T) {
	out, err := runIn(t, "hunter2\n", "hashpw")
	if err != nil {
		t.Fatal(err)
	}
	h := strings.TrimSpace(out)
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") || !auth.Verify("hunter2", h) || auth.Verify("hunter3", h) {
		t.Fatalf("hash: %q", out)
	}
	if _, err := runIn(t, "", "hashpw"); err == nil {
		t.Fatal("empty password accepted")
	}
	if out, err := runIn(t, "x", "hashpw", "extra"); err == nil {
		t.Fatalf("args accepted: %s", out)
	}
}

func TestTOTPEnroll(t *testing.T) {
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	if err := pki.GenerateKEK(kek); err != nil {
		t.Fatal(err)
	}
	usersFile := filepath.Join(dir, "users.yml")
	h, _ := auth.Hash("pw", auth.HashParams{M: 64, T: 1, P: 1, SaltLen: 16, KeyLen: 32})
	if err := os.WriteFile(usersFile, []byte("users:\n  admin:\n    password: '"+h+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runIn(t, "", "totp", "enroll", "admin", "--users-file", usersFile, "--kek-file", kek)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "otpauth://totp/tgproxy:admin?") || !strings.Contains(out, "█") {
		t.Fatalf("output: %s", out)
	}
	m := regexp.MustCompile(`totp_secret_enc: '([^']+)'`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no totp_secret_enc: %s", out)
	}
	// значение расшифровывается KEK с AAD пользователя и совпадает с секретом из URI
	k, err := pki.LoadKEK(kek)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(m[1])
	pt, err := k.Open(raw, []byte("totp:admin"))
	if err != nil || !strings.Contains(out, "secret="+string(pt)) {
		t.Fatalf("open: %v", err)
	}
	if _, err := k.Open(raw, []byte("totp:other")); err == nil {
		t.Fatal("AAD not bound")
	}
	// файл пользователей не тронут
	if b, _ := os.ReadFile(usersFile); strings.Contains(string(b), "totp_secret_enc") {
		t.Fatal("users file was modified")
	}
	// --no-qr
	out, err = runIn(t, "", "totp", "enroll", "admin", "--users-file", usersFile, "--kek-file", kek, "--no-qr")
	if err != nil || strings.Contains(out, "█") {
		t.Fatalf("no-qr: %v", err)
	}
}

func TestTOTPEnrollErrors(t *testing.T) {
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	if err := pki.GenerateKEK(kek); err != nil {
		t.Fatal(err)
	}
	usersFile := filepath.Join(dir, "users.yml")
	h, _ := auth.Hash("pw", auth.HashParams{M: 64, T: 1, P: 1, SaltLen: 16, KeyLen: 32})
	_ = os.WriteFile(usersFile, []byte("users:\n  admin:\n    password: '"+h+"'\n"), 0o600)

	cases := map[string][]string{
		"no flags":     {"totp", "enroll", "admin", "--users-file", "", "--kek-file", ""},
		"unknown user": {"totp", "enroll", "ghost", "--users-file", usersFile, "--kek-file", kek},
		"no users":     {"totp", "enroll", "admin", "--users-file", filepath.Join(dir, "none"), "--kek-file", kek},
		"no kek":       {"totp", "enroll", "admin", "--users-file", usersFile, "--kek-file", filepath.Join(dir, "none")},
		"no user arg":  {"totp", "enroll"},
	}
	for name, args := range cases {
		if _, err := runIn(t, "", args...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestLoadSealerSwappable(t *testing.T) {
	old := loadSealer
	defer func() { loadSealer = old }()
	loadSealer = func(string) (auth.Sealer, error) { return nil, errors.New("not wired") }
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "u.yml")
	h, _ := auth.Hash("pw", auth.HashParams{M: 64, T: 1, P: 1, SaltLen: 16, KeyLen: 32})
	_ = os.WriteFile(usersFile, []byte("users:\n  admin:\n    password: '"+h+"'\n"), 0o600)
	_, err := runIn(t, "", "totp", "enroll", "admin", "--users-file", usersFile, "--kek-file", "x")
	if err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("%v", err)
	}
}
