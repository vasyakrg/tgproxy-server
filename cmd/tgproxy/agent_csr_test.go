package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentCSRCommand(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "agent.key")

	out, err := run(t, "agent", "csr", "--key", key, "--id", "n1", "--out", "-")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(out))
	if blk == nil {
		t.Fatalf("no CSR in %q", out)
	}
	req, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || req.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	if len(req.URIs) != 1 || req.URIs[0].String() != "spiffe://tgproxy/agent/n1" {
		t.Fatalf("SAN %v", req.URIs)
	}
	if strings.Contains(out, "PRIVATE") {
		t.Fatal("key printed")
	}
	st, err := os.Stat(key)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode: %v %v", st, err)
	}
	first, _ := os.ReadFile(key)

	// отказ без --force, ключ не тронут
	if _, err := run(t, "agent", "csr", "--key", key, "--id", "n1"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want refusal, got %v", err)
	}
	if again, _ := os.ReadFile(key); string(again) != string(first) {
		t.Fatal("key overwritten without --force")
	}

	// --force + вывод в файл
	csrFile := filepath.Join(dir, "a.csr")
	if _, err := run(t, "agent", "csr", "--key", key, "--id", "n1", "--out", csrFile, "--force"); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(key); string(again) == string(first) {
		t.Fatal("key not replaced with --force")
	}
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o600 {
		t.Fatal("mode after force")
	}
	if b, err := os.ReadFile(csrFile); err != nil || !strings.Contains(string(b), "CERTIFICATE REQUEST") {
		t.Fatalf("csr file: %v", err)
	}

	// неверный id — ключ не создаётся
	key2 := filepath.Join(dir, "k2")
	if _, err := run(t, "agent", "csr", "--key", key2, "--id", "bad id!"); err == nil {
		t.Fatal("want invalid id error")
	}
	if _, err := os.Stat(key2); !os.IsNotExist(err) {
		t.Fatal("key created for invalid id")
	}
	// недоступный каталог
	if _, err := run(t, "agent", "csr", "--key", filepath.Join(dir, "no", "k"), "--id", "n1"); err == nil {
		t.Fatal("want error")
	}
}
