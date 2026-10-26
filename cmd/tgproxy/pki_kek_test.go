package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPKIKEKInit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "etc", "kek")
	out, err := run(t, "pki", "kek-init", "--out", p)
	if err != nil || !strings.Contains(out, "создан") {
		t.Fatalf("kek-init: %v %q", err, out)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o400 || st.Size() != 32 {
		t.Fatalf("file: %v %v", st, err)
	}
	before, _ := os.ReadFile(p)
	out, err = run(t, "pki", "kek-init", "--out", p)
	if err != nil || !strings.Contains(out, "уже существует") {
		t.Fatalf("repeat: %v %q", err, out)
	}
	if after, _ := os.ReadFile(p); string(after) != string(before) {
		t.Fatal("KEK was overwritten")
	}
	if _, err := run(t, "pki", "kek-init", "--out", filepath.Join(p, "x", "kek")); err == nil {
		t.Fatal("want error for impossible path")
	}
}
