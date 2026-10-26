package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

func TestKeygenSignVerify(t *testing.T) {
	d := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"keygen", "--dir", d}, &out); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(d, "minisign.key"))
	if err := run([]string{"keygen", "--dir", d}, &out); err != nil { // идемпотентно
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(d, "minisign.key")); !bytes.Equal(before, after) {
		t.Fatal("ключ перезаписан")
	}
	if err := run([]string{"pubkey", "--dir", d}, &out); err != nil {
		t.Fatal(err)
	}
	pk, err := verify.ParsePublicKey(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	deb := filepath.Join(d, "tgproxy_0.0.1-snapshot_arm64.deb")
	if err := os.WriteFile(deb, []byte("deb"), 0o644); err != nil {
		t.Fatal(err)
	}
	pk2 := filepath.Join(d, "pk")
	if err := run([]string{"sign", "--key", filepath.Join(d, "minisign.key"), "--out", pk2, deb}, &out); err != nil {
		t.Fatal(err)
	}
	vd := filepath.Join(pk2, "0.0.1-snapshot")
	sums, _ := os.ReadFile(filepath.Join(vd, "checksums.txt"))
	sig, _ := os.ReadFile(filepath.Join(vd, "checksums.txt.minisig"))
	if err := verify.Verify(sums, sig, []verify.PublicKey{pk}); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(filepath.Join(vd, filepath.Base(deb)))
	defer func() { _ = f.Close() }()
	if err := verify.CheckFile(sums, filepath.Base(deb), f); err != nil {
		t.Fatal(err)
	}
}

func TestErrors(t *testing.T) {
	var out bytes.Buffer
	d := t.TempDir()
	for _, a := range [][]string{
		nil, {"bogus"}, {"sign"}, {"sign", "--key", filepath.Join(d, "none"), "x.deb"}, {"pubkey", "--dir", d}, {"sign", "--bad"},
	} {
		if err := run(a, &out); err == nil {
			t.Errorf("%v: ожидалась ошибка", a)
		}
	}
	_ = run([]string{"keygen", "--dir", d}, &out)
	bad := filepath.Join(d, "other.deb")
	_ = os.WriteFile(bad, nil, 0o644)
	if err := run([]string{"sign", "--key", filepath.Join(d, "minisign.key"), bad}, &out); err == nil {
		t.Error("плохое имя deb принято")
	}
	if err := run([]string{"sign", "--key", filepath.Join(d, "minisign.key"), filepath.Join(d, "tgproxy_1.0.0_amd64.deb")}, &out); err == nil {
		t.Error("нет файла")
	}
}
