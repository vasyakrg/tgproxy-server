package verify

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"aead.dev/minisign"
)

func TestVerify(t *testing.T) {
	k1, k2, other := newKey(t), newKey(t), newKey(t)
	msg := []byte(sumLine("tgproxy_1.0.0_amd64.deb", []byte("deb")))
	keys := []PublicKey{k1.pub, k2.pub}

	t.Run("основной ключ", func(t *testing.T) {
		info, err := Authenticate(msg, signED(k1, msg), keys)
		if err != nil {
			t.Fatal(err)
		}
		if info.KeyIndex != 0 || !info.Prehashed || info.KeyID != k1.pub.ID() {
			t.Errorf("info = %+v", info)
		}
		if info.Fields["file"] != "checksums.txt" || info.Fields["timestamp"] != "1700000000" {
			t.Errorf("trusted comment не разобран: %+v", info.Fields)
		}
	})
	t.Run("ротационный (второй) ключ", func(t *testing.T) {
		info, err := Authenticate(msg, signED(k2, msg), keys)
		if err != nil || info.KeyIndex != 1 {
			t.Fatalf("err=%v info=%+v", err, info)
		}
		if err := Verify(msg, signED(k2, msg), keys); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("чужой ключ", func(t *testing.T) {
		if err := Verify(msg, signED(other, msg), keys); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("изменённые данные", func(t *testing.T) {
		bad := append([]byte(nil), msg...)
		bad[0] ^= 1
		if err := Verify(bad, signED(k1, msg), keys); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("подменён trusted comment", func(t *testing.T) {
		sig := signED(k1, msg)
		forged := bytes.Replace(sig, []byte("timestamp:1700000000"), []byte("timestamp:1800000000"), 1)
		if err := Verify(msg, forged, keys); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("legacy Ed принимается", func(t *testing.T) {
		sig := minisign.SignWithComments(k1.priv, msg, "timestamp:1", "u")
		info, err := Authenticate(msg, sig, keys)
		if err != nil || info.Prehashed {
			t.Fatalf("err=%v info=%+v", err, info)
		}
	})
	t.Run("нет ключей", func(t *testing.T) {
		if err := Verify(msg, signED(k1, msg), nil); !errors.Is(err, ErrNoKeys) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("мусор вместо подписи", func(t *testing.T) {
		if err := Verify(msg, []byte("junk"), keys); err == nil {
			t.Fatal("ожидалась ошибка")
		}
	})
}

func TestParsePublicKey(t *testing.T) {
	k := newKey(t)
	for name, in := range map[string]string{
		"base64": k.pub.String(),
		"файл":   "untrusted comment: minisign public key\n" + k.pub.String() + "\n",
	} {
		pk, err := ParsePublicKey(in)
		if err != nil || pk.ID() != k.pub.ID() {
			t.Errorf("%s: pk=%v err=%v", name, pk, err)
		}
	}
	for _, bad := range []string{"", "  ", "!!!", "AAAA"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%q: ожидалась ошибка", bad)
		}
	}
	if _, err := ParsePublicKeys([]string{k.pub.String(), "bad"}); err == nil || !strings.Contains(err.Error(), "pubkeys[1]") {
		t.Errorf("err = %v", err)
	}
	if ks, err := ParsePublicKeys(nil); err != nil || len(ks) != 0 {
		t.Errorf("ks=%v err=%v", ks, err)
	}
}

func TestCheckFile(t *testing.T) {
	deb := []byte("deb-content-0123456789")
	cs := []byte(sumLine("a.deb", deb) + sumLine("b.deb", []byte("other")))
	if err := CheckFile(cs, "a.deb", bytes.NewReader(deb)); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), deb...)
	bad[3] ^= 1 // 1 байт
	if err := CheckFile(cs, "a.deb", bytes.NewReader(bad)); !errors.Is(err, ErrChecksum) {
		t.Fatalf("err = %v", err)
	}
	if err := CheckFile(cs, "zzz.deb", bytes.NewReader(deb)); !errors.Is(err, ErrNotListed) {
		t.Fatalf("err = %v", err)
	}
	if err := CheckFile([]byte("zz  a.deb\n"), "a.deb", bytes.NewReader(deb)); err == nil {
		t.Fatal("ожидалась ошибка некорректной суммы")
	}
	if err := CheckFile(cs, "a.deb", errReader{}); err == nil {
		t.Fatal("ожидалась ошибка чтения")
	}
	if s, err := Sum(cs, "b.deb"); err != nil || len(s) != 64 {
		t.Fatalf("s=%q err=%v", s, err)
	}
	if _, err := Sum(cs, "nope"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	star := []byte(strings.Replace(sumLine("a.deb", deb), "  a.deb", " *a.deb", 1))
	if err := CheckFile(star, "a.deb", bytes.NewReader(deb)); err != nil {
		t.Fatalf("binary-mode: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestCheckVersion(t *testing.T) {
	ok := [][2]string{{"1.2.3", "1.2.3"}, {"v1.3.0", "1.2.9"}, {"2.0.0", ""}, {"1.0.0", "1.0.0-rc.1"}, {"1.0.0-rc.2", "1.0.0-rc.1"}}
	for _, c := range ok {
		if err := CheckVersion(c[0], c[1]); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	for _, c := range [][2]string{{"1.2.2", "1.2.3"}, {"0.9.9", "1.0.0"}, {"1.0.0-rc.1", "1.0.0"}} {
		if err := CheckVersion(c[0], c[1]); !errors.Is(err, ErrDowngrade) {
			t.Errorf("%v: err = %v", c, err)
		}
	}
	if err := CheckVersion("garbage", "1.0.0"); !errors.Is(err, ErrBadVersion) {
		t.Errorf("err = %v", err)
	}
	if err := CheckVersion("1.0.0", "bad"); !errors.Is(err, ErrBadVersion) {
		t.Errorf("err = %v", err)
	}
}

func TestCompare(t *testing.T) {
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	for i := range order {
		for j := range order {
			c, err := CompareVersions(order[i], order[j])
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if c != want {
				t.Errorf("%s vs %s = %d, want %d", order[i], order[j], c, want)
			}
		}
	}
	if c, _ := CompareVersions("1.0.0+a", "1.0.0+b"); c != 0 {
		t.Errorf("build должен игнорироваться")
	}
	if _, err := CompareVersions("x", "1.0.0"); err == nil {
		t.Error("ожидалась ошибка")
	}
	if _, err := CompareVersions("1.0.0", "x"); err == nil {
		t.Error("ожидалась ошибка")
	}
	if _, err := ParseVersion("99999999999999999999.0.0"); err == nil {
		t.Error("переполнение должно отвергаться")
	}
}

func TestVerifierStruct(t *testing.T) {
	k := newKey(t)
	msg := []byte(sumLine("a.deb", []byte("x")))
	v := Verifier{Keys: []PublicKey{k.pub}, MinVersion: "1.2.0"}
	if err := v.Verify(msg, signED(k, msg)); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckFile(msg, "a.deb", bytes.NewReader([]byte("x"))); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckVersion("1.1.9"); !errors.Is(err, ErrDowngrade) {
		t.Fatal(err)
	}
	if err := v.CheckVersion("1.2.0"); err != nil {
		t.Fatal(err)
	}
}
