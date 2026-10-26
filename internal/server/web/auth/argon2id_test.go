package auth

import (
	"strings"
	"testing"
)

const (
	autheliaDocHash = "$argon2id$v=19$m=65536,t=3,p=2$BpLnfgDsc2WD8F2q$o/vzA4myCqZZ36bUGsDY//8mKUYNZZaR0t4MFFSs+iM"
	devHash         = "$argon2id$v=19$m=65536,t=3,p=4$SsVC93DvL2QsXq2KEClWuw$7jIVfrXLMXZaQY2/RUDqCrXQzD2nQL4MIt8QATsw2Is"
)

func TestParseReferenceHashes(t *testing.T) {
	p, err := ParsePHC(autheliaDocHash)
	if err != nil {
		t.Fatal(err)
	}
	if p.M != 65536 || p.T != 3 || p.P != 2 || len(p.Salt) != 12 || len(p.Key) != 32 {
		t.Fatalf("params: %+v", p)
	}
}

func TestVerifyReference(t *testing.T) {
	if !Verify("dev-password", devHash) {
		t.Fatal("dev hash must verify")
	}
	if Verify("wrong", devHash) {
		t.Fatal("wrong password verified")
	}
}

func TestHashRoundTripAndDefaults(t *testing.T) {
	h, err := Hash("s3cret", DefaultHashParams())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash: %s", h)
	}
	if !Verify("s3cret", h) || Verify("s3cret2", h) {
		t.Fatal("round trip")
	}
	p, _ := ParsePHC(h)
	if len(p.Salt) != 16 || len(p.Key) != 32 {
		t.Fatalf("lengths: %d %d", len(p.Salt), len(p.Key))
	}
}

func TestParsePaddedBase64(t *testing.T) {
	// Std с паддингом: salt 9 байт -> "AAAAAAAAAAAA"? берём 10 байт -> 16 символов с "==".
	phc := "$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQ==$AAECAwQFBgcICQoLDA0ODw=="
	p, err := ParsePHC(phc)
	if err != nil || len(p.Salt) != 10 || len(p.Key) != 16 {
		t.Fatalf("padded: %v %+v", err, p)
	}
	raw := "$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQ$AAECAwQFBgcICQoLDA0ODw"
	if _, err := ParsePHC(raw); err != nil {
		t.Fatalf("raw: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	salt, key := "AAECAwQFBgcICQoL", "AAECAwQFBgcICQoLDA0ODw"
	cases := map[string]string{
		"v16":         "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key,
		"argon2i":     "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"argon2d":     "$argon2d$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"no m":        "$argon2id$v=19$t=1,p=1$" + salt + "$" + key,
		"no t":        "$argon2id$v=19$m=64,p=1$" + salt + "$" + key,
		"no p":        "$argon2id$v=19$m=64,t=1$" + salt + "$" + key,
		"p=0":         "$argon2id$v=19$m=64,t=1,p=0$" + salt + "$" + key,
		"p=256":       "$argon2id$v=19$m=64,t=1,p=256$" + salt + "$" + key,
		"bad b64":     "$argon2id$v=19$m=64,t=1,p=1$!!!$" + key,
		"bad key b64": "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$!!!",
		"short salt":  "$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBg$" + key,
		"m too big":   "$argon2id$v=19$m=1048577,t=1,p=1$" + salt + "$" + key,
		"t too big":   "$argon2id$v=19$m=64,t=11,p=1$" + salt + "$" + key,
		"m small":     "$argon2id$v=19$m=4,t=1,p=1$" + salt + "$" + key,
		"zero t":      "$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + key,
		"unknown":     "$argon2id$v=19$m=64,t=1,p=1,x=1$" + salt + "$" + key,
		"bad kv":      "$argon2id$v=19$m=64,t,p=1$" + salt + "$" + key,
		"nan":         "$argon2id$v=19$m=a,t=1,p=1$" + salt + "$" + key,
		"short":       "$argon2id$v=19$m=64,t=1,p=1$" + salt,
		"empty":       "",
		"short key":   "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$AAE",
	}
	for name, s := range cases {
		if _, err := ParsePHC(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if Verify("x", s) {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestDoSLimitsNoCompute(t *testing.T) {
	// m = 4 GiB: при вычислении тест бы упал по памяти/времени.
	phc := "$argon2id$v=19$m=4194304,t=3,p=4$AAECAwQFBgcICQoL$AAECAwQFBgcICQoLDA0ODw"
	if Verify("x", phc) {
		t.Fatal("verified")
	}
	if _, err := Hash("x", HashParams{M: 1 << 21, T: 1, P: 1, SaltLen: 16, KeyLen: 32}); err == nil {
		t.Fatal("Hash must reject huge m")
	}
	if _, err := Hash("x", HashParams{M: 64, T: 1, P: 1, SaltLen: 2, KeyLen: 32}); err == nil {
		t.Fatal("Hash must reject short salt")
	}
}

func TestDummyAlwaysFalse(t *testing.T) {
	if VerifyDummy("anything") {
		t.Fatal("dummy verified")
	}
}
