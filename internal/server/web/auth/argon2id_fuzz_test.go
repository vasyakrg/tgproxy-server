package auth

import "testing"

func FuzzParsePHC(f *testing.F) {
	for _, s := range []string{
		"$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g=",
		"$argon2id$v=19$m=4294967295,t=4294967295,p=255$c29tZXNhbHRzYWx0$aGFzaA",
		"$argon2i$v=19$m=1,t=1,p=1$YQ$YQ",
		"$argon2id$v=19$m=0,t=0,p=0$$",
		"$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHRzYWx0$AAAAAA",
		"", "$", "$$$$$$",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePHC(s)
		if err != nil {
			return
		}
		if p.M == 0 || p.M > maxMemoryKiB || p.T == 0 || p.T > maxTime || p.P == 0 {
			t.Fatalf("params out of bounds: %+v", p)
		}
		if p.M < 8*uint32(p.P) {
			t.Fatalf("m too small: %+v", p)
		}
		if len(p.Salt) < minSaltLen || len(p.Salt) > maxSaltLen || len(p.Key) < minKeyLen || len(p.Key) > maxKeyLen {
			t.Fatalf("salt/key length out of bounds: %d/%d", len(p.Salt), len(p.Key))
		}
	})
}
