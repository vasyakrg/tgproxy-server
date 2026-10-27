package faketls

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
	"time"
)

const dom = "front.example.test"

var (
	k0  = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	k1  = [16]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}
	k2  = [16]byte{9: 9}
	now = time.Unix(1_800_000_000, 0)
)

func mustParse(t testing.TB, b []byte) Hello {
	t.Helper()
	h, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return h
}

func hello(key [16]byte, ts time.Time, names ...string) []byte {
	return buildHello(genOpts{key: key[:], sni: names, timestamp: ts, sessionID: sid()})
}

func TestMatch_Valid(t *testing.T) {
	h := mustParse(t, hello(k0, now, dom))
	if h.SNI != dom || len(h.SessionID) != 32 {
		t.Fatalf("SNI=%q sid=%d", h.SNI, len(h.SessionID))
	}
	if idx, ok := Match(h, [][16]byte{k0}, dom, now, time.Minute); !ok || idx != 0 {
		t.Fatalf("idx=%d ok=%v", idx, ok)
	}
}

func TestMatch_Rejects(t *testing.T) {
	skew := time.Minute
	tests := map[string]struct {
		raw  []byte
		keys [][16]byte
	}{
		"wrong sni":     {hello(k0, now, "other.example.test"), [][16]byte{k0}},
		"no sni":        {hello(k0, now), [][16]byte{k0}},
		"wrong hmac":    {hello(k1, now, dom), [][16]byte{k0}},
		"random digest": {buildHello(genOpts{sni: []string{dom}, sessionID: sid(), noHMAC: true}), [][16]byte{k0}},
		"stale":         {hello(k0, now.Add(-skew-2*time.Second), dom), [][16]byte{k0}},
		"future":        {hello(k0, now.Add(skew+2*time.Second), dom), [][16]byte{k0}},
		"no keys":       {hello(k0, now, dom), nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := mustParse(t, tc.raw)
			if idx, ok := Match(h, tc.keys, dom, now, skew); ok {
				t.Fatalf("ожидали отказ, получили idx=%d", idx)
			}
		})
	}
}

func TestMatch_SkewBoundary(t *testing.T) {
	skew := 30 * time.Second
	for _, d := range []time.Duration{-skew, skew, 0} {
		h := mustParse(t, hello(k0, now.Add(d), dom))
		if _, ok := Match(h, [][16]byte{k0}, dom, now, skew); !ok {
			t.Fatalf("смещение %v внутри окна, ожидали ok", d)
		}
	}
}

func TestMatch_PicksCorrectKey(t *testing.T) {
	keys := [][16]byte{k0, k1, k2}
	for want := range keys {
		h := mustParse(t, hello(keys[want], now, dom))
		idx, ok := Match(h, keys, dom, now, time.Minute)
		if !ok || idx != want {
			t.Fatalf("want %d, got idx=%d ok=%v", want, idx, ok)
		}
	}
}

func TestMatch_DuplicateKeysFirstWins(t *testing.T) {
	h := mustParse(t, hello(k1, now, dom))
	idx, ok := Match(h, [][16]byte{k0, k1, k2, k1}, dom, now, time.Minute)
	if !ok || idx != 1 {
		t.Fatalf("idx=%d ok=%v, ждали 1", idx, ok)
	}
}

func TestMatch_SNIAmongSeveral(t *testing.T) {
	h := mustParse(t, hello(k0, now, "a.example.test", dom))
	if h.SNI != "a.example.test" || len(h.ServerNames) != 2 {
		t.Fatalf("SNI=%q names=%v", h.SNI, h.ServerNames)
	}
	if _, ok := Match(h, [][16]byte{k0}, dom, now, time.Minute); !ok {
		t.Fatal("mtg принимает, если среди имён есть нужное")
	}
}

func TestMatch_ZeroValueHello(t *testing.T) {
	if _, ok := Match(Hello{}, [][16]byte{k0}, dom, now, time.Minute); ok {
		t.Fatal("пустой Hello не должен совпадать")
	}
}

func TestMatch_NoAllocsPerKey(t *testing.T) {
	h := mustParse(t, hello(k2, now, dom))
	one := [][16]byte{k2}
	many := make([][16]byte, 50)
	for i := range many {
		many[i][0] = byte(i + 100)
	}
	many[49] = k2
	run := func(keys [][16]byte) float64 {
		return testing.AllocsPerRun(200, func() { Match(h, keys, dom, now, time.Minute) })
	}
	a1, aN := run(one), run(many)
	if aN > a1 || aN > 2 {
		t.Fatalf("аллокации растут с числом ключей: 1 ключ=%v, 50 ключей=%v", a1, aN)
	}
}

func TestMatch_ReferenceHMAC(t *testing.T) {
	// собственный HMAC в Match обязан совпадать с crypto/hmac: генератор использует hmac.New.
	for i := range 50 {
		var k [16]byte
		k[0], k[15] = byte(i), byte(i*7)
		h := mustParse(t, hello(k, now.Add(time.Duration(i)*time.Second), dom))
		if _, ok := Match(h, [][16]byte{k}, dom, now.Add(time.Minute), 2*time.Minute); !ok {
			t.Fatalf("ключ %d не совпал", i)
		}
	}
}

func TestReadFirstRecord(t *testing.T) {
	raw := hello(k0, now, dom)
	t.Run("ok", func(t *testing.T) {
		// читает ровно одну запись, остаток потока не трогает
		r := bytes.NewReader(append(append([]byte(nil), raw...), "tail"...))
		got, err := ReadFirstRecord(r, MaxRecord)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("err=%v equal=%v", err, bytes.Equal(got, raw))
		}
		rest, _ := io.ReadAll(r)
		if string(rest) != "tail" {
			t.Fatalf("остаток %q", rest)
		}
	})
	t.Run("one byte reader", func(t *testing.T) {
		got, err := ReadFirstRecord(iotest.OneByteReader(bytes.NewReader(raw)), MaxRecord)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatal("медленный клиент: запись должна собраться")
		}
	})
	t.Run("not handshake", func(t *testing.T) {
		got, err := ReadFirstRecord(bytes.NewReader([]byte("GET / HTTP/1.1\r\n\r\n")), MaxRecord)
		if !errors.Is(err, ErrNotHandshake) || string(got) != "GET /" {
			t.Fatalf("err=%v got=%q", err, got)
		}
	})
	t.Run("application data", func(t *testing.T) {
		_, err := ReadFirstRecord(bytes.NewReader([]byte{0x17, 3, 3, 0, 1, 0}), MaxRecord)
		if !errors.Is(err, ErrNotHandshake) {
			t.Fatal(err)
		}
	})
	t.Run("bad version", func(t *testing.T) {
		_, err := ReadFirstRecord(bytes.NewReader([]byte{0x16, 2, 0, 0, 1, 0}), MaxRecord)
		if !errors.Is(err, ErrBadVersion) {
			t.Fatal(err)
		}
	})
	t.Run("zero length", func(t *testing.T) {
		_, err := ReadFirstRecord(bytes.NewReader([]byte{0x16, 3, 1, 0, 0}), MaxRecord)
		if !errors.Is(err, ErrBadLength) {
			t.Fatal(err)
		}
	})
	t.Run("too large", func(t *testing.T) {
		hdr := []byte{0x16, 3, 1, 0x40, 0x01} // 16385
		got, err := ReadFirstRecord(bytes.NewReader(append(hdr, make([]byte, 20000)...)), MaxRecord)
		if !errors.Is(err, ErrTooLarge) || len(got) != 5 {
			t.Fatalf("err=%v len=%d: тело читать нельзя", err, len(got))
		}
	})
	t.Run("max boundary", func(t *testing.T) {
		hdr := []byte{0x16, 3, 1, 0x40, 0x00} // ровно 16384
		got, err := ReadFirstRecord(bytes.NewReader(append(hdr, make([]byte, 16384)...)), MaxRecord)
		if err != nil || len(got) != 5+16384 {
			t.Fatalf("err=%v len=%d", err, len(got))
		}
	})
	t.Run("custom max", func(t *testing.T) {
		_, err := ReadFirstRecord(bytes.NewReader(raw), 10)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatal(err)
		}
	})
	t.Run("default max", func(t *testing.T) {
		if _, err := ReadFirstRecord(bytes.NewReader(raw), 0); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		got, err := ReadFirstRecord(bytes.NewReader(raw[:50]), MaxRecord)
		if err == nil || !bytes.Equal(got, raw[:50]) {
			t.Fatalf("err=%v len=%d: прочитанное нужно вернуть для replay", err, len(got))
		}
	})
	t.Run("short header", func(t *testing.T) {
		got, err := ReadFirstRecord(bytes.NewReader([]byte{0x16, 3}), MaxRecord)
		if err == nil || len(got) != 2 {
			t.Fatalf("err=%v got=%x", err, got)
		}
	})
}

func TestParse_Errors(t *testing.T) {
	good := hello(k0, now, dom)
	mut := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	tests := map[string][]byte{
		"empty":         nil,
		"short":         {0x16, 3, 1},
		"not handshake": mut(func(b []byte) []byte { b[0] = 0x17; return b }),
		"bad version":   mut(func(b []byte) []byte { b[1] = 2; return b }),
		"record len":    mut(func(b []byte) []byte { return b[:len(b)-1] }),
		"not hello":     mut(func(b []byte) []byte { b[5] = 2; return b }),
		"hs len":        mut(func(b []byte) []byte { b[8]++; return b }),
		"header only":   {0x16, 3, 1, 0, 0},
		"truncated sid": mut(func(b []byte) []byte { b[randomOffset+randomLen] = 0xff; return b }),
		"odd ciphers": buildHello(genOpts{key: k0[:], sni: []string{dom}, timestamp: now,
			sessionID: sid(), ciphers: []byte{0x13, 0x01, 0x13}}),
		"grease only": buildHello(genOpts{key: k0[:], sni: []string{dom}, timestamp: now,
			sessionID: sid(), ciphers: []byte{0x0a, 0x0a, 0x1a, 0x1a}}),
		"bad ext": buildHello(genOpts{key: k0[:], sni: []string{dom}, timestamp: now,
			sessionID: sid(), extraExt: []byte{0, 0x2b, 0xff, 0xff, 1}}),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(b); err == nil {
				t.Fatal("ожидали ошибку")
			}
		})
	}
}

func TestParse_SNIVariants(t *testing.T) {
	// посторонние расширения до server_name пропускаются
	h := mustParse(t, buildHello(genOpts{key: k0[:], sni: []string{dom}, timestamp: now, sessionID: sid(),
		extraExt: []byte{0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d}}))
	if h.SNI != dom {
		t.Fatalf("SNI=%q", h.SNI)
	}
	// нет SNI — не ошибка разбора, Match откажет
	if h := mustParse(t, hello(k0, now)); h.SNI != "" || len(h.ServerNames) != 0 {
		t.Fatalf("SNI=%q", h.SNI)
	}
	// пустой список server_name
	b := buildHello(genOpts{key: k0[:], timestamp: now, sessionID: sid(), extraExt: []byte{0, 0, 0, 2, 0, 0}})
	if h := mustParse(t, b); h.SNI != "" {
		t.Fatalf("SNI=%q", h.SNI)
	}
	// не host_name в server_name
	b = buildHello(genOpts{key: k0[:], timestamp: now, sessionID: sid(), extraExt: []byte{0, 0, 0, 4, 0, 2, 1, 0}})
	if _, err := Parse(b); err == nil {
		t.Fatal("тип записи не host_name → ошибка")
	}
}
