package link

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

var testKey = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func TestBuildContainsEESecret(t *testing.T) {
	tg, https := Build("proxy.example.com", 443, testKey, "front.example.com")
	want := "ee" + hex.EncodeToString(testKey[:]) + hex.EncodeToString([]byte("front.example.com"))
	if !strings.HasPrefix(tg, "tg://proxy?") || !strings.HasPrefix(https, "https://t.me/proxy?") {
		t.Fatalf("схемы: %q %q", tg, https)
	}
	for _, l := range []string{tg, https} {
		if !strings.Contains(l, "secret="+want) || !strings.Contains(l, "server=proxy.example.com") || !strings.Contains(l, "port=443") {
			t.Fatalf("ссылка без нужных частей: %q", l)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	tg, https := Build("203.0.113.9", 8443, testKey, "front.example.com")
	for _, l := range []string{tg, https} {
		h, p, k, d, err := Parse(l)
		if err != nil {
			t.Fatal(err)
		}
		if h != "203.0.113.9" || p != 8443 || k != testKey || d != "front.example.com" {
			t.Fatalf("круговой: %v %v %v %v", h, p, k, d)
		}
	}
}

func TestParseBase64Secret(t *testing.T) {
	raw := append([]byte{0xee}, testKey[:]...)
	raw = append(raw, "front.example.com"...)
	for _, enc := range []string{
		base64.RawURLEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
	} {
		_, _, k, d, err := Parse("tg://proxy?server=h.example&port=443&secret=" + strings.NewReplacer("+", "%2B", "=", "%3D").Replace(enc))
		if err != nil || k != testKey || d != "front.example.com" {
			t.Fatalf("%q: %v %v %v", enc, k, d, err)
		}
	}
}

func TestParseErrors(t *testing.T) {
	keyHex := hex.EncodeToString(testKey[:])
	dom := hex.EncodeToString([]byte("a.example"))
	cases := map[string]string{
		"dd":              "tg://proxy?server=h&port=443&secret=dd" + keyHex,
		"plain":           "tg://proxy?server=h&port=443&secret=" + keyHex,
		"нет секрета":     "tg://proxy?server=h&port=443",
		"нет server":      "tg://proxy?port=443&secret=ee" + keyHex + dom,
		"нет port":        "tg://proxy?server=h&secret=ee" + keyHex + dom,
		"port=0":          "tg://proxy?server=h&port=0&secret=ee" + keyHex + dom,
		"port=abc":        "tg://proxy?server=h&port=abc&secret=ee" + keyHex + dom,
		"port=70000":      "tg://proxy?server=h&port=70000&secret=ee" + keyHex + dom,
		"нет домена":      "tg://proxy?server=h&port=443&secret=ee" + keyHex,
		"короткий":        "tg://proxy?server=h&port=443&secret=ee0102",
		"не hex/b64":      "tg://proxy?server=h&port=443&secret=%25%25",
		"схема":           "http://t.me/proxy?server=h&port=443&secret=ee" + keyHex + dom,
		"хост t.me":       "https://evil.example/proxy?server=h&port=443&secret=ee" + keyHex + dom,
		"путь":            "https://t.me/other?server=h&port=443&secret=ee" + keyHex + dom,
		"tg host":         "tg://other?server=h&port=443&secret=ee" + keyHex + dom,
		"мусор":           "::::",
		"пусто":           "",
		"домен non-ascii": "tg://proxy?server=h&port=443&secret=ee" + keyHex + "c3a4",
	}
	for name, l := range cases {
		_, _, _, _, err := Parse(l)
		if err == nil {
			t.Errorf("%s: ожидали ошибку", name)
			continue
		}
		if strings.Contains(err.Error(), keyHex) {
			t.Errorf("%s: ключ в ошибке: %v", name, err)
		}
	}
	_, _, _, _, err := Parse("tg://proxy?server=h&port=443&secret=dd" + keyHex)
	if err == nil || !strings.Contains(err.Error(), "FakeTLS") {
		t.Fatalf("dd: понятная ошибка, получили %v", err)
	}
}
