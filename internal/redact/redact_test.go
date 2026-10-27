package redact_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
)

// fakeHex — 32 hex-символа фиктивного ключа.
const fakeHex = "ab12cd34ef56ab12cd34ef56ab12cd34"

const (
	body  = "AAHdq" + "TcvCH1vGWJxfSeofSAs0K5PALDsaw" // склеено: литерал не должен совпадать с шаблоном токена (secret scanning)
	tok   = "123456789:" + body
	botID = "123456789"
)

func TestToken(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"valid", tok, "123456789:***"},
		{"not a token", "hello", "***"},
		{"empty", "", "***"},
		{"short body", "123456789:abc", "***"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redact.Token(tt.in); got != tt.want {
				t.Fatalf("Token(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "no secrets here", "no secrets here"},
		{"path", "/bot" + tok + "/sendMessage", "/bot" + botID + ":***/sendMessage"},
		{"file path", "/file/bot" + tok + "/photos/file_1.jpg", "/file/bot" + botID + ":***/photos/file_1.jpg"},
		{"query", "https://x/y?token=" + tok + "&a=1", "https://x/y?token=" + botID + ":***&a=1"},
		{"json error", `{"ok":false,"description":"Unauthorized: ` + tok + `"}`, `{"ok":false,"description":"Unauthorized: ` + botID + `:***"}`},
		{"multipart filename", `Content-Disposition: form-data; name="document"; filename="` + tok + `.txt"`, `Content-Disposition: form-data; name="document"; filename="` + botID + `:***.txt"`},
		{"urlencoded upper", "/bot" + botID + "%3A" + body + "/getMe", "/bot" + botID + ":***/getMe"},
		{"urlencoded lower", "/bot" + botID + "%3a" + body + "/getMe", "/bot" + botID + ":***/getMe"},
		{"two tokens", tok + " " + tok, botID + ":*** " + botID + ":***"},
		{"glued tokens", "99999:" + body + tok, "99999:***"},
		{"short digits kept", "1234:" + body, "1234:" + body},
		{"client key", "/k/tgp_abcdEFGH12345678ijkl/bot", "/k/tgp_abcd…/bot"},
		{"enroll", "token enr_Zz9Yy8Xx7Ww6Vv5Uu4Tt", "token enr_Zz9Y…"},
		{"faketls", "secret ee" + fakeHex + "676f6f676c652e636f6d", "secret eeab12…"},
		{"faketls short kept", "ee" + fakeHex[:30], "ee" + fakeHex[:30]},
		{"tg proxy url", "tg://proxy?server=1.2.3.4&port=443&secret=ee" + fakeHex + "&x=1", "tg://proxy?server=1.2.3.4&port=443&secret=***&x=1"},
		{"t.me proxy url", "https://t.me/proxy?server=h&port=443&secret=" + fakeHex, "https://t.me/proxy?server=h&port=443&secret=***"},
		{"secret upper", "SECRET=" + fakeHex + " end", "secret=*** end"},
		{"metric name untouched", "tgp_requests_total", "tgp_requests_total"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redact.String(tt.in)
			if got != tt.want {
				t.Fatalf("String(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestURL(t *testing.T) {
	if got := redact.URL(nil); got != "" {
		t.Fatalf("nil: %q", got)
	}
	u, _ := url.Parse("https://api.telegram.org/bot" + tok + "/getMe?x=" + tok)
	got := redact.URL(u)
	if strings.Contains(got, body) || !strings.Contains(got, botID+":***/getMe") {
		t.Fatalf("got %q", got)
	}
	u, _ = url.Parse("https://user:pa55word@h/k/tgp_abcdEFGH12345678ijkl/bot" + tok + "/getMe")
	got = redact.URL(u)
	if strings.Contains(got, "pa55word") || strings.Contains(got, "EFGH") || strings.Contains(got, body) {
		t.Fatalf("leak: %q", got)
	}
}

func TestURLError(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "https://api.telegram.org/bot" + tok + "/sendMessage", Err: errors.New("dial tcp: timeout")}
	got := redact.String(err.Error())
	if strings.Contains(got, body) || !strings.Contains(got, "dial tcp: timeout") {
		t.Fatalf("got %q", got)
	}
	if e := redact.Error(err); strings.Contains(e.Error(), body) {
		t.Fatalf("Error leak: %v", e)
	}
	if redact.Error(nil) != nil {
		t.Fatal("nil error must stay nil")
	}
	plain := errors.New("plain")
	if redact.Error(plain) != plain {
		t.Fatal("clean error must be returned as is")
	}
}

func FuzzRedactNeverLeaks(f *testing.F) {
	f.Add("/bot", "/sendMessage", uint32(123456), body, false)
	f.Add("", "", uint32(99999), body, true)
	f.Add("99999:", "12345:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", uint32(12345), body, false)
	f.Add("%3A", "tgp_", uint32(7777777), "_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-", true)
	f.Fuzz(func(t *testing.T, pre, post string, id uint32, rawBody string, encoded bool) {
		var b strings.Builder
		for _, r := range rawBody {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
				b.WriteRune(r)
			}
		}
		secret := b.String()
		if len(secret) < 30 {
			secret += strings.Repeat("x", 30-len(secret))
		}
		if pre != "" && pre[len(pre)-1] >= '0' && pre[len(pre)-1] <= '9' {
			return // digits of pre become part of the (non-secret) bot id
		}
		if strings.Contains(pre+post, secret) || strings.Contains(secret, "tgp_") {
			return // the surrounding text legitimately contains the secret
		}
		botIDNum := id%1000000000 + 10000
		sep := ":"
		if encoded {
			sep = "%3A"
		}
		in := pre + itoa(botIDNum) + sep + secret + post
		out := redact.String(in)
		if strings.Contains(out, secret) {
			t.Fatalf("leak of secret %q in %q (input %q)", secret, out, in)
		}
		// glued variants must not leak either
		out = redact.String(pre + itoa(botIDNum) + sep + secret + itoa(botIDNum) + sep + secret + post)
		if strings.Contains(out, secret) {
			t.Fatalf("leak (glued) %q in %q", secret, out)
		}
		// idempotence
		if again := redact.String(out); again != out {
			t.Fatalf("not idempotent: %q -> %q", out, again)
		}
		key := "tgp_" + secret[:20]
		if strings.Trim(secret[:20], "_-") == secret[:20] || strings.ContainsAny(secret[:20], "_-") {
			return
		}
		if strings.Contains(redact.String(key), secret[4:20]) {
			t.Fatalf("client key leak")
		}
	})
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
