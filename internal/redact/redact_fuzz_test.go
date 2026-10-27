package redact

import (
	"strings"
	"testing"
)

// fuzzBody — фиктивная секретная часть токена; склеено: литерал не должен совпадать с шаблоном токена (secret scanning).
const fuzzBody = "AAHdq" + "TcvCH1vGWJxfSeofSAs0K5PALDsaw"

func secretOnly(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isSecretChar(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func FuzzString(f *testing.F) {
	f.Add("", uint32(123456), fuzzBody+"_-", " tail", false)
	f.Add("GET /bot", uint32(999999999), fuzzBody, "/getMe?x=1", true)
	f.Add("Post \"https://api.telegram.org/bot", uint32(12345), "AAAAAAAAAAAAAAAAAA"+"AAAAAAAAAAAAAAAAAA", "/sendMessage\": dial", false)
	f.Fuzz(func(t *testing.T, prefix string, id uint32, secret, suffix string, encoded bool) {
		sec := secretOnly(secret)
		if len(sec) < minSecretLen {
			sec += strings.Repeat("Z", minSecretLen)
		}
		if strings.Contains(prefix, sec) || strings.Contains(suffix, sec) {
			return // секрет легитимно присутствует вне токена
		}
		idStr := strings.Repeat("1", minIDDigits) + itoa(id)
		sep := ":"
		if encoded {
			sep = "%3A"
		}
		in := prefix + idStr + sep + sec + suffix
		out := String(in)
		if strings.Contains(out, sec) {
			t.Fatalf("secret leaked: in=%q out=%q", in, out)
		}
		// идемпотентность: повторная маскировка ничего не меняет
		if again := String(out); again != out {
			t.Fatalf("not idempotent: %q -> %q", out, again)
		}
		if Token(in) == "" {
			t.Fatal("empty Token result")
		}
	})
}

func FuzzKeys(f *testing.F) {
	f.Add("tgp_abcdefghijklmnopqrstuvwxyz0123456789")
	f.Add("x enr_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 y")
	f.Fuzz(func(t *testing.T, s string) {
		out := String(s)
		for _, m := range keyRe.FindAllString(out, -1) {
			// после маскировки остаться может только 4+4 символа + «…»; полный ключ — утечка
			if len(m) >= 4+16 && !strings.Contains(m, "…") {
				if strings.Contains(s, m) && m[:4+keyKeepLen]+"…" != m {
					t.Fatalf("key survived: %q", m)
				}
			}
		}
		_ = Token(s)
	})
}

func FuzzMTProtoSecret(f *testing.F) {
	f.Add("tg://proxy?server=h&port=443&secret=", "ab12cd34ef56ab12cd34ef56ab12cd34", "&x=1")
	f.Add("key ee", "00112233445566778899aabbccddeeff", "676f6f676c65")
	f.Fuzz(func(t *testing.T, prefix, hexPart, suffix string) {
		var b strings.Builder
		for i := 0; i < len(hexPart); i++ {
			if c := hexPart[i]; c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
				b.WriteByte(c)
			}
		}
		sec := b.String()
		if len(sec) < 32 {
			sec += strings.Repeat("a", 32)
		}
		if strings.Contains(prefix, sec) || strings.Contains(suffix, sec) {
			return
		}
		for _, in := range []string{prefix + "ee" + sec + suffix, prefix + "secret=" + sec + suffix} {
			out := String(in)
			if strings.Contains(out, sec[:32]) && !strings.Contains(prefix+suffix, sec[:32]) {
				t.Fatalf("mtproto secret leaked: in=%q out=%q", in, out)
			}
			if again := String(out); again != out {
				t.Fatalf("not idempotent: %q -> %q", out, again)
			}
		}
	})
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
