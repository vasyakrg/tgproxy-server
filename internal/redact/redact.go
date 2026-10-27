// Package redact masks Telegram bot tokens and tgproxy credentials in
// strings, URLs, errors and slog records.
package redact

import (
	"regexp"
	"strings"
)

const (
	minIDDigits  = 5
	minSecretLen = 30
	keyKeepLen   = 4
)

// keyRe matches client keys (tgp_<base62>) and enrollment tokens (enr_<base62>).
// A minimum body length keeps metric names such as tgp_requests_total intact.
var keyRe = regexp.MustCompile(`(?:tgp|enr)_[A-Za-z0-9]{16,}`)

// fakeTLSRe — FakeTLS/MTProto-секрет: префикс ee + hex-ключ (>=16 байт) + опциональный домен.
var fakeTLSRe = regexp.MustCompile(`ee[0-9a-fA-F]{32,}`)

// secretParamRe — параметр secret=<...> в tg://proxy, t.me/proxy и произвольных строках.
var secretParamRe = regexp.MustCompile(`(?i)secret=[^&\s"'<>]*`)

func isSecretChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

type span struct {
	start, end int
	id         string
}

// findTokens locates every `<digits>:<secret>` (also with url-encoded colon)
// occurrence. It scans separators instead of using a single regexp so that
// tokens glued to one another cannot hide each other.
func findTokens(s string) []span {
	var spans []span
	for i := 0; i < len(s); i++ {
		sepLen := 0
		switch {
		case s[i] == ':':
			sepLen = 1
		case s[i] == '%' && i+2 < len(s) && s[i+1] == '3' && (s[i+2] == 'A' || s[i+2] == 'a'):
			sepLen = 3
		default:
			continue
		}
		ds := i
		for ds > 0 && isDigit(s[ds-1]) {
			ds--
		}
		if i-ds < minIDDigits {
			continue
		}
		be := i + sepLen
		for be < len(s) && isSecretChar(s[be]) {
			be++
		}
		if be-(i+sepLen) < minSecretLen {
			continue
		}
		sp := span{start: ds, end: be, id: s[ds:i]}
		if n := len(spans); n > 0 && sp.start < spans[n-1].end {
			if sp.end > spans[n-1].end {
				spans[n-1].end = sp.end
			}
			continue
		}
		spans = append(spans, sp)
	}
	return spans
}

// String replaces every bot token in s with `<bot_id>:***` and masks client
// keys and enrollment tokens.
func String(s string) string {
	if s == "" {
		return s
	}
	if strings.Contains(strings.ToLower(s), "secret=") {
		s = secretParamRe.ReplaceAllString(s, "secret=***")
	}
	if spans := findTokens(s); len(spans) > 0 {
		var b strings.Builder
		last := 0
		for _, sp := range spans {
			b.WriteString(s[last:sp.start])
			b.WriteString(sp.id)
			b.WriteString(":***")
			last = sp.end
		}
		b.WriteString(s[last:])
		s = b.String()
	}
	if strings.Contains(s, "tgp_") || strings.Contains(s, "enr_") {
		s = keyRe.ReplaceAllStringFunc(s, func(m string) string {
			return m[:4+keyKeepLen] + "…"
		})
	}
	if strings.Contains(s, "ee") {
		s = fakeTLSRe.ReplaceAllStringFunc(s, func(m string) string {
			return m[:2+keyKeepLen] + "…"
		})
	}
	return s
}

// Token masks a single bot token: "123456:AAA..." -> "123456:***".
// Anything that is not a token yields "***".
func Token(s string) string {
	spans := findTokens(s)
	if len(spans) == 0 {
		return "***"
	}
	return spans[0].id + ":***"
}

type redactedError struct{ msg string }

func (e *redactedError) Error() string { return e.msg }

// Error returns err unchanged when its text is clean, otherwise an error with
// the redacted text. The error chain is intentionally dropped in the latter case.
func Error(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if red := String(msg); red != msg {
		return &redactedError{msg: red}
	}
	return err
}
