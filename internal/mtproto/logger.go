package mtproto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/9seconds/mtg/v2/mtglib"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
)

// fakeTLSSecretRe — полный секрет в виде ссылки/hex: ee + ключ (+ домен).
var fakeTLSSecretRe = regexp.MustCompile(`(?i)ee[0-9a-f]{32,}`)

// secretMasker прячет ключ инстанса во всех известных представлениях и
// отдаёт строку через redact.
type secretMasker struct{ forms []string }

func newSecretMasker(key [16]byte) secretMasker {
	raw := key[:]
	h := hex.EncodeToString(raw)
	return secretMasker{forms: []string{
		h,
		strings.ToUpper(h),
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	}}
}

func (m secretMasker) mask(s string) string {
	s = fakeTLSSecretRe.ReplaceAllString(s, "ee…")
	for _, f := range m.forms {
		s = strings.ReplaceAll(s, f, "***")
	}
	return redact.String(s)
}

// mtgLogger адаптирует slog к mtglib.Logger. Уровни mtg смещены вниз: Info
// (по строке на каждое соединение) пишется как Debug, Warning — как Warn.
type mtgLogger struct {
	l      *slog.Logger
	masker secretMasker
	name   string
	attrs  []slog.Attr
}

func newMTGLogger(l *slog.Logger, key [16]byte) mtglib.Logger {
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	return mtgLogger{l: l, masker: newSecretMasker(key), name: "mtg"}
}

func (g mtgLogger) with(a slog.Attr) mtgLogger {
	g.attrs = append(append([]slog.Attr(nil), g.attrs...), a)
	return g
}

func (g mtgLogger) Named(name string) mtglib.Logger {
	g.name += "/" + g.masker.mask(name)
	return g
}

func (g mtgLogger) BindInt(name string, v int) mtglib.Logger {
	return g.with(slog.Int(name, v))
}

func (g mtgLogger) BindStr(name, v string) mtglib.Logger {
	return g.with(slog.String(name, g.masker.mask(v)))
}

func (g mtgLogger) BindJSON(name, v string) mtglib.Logger {
	return g.with(slog.String(name, g.masker.mask(v)))
}

func (g mtgLogger) emit(level slog.Level, msg string, err error) {
	ctx := context.Background()
	if !g.l.Enabled(ctx, level) {
		return
	}
	attrs := make([]slog.Attr, 0, len(g.attrs)+2)
	attrs = append(attrs, slog.String("component", g.name))
	attrs = append(attrs, g.attrs...)
	if err != nil {
		attrs = append(attrs, slog.String("error", g.masker.mask(err.Error())))
	}
	g.l.LogAttrs(ctx, level, g.masker.mask(msg), attrs...)
}

func (g mtgLogger) Printf(format string, args ...any) {
	g.emit(slog.LevelDebug, fmt.Sprintf(format, args...), nil)
}
func (g mtgLogger) Info(msg string)                  { g.emit(slog.LevelDebug, msg, nil) }
func (g mtgLogger) InfoError(msg string, err error)  { g.emit(slog.LevelDebug, msg, err) }
func (g mtgLogger) Warning(msg string)               { g.emit(slog.LevelWarn, msg, nil) }
func (g mtgLogger) WarningError(msg string, e error) { g.emit(slog.LevelWarn, msg, e) }
func (g mtgLogger) Debug(msg string)                 { g.emit(slog.LevelDebug, msg, nil) }
func (g mtgLogger) DebugError(msg string, e error)   { g.emit(slog.LevelDebug, msg, e) }
