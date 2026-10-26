// Package app — wiring процессов server и agent: логирование, транспорт до
// агентов, HTTP-листенеры, сигналы.
package app

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
)

// ParseLevel разбирает уровень логирования debug|info|warn|error.
func ParseLevel(s string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(s)))); err != nil {
		return 0, fmt.Errorf("app: bad log level %q", s)
	}
	return l, nil
}

// NewLogger строит slog.Logger по cfg: формат json|text, уровень через
// возвращаемый LevelVar (для SIGHUP). Handler всегда обёрнут redact.NewHandler.
// w == nil -> stdout.
func NewLogger(cfg config.LoggingConfig, w io.Writer) (*slog.Logger, *slog.LevelVar, error) {
	if w == nil {
		w = os.Stdout
	}
	lvl, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}
	lv := new(slog.LevelVar)
	lv.Set(lvl)
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "json", "":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, nil, fmt.Errorf("app: bad log format %q", cfg.Format)
	}
	return slog.New(redact.NewHandler(h)), lv, nil
}
