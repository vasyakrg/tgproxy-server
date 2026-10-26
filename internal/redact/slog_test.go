package redact_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
)

type valuer struct{}

func (valuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("tok", tok), slog.Any("err", errors.New("fail "+tok)))
}

type stringer struct{}

func (stringer) String() string { return "s=" + tok }

type plainStruct struct{ T string }

func newLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(redact.NewHandler(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

func TestHandlerNeverLeaks(t *testing.T) {
	u, _ := url.Parse("https://api.telegram.org/bot" + tok + "/getMe")
	uerr := &url.Error{Op: "Get", URL: u.String(), Err: errors.New("boom")}
	var buf bytes.Buffer
	l := newLogger(&buf).With("pre", tok).WithGroup("g").With(slog.String("inner", tok))
	l.Info("msg "+tok,
		"str", tok,
		"err", uerr,
		"wrapped", fmt.Errorf("wrap: %w", uerr),
		"url", u,
		"valuer", valuer{},
		"stringer", stringer{},
		"struct", plainStruct{T: tok},
		"bytes", []byte(tok),
		"ptr", &plainStruct{T: tok},
		"strs", []string{tok},
		slog.Group("grp", slog.Group("deep", slog.String("t", tok), slog.Any("e", uerr))),
		"num", 5, "ok", true,
	)
	out := buf.String()
	if strings.Contains(out, body) {
		t.Fatalf("leak: %s", out)
	}
	if !strings.Contains(out, "num=5") || !strings.Contains(out, botID+":***") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestHandlerKeepsNonSecrets(t *testing.T) {
	var buf bytes.Buffer
	newLogger(&buf).Info("hello", "n", 1, "d", struct{ A int }{3}, "e", errors.New("plain"))
	out := buf.String()
	for _, w := range []string{"hello", "n=1", "A:3", "e=plain"} {
		if !strings.Contains(out, w) {
			t.Fatalf("missing %q in %s", w, out)
		}
	}
}

func TestHandlerEnabledAndLevel(t *testing.T) {
	var buf bytes.Buffer
	h := redact.NewHandler(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if h.Enabled(context.Background(), slog.LevelInfo) || !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("Enabled must delegate")
	}
}

func TestHandlerNilPointerSafe(_ *testing.T) {
	var buf bytes.Buffer
	var p *plainStruct
	newLogger(&buf).Info("x", "p", p)
}
