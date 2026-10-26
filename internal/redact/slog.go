package redact

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
)

type handler struct{ next slog.Handler }

// NewHandler wraps h so that every message, string attribute, error,
// group member, LogValuer result and arbitrary value is redacted first.
func NewHandler(h slog.Handler) slog.Handler { return &handler{next: h} }

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, String(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(attr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = attr(a)
	}
	return &handler{next: h.next.WithAttrs(out)}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(name)}
}

func attr(a slog.Attr) slog.Attr {
	a.Value = value(a.Value)
	return a
}

func value(v slog.Value) slog.Value {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(String(v.String()))
	case slog.KindGroup:
		g := v.Group()
		out := make([]slog.Attr, len(g))
		for i, a := range g {
			out[i] = attr(a)
		}
		return slog.GroupValue(out...)
	case slog.KindAny:
		return anyValue(v)
	default:
		return v
	}
}

func anyValue(v slog.Value) slog.Value {
	x := v.Any()
	switch t := x.(type) {
	case nil:
		return v
	case error:
		if red := Error(t); red != t {
			return slog.AnyValue(red)
		}
		return v
	case *url.URL:
		return slog.StringValue(URL(t))
	case []byte:
		return slog.StringValue(String(string(t)))
	}
	// Unknown shape: render it the way a handler would and keep the original
	// value only if rendering shows nothing to hide.
	s := fmt.Sprintf("%+v", x)
	if red := String(s); red != s {
		return slog.StringValue(red)
	}
	return v
}
