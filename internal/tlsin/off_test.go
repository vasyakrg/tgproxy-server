package tlsin

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

func TestOff(t *testing.T) {
	cfg := config.IngressTLS{Mode: config.TLSModeOff}
	if _, err := New(cfg); err == nil {
		t.Fatal("off without guard must fail")
	}
	if _, err := New(cfg, WithOffGuard(nil, ":8080")); err == nil {
		t.Fatal("off without trusted_proxies must fail")
	}
	if _, err := New(cfg, WithOffGuard(nil, "0.0.0.0:8080")); err == nil {
		t.Fatal("off on public listener without trusted_proxies must fail")
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for name, g := range map[string]Option{
		"trusted":  WithOffGuard(trusted, ":8080"),
		"loopback": WithOffGuard(nil, "127.0.0.1:8080"),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := New(cfg, g)
			if err != nil {
				t.Fatal(err)
			}
			if p.TLSConfig() != nil || p.Info().Mode != "off" || p.Reload() != nil {
				t.Fatal("off provider must be inert")
			}
			if c, err := p.GetCertificate(nil); err == nil || c != nil {
				t.Fatal("off provider has no certificate")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := p.Run(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnknownMode(t *testing.T) {
	if _, err := New(config.IngressTLS{Mode: "bogus"}); err == nil {
		t.Fatal("want error")
	}
}

func TestWithLogger(t *testing.T) {
	var o options
	WithLogger(slog.New(slog.DiscardHandler))(&o)
	if o.logger == nil {
		t.Fatal("logger not set")
	}
}
