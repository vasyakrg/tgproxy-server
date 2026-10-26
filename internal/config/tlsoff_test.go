package config

import (
	"net/netip"
	"testing"
)

func TestCheckTLSOff(t *testing.T) {
	tp := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if CheckTLSOff(nil, ":8080") == "" || CheckTLSOff(nil, "0.0.0.0:8080") == "" {
		t.Fatal("public listener without trusted_proxies must be rejected")
	}
	if CheckTLSOff(tp, ":8080") != "" || CheckTLSOff(nil, "127.0.0.1:8080") != "" {
		t.Fatal("trusted_proxies or loopback must be accepted")
	}
}

func TestACMEHTTP01ListenValidation(t *testing.T) {
	c := DefaultServer()
	c.Listen.Metrics = "127.0.0.1:9090"
	c.TLS = IngressTLS{Mode: TLSModeACME, Domains: []string{"a.test"}, CacheDir: "/tmp/x", ACME: ACMEConfig{HTTP01Listen: "bad"}}
	if err := ValidateServer(c); err == nil {
		t.Fatal("bad http01_listen must be rejected")
	}
	c.TLS.ACME.HTTP01Listen = ":80"
	if err := ValidateServer(c); err != nil {
		t.Fatalf("valid: %v", err)
	}
}
