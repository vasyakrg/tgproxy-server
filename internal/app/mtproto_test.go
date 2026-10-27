package app

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

func TestSanMatches(t *testing.T) {
	cases := []struct {
		sans []string
		host string
		want bool
	}{
		{[]string{"tg.example.com"}, "tg.example.com", true},
		{[]string{"TG.example.com"}, "tg.Example.com.", true},
		{[]string{"*.example.com"}, "tg.example.com", true},
		{[]string{"*.example.com"}, "a.b.example.com", false},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"other.test"}, "tg.example.com", false},
		{nil, "tg.example.com", false},
	}
	for _, c := range cases {
		if got := sanMatches(c.sans, c.host); got != c.want {
			t.Errorf("sanMatches(%v, %q) = %v, want %v", c.sans, c.host, got, c.want)
		}
	}
}

// mtprotoServerConfig — конфиг с TLS files (SAN ing.test) и включённым MTProto.
func mtprotoServerConfig(t *testing.T, domain, listen string) *config.ServerConfig {
	t.Helper()
	dir := t.TempDir()
	cf, kf := writeIngressPair(t, dir, 1)
	pkiDir := t.TempDir()
	if err := pki.DevInit(pkiDir, []string{"local"}); err != nil {
		t.Fatal(err)
	}
	kek := filepath.Join(dir, "kek")
	if err := pki.GenerateKEK(kek); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultServer()
	cfg.TLS = config.IngressTLS{Mode: config.TLSModeFiles, CertFile: cf, KeyFile: kf}
	cfg.AgentTLS = config.TLSFiles{
		CertFile: filepath.Join(pkiDir, pki.FileServerCert),
		KeyFile:  filepath.Join(pkiDir, pki.FileServerKey),
		CAFile:   filepath.Join(pkiDir, pki.FileCACert),
	}
	cfg.PKI.KEKFile = kek
	cfg.Store.SQLitePath = filepath.Join(dir, "tgproxy.db")
	cfg.Buffer.TmpDir = t.TempDir()
	cfg.Listen.Metrics = ""
	cfg.Auth.UsersFile = "" // веб-UI не нужен
	cfg.MTProto.Enabled = true
	cfg.MTProto.Listen = listen
	cfg.MTProto.FrontingDomain = domain
	return cfg
}

func TestMTProtoFrontingDomainNotInSAN(t *testing.T) {
	cfg := mtprotoServerConfig(t, "tg.other.test", config.MTProtoListenShared)
	s, err := NewServer(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		s.Close()
		t.Fatal("fronting_domain вне SAN должен отвергаться при старте")
	}
	if !errors.Is(err, errFrontingDomain) {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
}

func TestMTProtoDisabledNotWrapped(t *testing.T) {
	cfg := mtprotoServerConfig(t, "ing.test", config.MTProtoListenShared)
	cfg.MTProto.Enabled = false
	s, err := NewServer(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.mt != nil {
		t.Fatal("при enabled=false MTProto-обвязка не создаётся")
	}
}

func tlsGet(t *testing.T, addr string) (string, int) {
	t.Helper()
	cl := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "ing.test"}}, //nolint:gosec // тестовый самоподписанный сертификат
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.TLS.PeerCertificates[0].Subject.CommonName, resp.StatusCode
}

func runMTProtoServer(t *testing.T, mode string) (proxyAddr, dedAddr string) {
	t.Helper()
	cfg := mtprotoServerConfig(t, "ing.test", mode)
	proxyLn, adminLn := listen(t), listen(t)
	opts := ServerOptions{ProxyListener: proxyLn}
	if mode != config.MTProtoListenShared {
		dl := listen(t)
		opts.MTProtoListener = dl
		dedAddr = dl.Addr().String()
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := NewServer(context.Background(), cfg, logger, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx, proxyLn, adminLn); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("Serve не завершился")
		}
	})
	return proxyLn.Addr().String(), dedAddr
}

func TestMTProtoSharedServesTLS(t *testing.T) {
	proxy, _ := runMTProtoServer(t, config.MTProtoListenShared)
	cn, _ := tlsGet(t, proxy)
	if cn != "ing.test" {
		t.Fatalf("cn = %q", cn)
	}
}

func TestMTProtoDedicatedServesTLSStub(t *testing.T) {
	proxy, ded := runMTProtoServer(t, "127.0.0.1:0")
	cn, code := tlsGet(t, ded)
	if cn != "ing.test" || code != http.StatusNotFound {
		t.Fatalf("dedicated: cn=%q code=%d", cn, code)
	}
	// основной листенер прокси не обёрнут: обычный TLS
	if cn, _ := tlsGet(t, proxy); cn != "ing.test" {
		t.Fatalf("proxy cn = %q", cn)
	}
}
