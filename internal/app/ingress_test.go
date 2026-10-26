package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/metrics"
)

func writeIngressPair(t *testing.T, dir string, serial int64) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "ing.test"}, DNSNames: []string{"ing.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	cf, kf := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cf, kf
}

func TestIngressFilesWiring(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cf, kf := writeIngressPair(t, t.TempDir(), 1)
	cfg := &config.ServerConfig{TLS: config.IngressTLS{Mode: config.TLSModeFiles, CertFile: cf, KeyFile: kf}}
	var err error
	if s.ingress, err = s.newIngress(cfg); err != nil {
		t.Fatal(err)
	}
	if s.ingressTLSConfig() == nil {
		t.Fatal("tls config expected for files")
	}
	// obs ещё нет: события не паникуют; после появления obs состояние публикуется
	s.reportIngress(context.Background())
	s.obs = &obs{}
	s.obs.reg, s.obs.m = metrics.NewServerRegistry()
	s.reportIngress(context.Background()) // eval == nil — только метрика
	s.reloadIngress()
	// битый файл: SIGHUP-путь не паникует, прежний сертификат остаётся
	_ = os.WriteFile(cf, []byte("broken"), 0o644)
	s.reloadIngress()
	if s.ingress.Info().LastError == "" || s.ingress.Info().Subject == "" {
		t.Fatalf("info: %+v", s.ingress.Info())
	}
}

func TestIngressOffRequiresTrusted(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cfg := &config.ServerConfig{Listen: config.ServerListen{Proxy: ":8080"}}
	if _, err := s.newIngress(cfg); err == nil {
		t.Fatal("off on public listener without trusted_proxies must fail")
	}
	cfg.Listen.Proxy = "127.0.0.1:8080"
	p, err := s.newIngress(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.ingress = p
	if s.ingressTLSConfig() != nil {
		t.Fatal("no tls for off")
	}
	s.reportIngress(context.Background())
}

func TestIngressACMEHTTP01Listener(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	cfg := &config.ServerConfig{TLS: config.IngressTLS{
		Mode: config.TLSModeACME, Domains: []string{"ing.test"}, CacheDir: filepath.Join(t.TempDir(), "acme"),
		ACME: config.ACMEConfig{DirectoryURL: "https://127.0.0.1:1/dir", HTTP01Listen: addr},
	}}
	if s.ingress, err = s.newIngress(cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	wait := s.runIngress(ctx)
	var resp *http.Response
	for range 100 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/.well-known/acme-challenge/none", nil)
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	// чужой Host отсекается HostPolicy autocert
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cancel()
	wait()

	// занятый порт: ошибка логируется, работа продолжается
	busy, _ := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	defer func() { _ = busy.Close() }()
	s.http01Addr = busy.Addr().String()
	ctx2, cancel2 := context.WithCancel(context.Background())
	wait2 := s.runIngress(ctx2)
	cancel2()
	wait2()
}
