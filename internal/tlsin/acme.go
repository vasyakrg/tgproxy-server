package tlsin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

const (
	acmeRefreshOK    = time.Hour
	acmeRefreshRetry = 10 * time.Minute
	acmeCacheMode    = 0o700
)

type acmeProvider struct {
	o       *options
	mgr     *autocert.Manager
	domains []string

	mu           sync.Mutex
	info         CertInfo
	seen         map[string]struct{}
	lastErr      string
	lastExpiring time.Time
	cur          *x509.Certificate
}

func newACME(cfg config.IngressTLS, o *options) (Provider, error) {
	if len(cfg.Domains) == 0 {
		return nil, errors.New("tlsin: tls.domains required for acme")
	}
	if cfg.CacheDir == "" {
		return nil, errors.New("tlsin: tls.cache_dir required for acme")
	}
	if cfg.ACME.ViaAgentEgress && o.client == nil {
		return nil, errors.New("tlsin: tls.acme.via_agent_egress requires an HTTP client (WithHTTPClient)")
	}
	if err := os.MkdirAll(cfg.CacheDir, acmeCacheMode); err != nil {
		return nil, fmt.Errorf("tlsin: acme cache dir: %w", err)
	}
	// В кеше лежит ключ аккаунта и ключи сертификатов.
	if st, err := os.Stat(cfg.CacheDir); err != nil {
		return nil, fmt.Errorf("tlsin: acme cache dir: %w", err)
	} else if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("tlsin: acme cache dir %s has mode %04o, want 0700", cfg.CacheDir, st.Mode().Perm())
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cfg.CacheDir),
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.ACME.Email,
	}
	if cfg.ACME.DirectoryURL != "" || o.client != nil {
		dir := cfg.ACME.DirectoryURL
		if dir == "" {
			dir = autocert.DefaultACMEDirectory
		}
		m.Client = &acme.Client{DirectoryURL: dir, HTTPClient: o.client}
	}
	return &acmeProvider{
		o: o, mgr: m, domains: slices.Clone(cfg.Domains), seen: map[string]struct{}{},
		info: CertInfo{Mode: string(config.TLSModeACME)},
	}, nil
}

// isALPNChallenge — запрос CA по TLS-ALPN-01 (отдаётся одноразовый сертификат).
func isALPNChallenge(h *tls.ClientHelloInfo) bool {
	return len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == acme.ALPNProto
}

func (p *acmeProvider) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := p.mgr.GetCertificate(h)
	switch {
	case isALPNChallenge(h):
	case err != nil:
		p.failed(h.ServerName, err)
	default:
		p.observe(cert)
	}
	return cert, err
}

// failed фиксирует ошибку выпуска только для своих доменов (чужие SNI от
// сканеров отсекает HostPolicy и не должны давать алерт).
func (p *acmeProvider) failed(host string, err error) {
	if !slices.ContainsFunc(p.domains, func(d string) bool { return strings.EqualFold(d, strings.TrimSuffix(host, ".")) }) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastErr == err.Error() {
		return
	}
	p.lastErr = err.Error()
	p.info.LastError = p.lastErr
	var na time.Time
	if p.cur != nil {
		na = p.cur.NotAfter
	}
	p.o.logger.Error("acme certificate not obtained", "host", host, "error", err)
	p.o.emit(Event{Type: EventInvalid, NotAfter: na, Err: err})
}

// observe обновляет Info по выданному сертификату; новый серийник — событие reloaded.
func (p *acmeProvider) observe(c *tls.Certificate) {
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	serial := leaf.SerialNumber.String()
	if _, seen := p.seen[serial]; !seen {
		p.seen[serial] = struct{}{}
		p.lastErr = ""
		// Info — по последнему выданному (по NotBefore) сертификату.
		if p.cur == nil || !leaf.NotBefore.Before(p.cur.NotBefore) {
			p.cur = leaf
			p.info = CertInfo{
				Mode: string(config.TLSModeACME), Subject: leaf.Subject.String(), SANs: slices.Clone(leaf.DNSNames),
				Issuer: leaf.Issuer.String(), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, LastReload: p.o.clock(),
			}
			p.lastExpiring = time.Time{}
		}
		p.o.setNotAfter(leaf.NotAfter)
		p.o.logger.Info("acme certificate in use", "subject", leaf.Subject.String(), "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
		p.o.emit(Event{Type: EventReloaded, NotAfter: leaf.NotAfter})
	}
	p.checkExpiringLocked()
}

func (p *acmeProvider) checkExpiringLocked() {
	if p.cur == nil {
		return
	}
	now := p.o.clock()
	if p.cur.NotAfter.Sub(now) >= ExpiryWarn || (!p.lastExpiring.IsZero() && now.Sub(p.lastExpiring) < expiringRepeat) {
		return
	}
	p.lastExpiring = now
	p.o.emit(Event{Type: EventExpiring, NotAfter: p.cur.NotAfter})
}

func (p *acmeProvider) Info() CertInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.info
	i.SANs = slices.Clone(i.SANs)
	return i
}

func (p *acmeProvider) TLSConfig() *tls.Config {
	c := p.mgr.TLSConfig() // NextProtos: h2, http/1.1, acme-tls/1 (TLS-ALPN-01)
	c.GetCertificate = p.GetCertificate
	c.MinVersion = tls.VersionTLS12
	return c
}

// HTTPHandler — обработчик HTTP-01 для :80.
func (p *acmeProvider) HTTPHandler(fallback http.Handler) http.Handler {
	return p.mgr.HTTPHandler(fallback)
}

// Reload для acme — no-op: продлением управляет autocert.
func (p *acmeProvider) Reload() error { return nil }

// refresh запрашивает сертификат для каждого домена (из кеша либо выпуск) и
// проверяет срок. Возвращает первую ошибку.
func (p *acmeProvider) refresh() error {
	var errs []error
	for _, d := range p.domains {
		h := &tls.ClientHelloInfo{
			ServerName:   d,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, // autocert: ECDSA-ключ
		}
		if _, err := p.GetCertificate(h); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d, err))
		}
	}
	p.mu.Lock()
	p.checkExpiringLocked()
	p.mu.Unlock()
	return errors.Join(errs...)
}

// Run сразу получает/загружает сертификаты, затем раз в час проверяет срок
// (при ошибке — повтор через 10 минут). Продление выполняет сам autocert.
func (p *acmeProvider) Run(ctx context.Context) error {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			next := acmeRefreshOK
			if err := p.refresh(); err != nil {
				p.o.logger.Warn("acme refresh failed", "error", err)
				next = acmeRefreshRetry
			}
			t.Reset(next)
		}
	}
}
