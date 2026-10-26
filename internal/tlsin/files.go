package tlsin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
)

const (
	defaultPollInterval = 60 * time.Second
	defaultDebounce     = 250 * time.Millisecond
	expiringRepeat      = time.Hour
	// maxKeyPerm — самые широкие допустимые права ключа (0640 root:tgproxy).
	maxKeyPerm os.FileMode = 0o640
)

type fileSig struct {
	mod  [2]time.Time
	size [2]int64
}

type filesProvider struct {
	o        *options
	certFile string
	keyFile  string
	domains  []string

	cur atomic.Pointer[tls.Certificate]

	mu           sync.Mutex // защищает поля ниже и сериализует загрузки
	info         CertInfo
	sig          fileSig
	lastExpiring time.Time
}

func newFiles(cfg config.IngressTLS, o *options) (Provider, error) {
	p := &filesProvider{o: o, certFile: cfg.CertFile, keyFile: cfg.KeyFile, domains: cfg.Domains,
		info: CertInfo{Mode: string(config.TLSModeFiles)}}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sig = p.signature()
	cert, err := p.load()
	if err != nil {
		return nil, fmt.Errorf("tlsin: load ingress cert: %w", err)
	}
	p.accept(cert)
	return p, nil
}

// load читает и валидирует пару; ничего не меняет в состоянии.
func (p *filesProvider) load() (*tls.Certificate, error) {
	st, err := os.Stat(p.keyFile)
	if err != nil {
		return nil, redact.Error(err)
	}
	if perm := st.Mode().Perm(); perm&^maxKeyPerm != 0 {
		return nil, fmt.Errorf("key file %s has mode %04o, want at most %04o", p.keyFile, perm, maxKeyPerm)
	}
	cert, err := tls.LoadX509KeyPair(p.certFile, p.keyFile)
	if err != nil {
		return nil, redact.Error(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	cert.Leaf = leaf
	now := p.o.clock()
	switch {
	case now.Before(leaf.NotBefore):
		return nil, fmt.Errorf("certificate is not valid yet (not before %s)", leaf.NotBefore.UTC().Format(time.RFC3339))
	case !now.Before(leaf.NotAfter):
		return nil, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if err := checkChain(&cert); err != nil {
		return nil, err
	}
	for _, d := range p.domains {
		if err := leaf.VerifyHostname(d); err != nil {
			return nil, fmt.Errorf("certificate does not cover tls.domains entry: %w", err)
		}
	}
	return &cert, nil
}

// checkChain проверяет согласованность присланной цепочки: каждый сертификат
// подписан следующим. Корни не проверяются: корпоративный/частный УЦ не
// обязан быть в системном хранилище сервера.
func checkChain(c *tls.Certificate) error {
	prev := c.Leaf
	for i, der := range c.Certificate[1:] {
		next, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse chain[%d]: %w", i+1, err)
		}
		if err := prev.CheckSignatureFrom(next); err != nil {
			return fmt.Errorf("chain[%d] is not signed by chain[%d]: %w", i, i+1, err)
		}
		prev = next
	}
	return nil
}

// accept подменяет действующий сертификат. Вызывать под p.mu.
func (p *filesProvider) accept(c *tls.Certificate) {
	p.cur.Store(c)
	l := c.Leaf
	sans := append([]string(nil), l.DNSNames...)
	for _, ip := range l.IPAddresses {
		sans = append(sans, ip.String())
	}
	p.info = CertInfo{
		Mode: string(config.TLSModeFiles), Subject: l.Subject.String(), SANs: sans, Issuer: l.Issuer.String(),
		NotBefore: l.NotBefore, NotAfter: l.NotAfter, LastReload: p.o.clock(),
	}
	p.o.setNotAfter(l.NotAfter)
	p.o.logger.Info("ingress certificate loaded", "subject", p.info.Subject, "not_after", l.NotAfter.UTC().Format(time.RFC3339))
	p.o.emit(Event{Type: EventReloaded, NotAfter: l.NotAfter})
	p.lastExpiring = time.Time{}
	p.checkExpiring()
}

// checkExpiring шлёт EventExpiring, если срок меньше порога и событие
// не повторялось в последний час. Вызывать под p.mu.
func (p *filesProvider) checkExpiring() {
	c := p.cur.Load()
	if c == nil {
		return
	}
	now := p.o.clock()
	if c.Leaf.NotAfter.Sub(now) >= ExpiryWarn || (!p.lastExpiring.IsZero() && now.Sub(p.lastExpiring) < expiringRepeat) {
		return
	}
	p.lastExpiring = now
	p.o.emit(Event{Type: EventExpiring, NotAfter: c.Leaf.NotAfter})
}

// reloadLocked пробует загрузить новую пару; при ошибке остаётся старая.
func (p *filesProvider) reloadLocked() error {
	p.sig = p.signature()
	cert, err := p.load()
	if err != nil {
		p.info.LastError = err.Error()
		var na time.Time
		if c := p.cur.Load(); c != nil {
			na = c.Leaf.NotAfter
		}
		p.o.logger.Error("ingress certificate rejected, keeping previous", "error", err)
		p.o.emit(Event{Type: EventInvalid, NotAfter: na, Err: err})
		return err
	}
	p.accept(cert)
	return nil
}

// Reload перечитывает файлы безусловно.
func (p *filesProvider) Reload() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reloadLocked()
}

// poll перечитывает файлы, только если изменились mtime/размер (в том числе
// файл пропал/появился); неизменённая ошибка не повторяется каждую минуту.
func (p *filesProvider) poll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.signature() != p.sig {
		_ = p.reloadLocked()
	}
	p.checkExpiring()
}

// signature — mtime и размер cert/key; отсутствующий файл даёт нулевые значения.
func (p *filesProvider) signature() fileSig {
	var s fileSig
	for i, f := range []string{p.certFile, p.keyFile} {
		if st, err := os.Stat(f); err == nil {
			s.mod[i], s.size[i] = st.ModTime(), st.Size()
		}
	}
	return s
}

func (p *filesProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.cur.Load(), nil
}

func (p *filesProvider) Info() CertInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.info
	i.SANs = append([]string(nil), i.SANs...)
	return i
}

func (p *filesProvider) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: p.GetCertificate, MinVersion: tls.VersionTLS12}
}

// Run наблюдает за каталогами сертификата и ключа (fsnotify; каталог, а не
// файл — из-за атомарной подмены через mv/symlink) и раз в pollInterval
// сверяет mtime. События склеиваются debounce-таймером.
func (p *filesProvider) Run(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	var events <-chan fsnotify.Event
	var werrs <-chan error
	if err != nil {
		p.o.logger.Warn("fsnotify unavailable, using polling only", "error", err)
	} else {
		defer func() { _ = w.Close() }()
		for _, d := range uniqueDirs(p.certFile, p.keyFile) {
			if err := w.Add(d); err != nil {
				p.o.logger.Warn("cannot watch directory, relying on polling", "dir", d, "error", err)
			}
		}
		events, werrs = w.Events, w.Errors
	}
	tick := time.NewTicker(p.o.pollInterval)
	defer tick.Stop()
	deb := time.NewTimer(time.Hour)
	deb.Stop()
	defer deb.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if ev.Op != fsnotify.Chmod {
				deb.Reset(p.o.debounce)
			}
		case err, ok := <-werrs:
			if !ok {
				werrs = nil
				continue
			}
			p.o.logger.Warn("certificate watcher error", "error", err)
		case <-deb.C:
			p.poll()
		case <-tick.C:
			p.poll()
		}
	}
}

func uniqueDirs(files ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range files {
		d := filepath.Dir(f)
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}
