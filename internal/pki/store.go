package pki

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const (
	// caAAD — назначение шифртекста ключа CA при KEK.Seal/Open.
	caAAD = "pki:ca"

	// DefaultCATTL — срок жизни CA (10 лет).
	DefaultCATTL = 10 * 365 * 24 * time.Hour

	defaultCAName = "tgproxy CA"
)

// Options — параметры Authority; нулевые значения — по умолчанию.
type Options struct {
	CAName    string        // CN создаваемого CA
	CATTL     time.Duration // срок CA, по умолчанию 10 лет
	ServerTTL time.Duration // срок серверного сертификата, по умолчанию 90 дней
}

// Authority — CA сервера: сертификат в БД открыто, ключ зашифрован KEK.
// Безопасен для конкурентного использования.
type Authority struct {
	ca   *CA
	repo store.CertRepo
	opts Options

	mu     sync.Mutex
	server *tls.Certificate
	srvX   *x509.Certificate
}

// LoadOrInit загружает CA из БД; если его нет — создаёт (ECDSA P-256, 10 лет)
// и сохраняет с ключом, зашифрованным KEK (AAD "pki:ca"). Неверный KEK при
// существующем CA — ошибка расшифровки, CA не перезаписывается.
func LoadOrInit(ctx context.Context, repo store.CertRepo, kek *KEK, opts Options) (*Authority, error) {
	if repo == nil || kek == nil {
		return nil, errors.New("pki: repo and kek are required")
	}
	if opts.CAName == "" {
		opts.CAName = defaultCAName
	}
	if opts.CATTL <= 0 {
		opts.CATTL = DefaultCATTL
	}
	if opts.ServerTTL <= 0 {
		opts.ServerTTL = DefaultTTL
	}
	rec, err := repo.LoadCA(ctx)
	switch {
	case err == nil:
		keyPEM, oerr := kek.Open(rec.SealedKey, []byte(caAAD))
		if oerr != nil {
			return nil, fmt.Errorf("pki: decrypt CA key (wrong KEK?): %w", oerr)
		}
		defer clear(keyPEM)
		ca, lerr := LoadCA(rec.CertPEM, keyPEM)
		if lerr != nil {
			return nil, lerr
		}
		return &Authority{ca: ca, repo: repo, opts: opts}, nil
	case errors.Is(err, store.ErrNotFound):
	default:
		return nil, fmt.Errorf("pki: load CA: %w", err)
	}
	ca, err := NewCA(opts.CAName, opts.CATTL)
	if err != nil {
		return nil, err
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	sealed, err := kek.Seal(keyPEM, []byte(caAAD))
	if err != nil {
		return nil, fmt.Errorf("pki: seal CA key: %w", err)
	}
	if err := repo.SaveCA(ctx, store.CARecord{CertPEM: ca.CertPEM(), SealedKey: sealed, CreatedAt: nowFunc()}); err != nil {
		return nil, fmt.Errorf("pki: save CA: %w", err)
	}
	return &Authority{ca: ca, repo: repo, opts: opts}, nil
}

// CAFingerprint — SHA-256 отпечаток DER-сертификата CA в формате ssh:
// "SHA256:<base64 без паддинга>".
func (a *Authority) CAFingerprint() string { return Fingerprint(a.ca.cert) }

// Fingerprint возвращает отпечаток сертификата в формате "SHA256:<base64 raw>".
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Pool — пул доверия с CA.
func (a *Authority) Pool() *x509.CertPool { return a.ca.Pool() }

// CertPEM — сертификат CA в PEM (отдаётся агентам при enrollment).
func (a *Authority) CertPEM() []byte { return a.ca.CertPEM() }

// ServerCert возвращает серверный mTLS-сертификат (SAN spiffe://tgproxy/server,
// 90 дней). Выпускается лениво и кешируется в памяти (ключ не покидает
// процесс); после 2/3 срока перевыпускается. Пригоден для
// tls.Config.GetCertificate / GetClientCertificate.
func (a *Authority) ServerCert(_ context.Context) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.server != nil && !DueForRotation(a.srvX, nowFunc()) {
		return a.server, nil
	}
	b, err := IssueServerClient(a.ca, a.opts.ServerTTL)
	if err != nil {
		return nil, err
	}
	cert, err := b.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("pki: server keypair: %w", err)
	}
	x, err := parseCertPEM(b.CertPEM)
	if err != nil {
		return nil, err
	}
	a.server, a.srvX = &cert, x
	return a.server, nil
}
