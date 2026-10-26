package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	pemCert = "CERTIFICATE"
	pemKey  = "PRIVATE KEY"
	pemCSR  = "CERTIFICATE REQUEST"

	// skew — допуск рассинхронизации часов для NotBefore.
	skew = 5 * time.Minute
)

// nowFunc подменяется в тестах.
var nowFunc = time.Now

// CA — самоподписанный удостоверяющий центр (ECDSA P-256).
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// NewCA создаёт самоподписанный CA с CN=cn и сроком ttl.
func NewCA(cn string, ttl time.Duration) (*CA, error) {
	if cn == "" {
		return nil, errors.New("pki: empty CA common name")
	}
	if ttl <= 0 {
		return nil, errors.New("pki: CA ttl must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := nowFunc()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"tgproxy"}},
		NotBefore:             now.Add(-skew),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA cert: %w", err)
	}
	return &CA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: pemCert, Bytes: der})}, nil
}

// LoadCA загружает CA из PEM (ключ PKCS#8, уже расшифрованный).
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("pki: certificate is not a CA")
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("pki: CA key does not match certificate")
	}
	return &CA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: pemCert, Bytes: cert.Raw})}, nil
}

// Cert возвращает сертификат CA.
func (c *CA) Cert() *x509.Certificate { return c.cert }

// CertPEM возвращает сертификат CA в PEM.
func (c *CA) CertPEM() []byte { return append([]byte(nil), c.certPEM...) }

// KeyPEM возвращает приватный ключ CA (PKCS#8 PEM). Хранить только 0600.
func (c *CA) KeyPEM() ([]byte, error) { return marshalKey(c.key) }

// Pool возвращает пул доверия с этим CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// PoolFromPEM строит пул доверия из PEM (для агента: ca.crt).
func PoolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	cert, err := parseCertPEM(caPEM)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	p.AddCert(cert)
	return p, nil
}

func newSerial() (*big.Int, error) {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	return s, nil
}

func marshalKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemKey, Bytes: der}), nil
}

func parseKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemKey {
		return nil, errors.New("pki: no PKCS#8 private key in PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("pki: key is not ECDSA P-256")
	}
	return ek, nil
}

func parseCertPEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemCert {
		return nil, errors.New("pki: no certificate in PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate: %w", err)
	}
	return c, nil
}
