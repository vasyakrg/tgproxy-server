package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

const (
	// DefaultTTL — срок листовых сертификатов по умолчанию.
	DefaultTTL = 90 * 24 * time.Hour

	spiffeScheme = "spiffe"
	spiffeHost   = "tgproxy"
	agentPrefix  = "/agent/"
	serverPath   = "/server"

	// ServerDNSName — DNS SAN серверного сертификата.
	ServerDNSName = "tgproxy-server"
)

var agentIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ServerURI возвращает SAN URI сервера.
func ServerURI() *url.URL { return &url.URL{Scheme: spiffeScheme, Host: spiffeHost, Path: serverPath} }

// AgentURI возвращает SAN URI агента.
func AgentURI(agentID string) *url.URL {
	return &url.URL{Scheme: spiffeScheme, Host: spiffeHost, Path: agentPrefix + agentID}
}

// ValidAgentID проверяет формат идентификатора агента.
func ValidAgentID(id string) bool { return agentIDRe.MatchString(id) }

// Bundle — выпущенный сертификат с ключом.
type Bundle struct {
	CertPEM []byte
	KeyPEM  []byte
}

// TLSCertificate собирает tls.Certificate.
func (b Bundle) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(b.CertPEM, b.KeyPEM)
}

func newKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate key: %w", err)
	}
	return k, nil
}

// sign выпускает листовой сертификат; CN/SAN целиком задаёт вызывающий.
func (c *CA) sign(pub *ecdsa.PublicKey, cn string, dns []string, uri *url.URL, ttl time.Duration) ([]byte, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := nowFunc()
	notAfter := now.Add(ttl)
	if notAfter.After(c.cert.NotAfter) {
		return nil, errors.New("pki: requested ttl exceeds CA validity")
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"tgproxy"}},
		NotBefore:             now.Add(-skew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemCert, Bytes: der}), nil
}

// IssueServerClient выпускает сертификат сервера (ключ генерируется здесь).
// EKU ServerAuth+ClientAuth: сервер — TLS-клиент в dial и TLS-сервер в
// reverse/agent_gateway. ttl<=0 → DefaultTTL.
func IssueServerClient(ca *CA, ttl time.Duration) (Bundle, error) {
	key, err := newKey()
	if err != nil {
		return Bundle{}, err
	}
	certPEM, err := ca.sign(&key.PublicKey, "tgproxy-server", []string{ServerDNSName}, ServerURI(), ttl)
	if err != nil {
		return Bundle{}, err
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// NewAgentCSR генерирует на агенте ключ и CSR. Содержимое subject/SAN в CSR
// информационное: сервер его игнорирует.
func NewAgentCSR(agentID string) (csrPEM, keyPEM []byte, err error) {
	if !ValidAgentID(agentID) {
		return nil, nil, fmt.Errorf("pki: invalid agent id %q", agentID)
	}
	key, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agent/" + agentID},
		URIs:    []*url.URL{AgentURI(agentID)},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create csr: %w", err)
	}
	keyPEM, err = marshalKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: der}), keyPEM, nil
}

// IssueAgent подписывает CSR агента: проверяет подпись CSR и тип ключа
// (ECDSA P-256), игнорирует CN/SAN/расширения из CSR и выставляет свои:
// URI spiffe://tgproxy/agent/<id>, EKU ServerAuth+ClientAuth. ttl<=0 → 90 дней.
func IssueAgent(ca *CA, csrPEM []byte, agentID string, ttl time.Duration) ([]byte, error) {
	if !ValidAgentID(agentID) {
		return nil, fmt.Errorf("pki: invalid agent id %q", agentID)
	}
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != pemCSR {
		return nil, errors.New("pki: no CSR in PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: csr signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("pki: csr key is not ECDSA P-256")
	}
	return ca.sign(pub, "agent/"+agentID, nil, AgentURI(agentID), ttl)
}
