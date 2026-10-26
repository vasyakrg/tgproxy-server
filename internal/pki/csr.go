package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

// SerialString — каноническая запись серийника (hex, нижний регистр) для
// CertRepo и denylist.
func SerialString(cert *x509.Certificate) string { return cert.SerialNumber.Text(16) }

// SignAgentCSR подписывает CSR агента. Требования: валидная подпись CSR,
// ключ только ECDSA P-256, в CSR нет BasicConstraints (запрос CA:true/false
// отклоняется). Subject и SAN из CSR игнорируются: сервер выставляет только
// URI spiffe://tgproxy/agent/<id>. EKU clientAuth+serverAuth, KU
// digitalSignature. ttl<=0 → 90 дней; больше 90 дней — отказ. Серийник, срок
// и agent_id записываются в CertRepo.
func (a *Authority) SignAgentCSR(ctx context.Context, csrPEM []byte, agentID string, ttl time.Duration) (certPEM []byte, serial string, err error) {
	if !ValidAgentID(agentID) {
		return nil, "", fmt.Errorf("pki: invalid agent id %q", agentID)
	}
	if ttl > DefaultTTL {
		return nil, "", fmt.Errorf("pki: ttl %s exceeds maximum %s", ttl, DefaultTTL)
	}
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != pemCSR {
		return nil, "", errors.New("pki: no CSR in PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("pki: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("pki: csr signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", errors.New("pki: csr key is not ECDSA P-256")
	}
	for _, e := range csr.Extensions {
		if e.Id.Equal(oidBasicConstraints) {
			return nil, "", errors.New("pki: csr must not request basic constraints (CA)")
		}
	}
	certPEM, err = a.ca.sign(pub, "agent/"+agentID, nil, AgentURI(agentID), ttl)
	if err != nil {
		return nil, "", err
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, "", err
	}
	serial = SerialString(cert)
	rec := store.CertRecord{
		Serial: serial, AgentID: agentID, Subject: AgentURI(agentID).String(),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, CertPEM: certPEM, CreatedAt: nowFunc(),
	}
	if err := a.repo.Put(ctx, rec); err != nil {
		return nil, "", fmt.Errorf("pki: record certificate: %w", err)
	}
	return certPEM, serial, nil
}

// normalizeSerial нормализует пользовательский ввод серийника.
func normalizeSerial(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
}
