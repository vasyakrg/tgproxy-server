package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// Check — дополнительная проверка листа (точка расширения: denylist
// серийников, M5). Ошибка отклоняет соединение.
type Check func(leaf *x509.Certificate) error

// AgentIDFromCert извлекает id агента из URI SAN spiffe://tgproxy/agent/<id>.
func AgentIDFromCert(cert *x509.Certificate) (string, error) {
	var id string
	for _, u := range cert.URIs {
		if u.Scheme != spiffeScheme || u.Host != spiffeHost || !strings.HasPrefix(u.Path, agentPrefix) {
			continue
		}
		if id != "" {
			return "", errors.New("pki: multiple agent SANs")
		}
		id = strings.TrimPrefix(u.Path, agentPrefix)
	}
	if id == "" || !ValidAgentID(id) {
		return "", errors.New("pki: no valid agent SAN")
	}
	return id, nil
}

func isServerCert(cert *x509.Certificate) bool {
	for _, u := range cert.URIs {
		if u.Scheme == spiffeScheme && u.Host == spiffeHost && u.Path == serverPath {
			return true
		}
	}
	return false
}

// verifyChain проверяет цепочку листа к пулу ca. Hostname не проверяется
// (идентичность — URI SAN), EKU: сертификат обязан быть пригоден как
// ServerAuth или ClientAuth (роль зависит от направления соединения).
func verifyChain(cs tls.ConnectionState, ca *x509.CertPool) (*x509.Certificate, error) {
	if ca == nil {
		return nil, errors.New("pki: nil CA pool")
	}
	if len(cs.PeerCertificates) == 0 {
		return nil, errors.New("pki: no peer certificate")
	}
	leaf := cs.PeerCertificates[0]
	if leaf.IsCA {
		return nil, errors.New("pki: peer certificate is a CA")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	var lastErr error
	for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         ca,
			Intermediates: inter,
			CurrentTime:   nowFunc(),
			KeyUsages:     []x509.ExtKeyUsage{eku},
		})
		if err == nil {
			return leaf, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("pki: verify peer chain: %w", lastErr)
}

func runChecks(leaf *x509.Certificate, checks []Check) error {
	for _, c := range checks {
		if err := c(leaf); err != nil {
			return fmt.Errorf("pki: peer rejected: %w", err)
		}
	}
	return nil
}

// VerifyAgentPeer — для tls.Config.VerifyConnection: пир обязан быть агентом
// agentID с цепочкой к ca.
func VerifyAgentPeer(ca *x509.CertPool, agentID string, checks ...Check) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		leaf, err := verifyChain(cs, ca)
		if err != nil {
			return err
		}
		got, err := AgentIDFromCert(leaf)
		if err != nil {
			return err
		}
		if got != agentID {
			return fmt.Errorf("pki: unexpected agent %q", got)
		}
		return runChecks(leaf, checks)
	}
}

// VerifyServerPeer — для tls.Config.VerifyConnection: пир обязан быть
// сервером tgproxy (SAN spiffe://tgproxy/server) с цепочкой к ca.
func VerifyServerPeer(ca *x509.CertPool, checks ...Check) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		leaf, err := verifyChain(cs, ca)
		if err != nil {
			return err
		}
		if !isServerCert(leaf) {
			return errors.New("pki: peer is not tgproxy-server")
		}
		return runChecks(leaf, checks)
	}
}
