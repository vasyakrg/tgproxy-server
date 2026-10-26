package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

// certHolder хранит действующий сертификат агента и отдаёт его новым
// TLS-рукопожатиям (GetCertificate / GetClientCertificate). Установленные
// соединения подмену не замечают.
type certHolder struct {
	cur atomic.Pointer[heldCert]
}

type heldCert struct {
	cert     *tls.Certificate
	leaf     *x509.Certificate
	agentID  string
	notAfter time.Time
}

func newHeldCert(cert tls.Certificate) (*heldCert, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("agent: empty certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("agent: parse certificate: %w", err)
	}
	id, _ := pki.AgentIDFromCert(leaf) // пусто для не-агентских сертификатов
	return &heldCert{cert: &cert, leaf: leaf, agentID: id, notAfter: leaf.NotAfter}, nil
}

func (h *certHolder) set(c *heldCert) { h.cur.Store(c) }

func (h *certHolder) get() *heldCert { return h.cur.Load() }

// serverCert — tls.Config.GetCertificate.
func (h *certHolder) serverCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := h.cur.Load()
	if c == nil {
		return nil, errors.New("agent: no certificate")
	}
	return c.cert, nil
}

// clientCert — tls.Config.GetClientCertificate.
func (h *certHolder) clientCert(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c := h.cur.Load()
	if c == nil {
		return nil, errors.New("agent: no certificate")
	}
	return c.cert, nil
}

// pendingKeyPath — файл pending-ключа рядом с основным.
func pendingKeyPath(keyFile string) string { return keyFile + ".next" }

// loadKeyPair читает crt/key; если пара не сошлась (сбой между rename cert и
// rename key при ротации), пробует pending-ключ `<key>.next` и «дорешивает»
// ротацию, переименовывая его в основной.
func loadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		return cert, nil
	}
	next := pendingKeyPath(keyFile)
	if _, serr := os.Stat(next); serr != nil {
		return tls.Certificate{}, err
	}
	cert2, err2 := tls.LoadX509KeyPair(certFile, next)
	if err2 != nil {
		return tls.Certificate{}, err
	}
	if rerr := os.Rename(next, keyFile); rerr != nil {
		return tls.Certificate{}, fmt.Errorf("recover rotated key: %w", rerr)
	}
	return cert2, nil
}

// certNotAfter — срок действия текущего сертификата.
func (a *Agent) certNotAfter() time.Time {
	if c := a.certs.get(); c != nil {
		return c.notAfter
	}
	return time.Time{}
}
