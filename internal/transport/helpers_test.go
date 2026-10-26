package transport

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

type env struct {
	ca       *pki.CA
	pool     *x509.CertPool
	srvCert  tls.Certificate // клиентский сертификат сервера
	newAgent func(t *testing.T, ca *pki.CA, id string) tls.Certificate
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ca, err := pki.NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &env{ca: ca, pool: ca.Pool(), srvCert: serverCert(t, ca), newAgent: agentCert}
}

func serverCert(t *testing.T, ca *pki.CA) tls.Certificate {
	t.Helper()
	b, err := pki.IssueServerClient(ca, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := b.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func agentCert(t *testing.T, ca *pki.CA, id string) tls.Certificate {
	t.Helper()
	csr, key, err := pki.NewAgentCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := pki.IssueAgent(ca, csr, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pki.Bundle{CertPEM: certPEM, KeyPEM: key}.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeAgent поднимает h2/mTLS-сервер с сертификатом агента id, выпущенным ca.
func (e *env) fakeAgent(t *testing.T, ca *pki.CA, id string, h http.Handler) AgentRef {
	t.Helper()
	cfg, err := pki.ServerTLSConfig(agentCert(t, ca, id), e.pool, pki.VerifyServerPeer(e.pool))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = cfg
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	return AgentRef{ID: id, URL: u, Mode: config.AgentModeDial}
}

func (e *env) dial(t *testing.T, opts ...Option) *Dial {
	t.Helper()
	d := NewDial(e.srvCert, e.pool, opts...)
	t.Cleanup(func() { _ = d.Close() })
	return d
}
