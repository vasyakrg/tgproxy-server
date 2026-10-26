package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

const maxCertBody = 64 << 10

// handleCSR — POST /_agent/csr: новый ключ P-256 (pending, в памяти и в
// `<key>.next` 0600) → CSR. Повторный вызов заменяет pending. Приватный ключ
// в ответ не попадает.
func (a *Agent) handleCSR(w http.ResponseWriter, _ *http.Request) {
	cur := a.certs.get()
	if cur == nil || cur.agentID == "" {
		writeAgentError(w, http.StatusInternalServerError, "", "tgproxy: agent identity unknown")
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeAgentError(w, http.StatusInternalServerError, "", "tgproxy: cannot generate key")
		return
	}
	keyPEM, err := marshalKeyPEM(key)
	if err != nil {
		writeAgentError(w, http.StatusInternalServerError, "", "tgproxy: cannot encode key")
		return
	}
	csr, err := BuildCSR(key, cur.agentID)
	if err != nil {
		writeAgentError(w, http.StatusInternalServerError, "", "tgproxy: cannot build csr")
		return
	}
	a.pendMu.Lock()
	defer a.pendMu.Unlock()
	if err := atomicWrite(pendingKeyPath(a.cfg.TLS.KeyFile), keyPEM, 0o600); err != nil {
		a.logger.Warn("agent pending key not saved", "err", err)
		writeAgentError(w, http.StatusInternalServerError, "", "tgproxy: cannot persist pending key")
		return
	}
	a.pending = key
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"csr": string(csr)})
}

type certRequest struct {
	Cert string `json:"cert"`
}

// handleCert — PUT /_agent/cert {"cert":"<PEM>"}: проверка (ключ pending, цепочка
// до CA агента, тот же agent_id, срок) → атомарная запись → горячая подмена.
// 204; 400 — не JSON; 409 — нет pending; 422 — проверка не пройдена.
func (a *Agent) handleCert(w http.ResponseWriter, r *http.Request) {
	var req certRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCertBody)).Decode(&req); err != nil {
		writeAgentError(w, http.StatusBadRequest, "", "tgproxy: bad cert json")
		return
	}
	a.pendMu.Lock()
	defer a.pendMu.Unlock()
	key, err := a.loadPending()
	if err != nil {
		writeAgentError(w, http.StatusConflict, "", "tgproxy: no pending csr")
		return
	}
	cur := a.certs.get()
	if cur == nil || cur.agentID == "" {
		writeAgentError(w, http.StatusInternalServerError, "", "tgproxy: agent identity unknown")
		return
	}
	held, certPEM, err := a.verifyNewCert([]byte(req.Cert), key, cur.agentID)
	if err != nil {
		writeAgentError(w, http.StatusUnprocessableEntity, "", "tgproxy: certificate rejected: "+err.Error())
		return
	}
	if err := a.installCert(certPEM, key, held); err != nil {
		a.logger.Error("agent cert install failed", "err", err)
		writeAgentError(w, http.StatusInternalServerError, "", "tgproxy: cannot install certificate")
		return
	}
	a.pending = nil
	a.logger.Info("agent certificate rotated", "not_after", held.notAfter)
	w.WriteHeader(http.StatusNoContent)
}

// loadPending возвращает pending-ключ из памяти или (после рестарта) из `<key>.next`.
// Вызывать под pendMu.
func (a *Agent) loadPending() (*ecdsa.PrivateKey, error) {
	if a.pending != nil {
		return a.pending, nil
	}
	b, err := os.ReadFile(pendingKeyPath(a.cfg.TLS.KeyFile))
	if err != nil {
		return nil, err
	}
	key, err := parseKeyPEM(b)
	if err != nil {
		return nil, err
	}
	a.pending = key
	return key, nil
}

// verifyNewCert разбирает цепочку PEM и проверяет её. Возвращает готовый
// держатель и нормализованный PEM.
func (a *Agent) verifyNewCert(certPEM []byte, key *ecdsa.PrivateKey, agentID string) (*heldCert, []byte, error) {
	var chain [][]byte
	rest := certPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			chain = append(chain, blk.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("no certificate in PEM")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("certificate does not match pending key")
	}
	if leaf.IsCA {
		return nil, nil, errors.New("certificate is a CA")
	}
	inter := x509.NewCertPool()
	for _, der := range chain[1:] {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			return nil, nil, fmt.Errorf("parse chain: %w", perr)
		}
		inter.AddCert(c)
	}
	// Сертификат агента используется и как серверный, и как клиентский.
	for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		if _, verr := leaf.Verify(x509.VerifyOptions{
			Roots: a.caPool, Intermediates: inter, CurrentTime: a.now(),
			KeyUsages: []x509.ExtKeyUsage{eku},
		}); verr != nil {
			return nil, nil, fmt.Errorf("chain: %w", verr)
		}
	}
	got, err := pki.AgentIDFromCert(leaf)
	if err != nil {
		return nil, nil, err
	}
	if got != agentID {
		return nil, nil, fmt.Errorf("agent id mismatch: %q", got)
	}
	h, err := newHeldCert(tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf})
	if err != nil {
		return nil, nil, err
	}
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return h, out, nil
}

// installCert: crt (atomic rename) → key.next → key (rename); затем подмена в
// памяти. Сбой между rename'ами лечится loadKeyPair при старте.
func (a *Agent) installCert(certPEM []byte, key *ecdsa.PrivateKey, held *heldCert) error {
	// Гарантируем наличие pending-файла до записи сертификата.
	keyPEM, err := marshalKeyPEM(key)
	if err != nil {
		return err
	}
	if err := atomicWrite(pendingKeyPath(a.cfg.TLS.KeyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write pending key: %w", err)
	}
	certFile := a.cfg.TLS.CertFile
	mode := os.FileMode(0o644)
	if st, err := os.Stat(certFile); err == nil {
		mode = st.Mode().Perm()
	}
	if err := atomicWrite(certFile, certPEM, mode); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.Rename(pendingKeyPath(a.cfg.TLS.KeyFile), a.cfg.TLS.KeyFile); err != nil {
		return fmt.Errorf("promote key: %w", err)
	}
	a.certs.set(held)
	return nil
}
