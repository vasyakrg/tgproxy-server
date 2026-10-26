package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Request — тело POST /enroll.
type Request struct {
	Token string `json:"token"`
	CSR   string `json:"csr"` // PEM
}

// Response — успешный ответ.
type Response struct {
	AgentID string `json:"agent_id"`
	Cert    string `json:"cert"`
	CA      string `json:"ca"`
}

var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

// Handler — POST /enroll для gateway.WithEnrollHandler. Токен нигде не логируется.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

func (s *Service) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := clientIP(r)
	if !s.lim.allow(ip) {
		s.observe("rate_limited")
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var req Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&req); err != nil || req.Token == "" || req.CSR == "" {
		s.observe("bad_request")
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	// CSR проверяется до гашения токена: ошибка клиента не сжигает токен.
	if err := checkCSR([]byte(req.CSR)); err != nil {
		s.observe("bad_csr")
		s.audit(r.Context(), "", "enroll.rejected", "", ip, "csr: "+err.Error())
		writeErr(w, http.StatusUnprocessableEntity, "invalid csr: "+err.Error())
		return
	}
	e, ok := s.consume(r, req.Token)
	if !ok {
		s.observe("denied")
		s.audit(r.Context(), "", "enroll.denied", "", ip, "")
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	agentID, err := s.createAgent(r, e)
	if err != nil {
		s.fail(w, r, ip, "create agent", err)
		return
	}
	certPEM, _, err := s.cfg.CA.SignAgentCSR(r.Context(), []byte(req.CSR), agentID, 0)
	if err != nil {
		_ = s.cfg.Agents.Delete(r.Context(), agentID)
		s.fail(w, r, ip, "sign csr", err)
		return
	}
	s.observe("ok")
	s.audit(r.Context(), "", "agent.enroll", agentID, ip, "enrollment="+e.ID+" name="+e.Name)
	s.log.Info("agent enrolled", "agent", agentID, "name", e.Name, "ip", ip)
	if s.cfg.Notify != nil {
		s.cfg.Notify(r.Context(), agentID, e.Name)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(Response{AgentID: agentID, Cert: string(certPEM), CA: string(s.cfg.CA.CertPEM())})
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, ip, stage string, err error) {
	s.observe("error")
	s.log.Error("enroll failed", "stage", stage, "ip", ip, "err", err)
	s.audit(r.Context(), "", "enroll.error", "", ip, stage)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// consume атомарно гасит токен. Любая причина отказа неразличима для клиента.
func (s *Service) consume(r *http.Request, token string) (store.Enrollment, bool) {
	h, ok := tokenHash(token)
	if !ok {
		return store.Enrollment{}, false
	}
	e, err := s.cfg.Enrollments.Consume(r.Context(), h[:], s.now())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("enroll: consume failed", "err", err)
		}
		return store.Enrollment{}, false
	}
	if subtle.ConstantTimeCompare(e.TokenHash, h[:]) != 1 {
		return store.Enrollment{}, false
	}
	return e, true
}

// tokenHash декодирует токен и возвращает его SHA-256 (как в БД).
func tokenHash(token string) ([sha256.Size]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != TokenBytes {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256(raw), true
}

// createAgent создаёт reverse-агента; id — slug имени, при коллизии с суффиксом.
func (s *Service) createAgent(r *http.Request, e store.Enrollment) (string, error) {
	base := agentSlug(e.Name)
	id := base
	for i := 0; i <= agentIDRetries; i++ {
		_, err := s.cfg.Agents.Create(r.Context(), store.Agent{
			ID: id, Name: e.Name, Mode: store.ModeReverse, Weight: e.Weight,
		})
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, store.ErrConflict) {
			return "", err
		}
		var b [2]byte
		if _, rerr := rand.Read(b[:]); rerr != nil {
			return "", rerr
		}
		id = base + "-" + hex.EncodeToString(b[:])
	}
	return "", fmt.Errorf("agent id %q: too many conflicts", base)
}

// checkCSR: PEM CSR, подпись, ECDSA P-256, без SAN и BasicConstraints.
// Сервер всё равно выставит SAN сам; чужие SAN считаются попыткой подмены.
func checkCSR(csrPEM []byte) error {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return errors.New("no CERTIFICATE REQUEST in pem")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return errors.New("cannot parse csr")
	}
	if err := csr.CheckSignature(); err != nil {
		return errors.New("bad csr signature")
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return errors.New("key must be ECDSA P-256")
	}
	if len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return errors.New("csr must not contain SAN")
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			return errors.New("csr must not request basic constraints")
		}
	}
	return nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
