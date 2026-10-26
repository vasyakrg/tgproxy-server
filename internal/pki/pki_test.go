package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA("test CA", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func mustAgent(t *testing.T, ca *CA, id string) Bundle {
	t.Helper()
	csr, key, err := NewAgentCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := IssueAgent(ca, csr, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{CertPEM: cert, KeyPEM: key}
}

func mustServer(t *testing.T, ca *CA) Bundle {
	t.Helper()
	b, err := IssueServerClient(ca, 0)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func state(t *testing.T, certPEM []byte, extra ...*x509.Certificate) tls.ConnectionState {
	t.Helper()
	c, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{PeerCertificates: append([]*x509.Certificate{c}, extra...)}
}

func TestVerifyAgentPeer(t *testing.T) {
	ca := mustCA(t)
	a := mustAgent(t, ca, "a1")
	cs := state(t, a.CertPEM)
	if err := VerifyAgentPeer(ca.Pool(), "a1")(cs); err != nil {
		t.Fatalf("a1: %v", err)
	}
	if err := VerifyAgentPeer(ca.Pool(), "a2")(cs); err == nil {
		t.Fatal("a2 must be rejected")
	}
	// сервер не является агентом
	if err := VerifyAgentPeer(ca.Pool(), "a1")(state(t, mustServer(t, ca).CertPEM)); err == nil {
		t.Fatal("server cert accepted as agent")
	}
	// чужой CA
	if err := VerifyAgentPeer(mustCA(t).Pool(), "a1")(cs); err == nil {
		t.Fatal("foreign CA accepted")
	}
	// пустое состояние / nil pool
	if err := VerifyAgentPeer(ca.Pool(), "a1")(tls.ConnectionState{}); err == nil {
		t.Fatal("empty state accepted")
	}
	if err := VerifyAgentPeer(nil, "a1")(cs); err == nil {
		t.Fatal("nil pool accepted")
	}
}

func TestVerifyServerPeer(t *testing.T) {
	ca := mustCA(t)
	if err := VerifyServerPeer(ca.Pool())(state(t, mustServer(t, ca).CertPEM)); err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := VerifyServerPeer(ca.Pool())(state(t, mustAgent(t, ca, "a1").CertPEM)); err == nil {
		t.Fatal("agent cert accepted as server")
	}
	if err := VerifyServerPeer(mustCA(t).Pool())(state(t, mustServer(t, ca).CertPEM)); err == nil {
		t.Fatal("foreign CA accepted")
	}
}

func TestVerifyRejectsCALeaf(t *testing.T) {
	ca := mustCA(t)
	if err := VerifyServerPeer(ca.Pool())(tls.ConnectionState{PeerCertificates: []*x509.Certificate{ca.Cert()}}); err == nil {
		t.Fatal("CA cert accepted as leaf")
	}
}

func TestVerifyExpired(t *testing.T) {
	ca := mustCA(t)
	a := mustAgent(t, ca, "a1")
	old := nowFunc
	t.Cleanup(func() { nowFunc = old })
	nowFunc = func() time.Time { return time.Now().Add(91 * 24 * time.Hour) }
	if err := VerifyAgentPeer(ca.Pool(), "a1")(state(t, a.CertPEM)); err == nil {
		t.Fatal("expired cert accepted")
	}
}

func TestChecksDenylist(t *testing.T) {
	ca := mustCA(t)
	a := mustAgent(t, ca, "a1")
	cs := state(t, a.CertPEM)
	deny := func(l *x509.Certificate) error { return errors.New("revoked " + l.SerialNumber.String()) }
	if err := VerifyAgentPeer(ca.Pool(), "a1", deny)(cs); err == nil {
		t.Fatal("check ignored (agent)")
	}
	if err := VerifyServerPeer(ca.Pool(), deny)(state(t, mustServer(t, ca).CertPEM)); err == nil {
		t.Fatal("check ignored (server)")
	}
	ok := func(*x509.Certificate) error { return nil }
	if err := VerifyAgentPeer(ca.Pool(), "a1", ok)(cs); err != nil {
		t.Fatal(err)
	}
}

func TestIssuedProperties(t *testing.T) {
	ca := mustCA(t)
	a := mustAgent(t, ca, "a1")
	c, _ := parseCertPEM(a.CertPEM)
	if got := c.NotAfter.Sub(c.NotBefore); got < 90*24*time.Hour || got > 90*24*time.Hour+skew+time.Minute {
		t.Fatalf("ttl = %v", got)
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Fatal("agent key not P-256")
	}
	if k, err := parseKeyPEM(a.KeyPEM); err != nil || !k.PublicKey.Equal(c.PublicKey) {
		t.Fatalf("key mismatch: %v", err)
	}
	if id, err := AgentIDFromCert(c); err != nil || id != "a1" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if len(c.ExtKeyUsage) != 2 || c.IsCA {
		t.Fatalf("eku=%v isCA=%v", c.ExtKeyUsage, c.IsCA)
	}
	if c.SerialNumber.BitLen() < 100 {
		t.Fatalf("serial too small: %d bits", c.SerialNumber.BitLen())
	}
	c2, _ := parseCertPEM(mustAgent(t, ca, "a1").CertPEM)
	if c.SerialNumber.Cmp(c2.SerialNumber) == 0 {
		t.Fatal("serial repeated")
	}

	s := mustServer(t, ca)
	sc, _ := parseCertPEM(s.CertPEM)
	if len(sc.DNSNames) != 1 || sc.DNSNames[0] != ServerDNSName || !isServerCert(sc) {
		t.Fatalf("server SAN: %v %v", sc.DNSNames, sc.URIs)
	}
	if len(sc.ExtKeyUsage) != 2 {
		t.Fatalf("server eku=%v", sc.ExtKeyUsage)
	}
	if _, err := s.TLSCertificate(); err != nil {
		t.Fatal(err)
	}
	// явный ttl
	short, err := IssueServerClient(ca, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	shc, _ := parseCertPEM(short.CertPEM)
	if shc.NotAfter.Sub(shc.NotBefore) > time.Hour+skew+time.Minute {
		t.Fatal("explicit ttl ignored")
	}
	// ttl больше срока CA
	if _, err := IssueServerClient(ca, 10*365*24*time.Hour); err == nil {
		t.Fatal("ttl beyond CA accepted")
	}
}

func TestCSRBadSignature(t *testing.T) {
	ca := mustCA(t)
	csr, _, err := NewAgentCSR("a1")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(csr)
	der := append([]byte(nil), blk.Bytes...)
	der[len(der)-1] ^= 0xff // портим подпись
	bad := pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: der})
	if _, err := IssueAgent(ca, bad, "a1", 0); err == nil {
		t.Fatal("tampered CSR accepted")
	}
	// подмена содержимого при сохранённой подписи
	der2 := append([]byte(nil), blk.Bytes...)
	for i := range der2 {
		if string(der2[i:min(i+2, len(der2))]) == "a1" {
			der2[i+1] = '2'
			break
		}
	}
	bad2 := pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: der2})
	if _, err := IssueAgent(ca, bad2, "a1", 0); err == nil {
		t.Fatal("CSR with altered body accepted")
	}
}

func TestCSRSANIgnored(t *testing.T) {
	ca := mustCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "evil"},
		DNSNames: []string{ServerDNSName},
		URIs:     []*url.URL{ServerURI()},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := IssueAgent(ca, pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: der}), "a1", 0)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := parseCertPEM(certPEM)
	if len(c.DNSNames) != 0 || len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://tgproxy/agent/a1" {
		t.Fatalf("SANs not overridden: %v %v", c.DNSNames, c.URIs)
	}
	if c.Subject.CommonName != "agent/a1" {
		t.Fatalf("CN=%q", c.Subject.CommonName)
	}
	if err := VerifyServerPeer(ca.Pool())(state(t, certPEM)); err == nil {
		t.Fatal("agent with spoofed CSR passes as server")
	}
}

func TestIssueAgentErrors(t *testing.T) {
	ca := mustCA(t)
	csr, _, _ := NewAgentCSR("a1")
	if _, err := IssueAgent(ca, csr, "../x", 0); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, _, err := NewAgentCSR("bad/id"); err == nil {
		t.Fatal("bad id accepted by NewAgentCSR")
	}
	if _, err := IssueAgent(ca, []byte("junk"), "a1", 0); err == nil {
		t.Fatal("junk accepted")
	}
	if _, err := IssueAgent(ca, pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: []byte("x")}), "a1", 0); err == nil {
		t.Fatal("garbage DER accepted")
	}
	// не P-256
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k384)
	if _, err := IssueAgent(ca, pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: der}), "a1", 0); err == nil {
		t.Fatal("P-384 accepted")
	}
}

func TestAgentIDFromCertErrors(t *testing.T) {
	for name, uris := range map[string][]string{
		"none":   nil,
		"server": {"spiffe://tgproxy/server"},
		"two":    {"spiffe://tgproxy/agent/a", "spiffe://tgproxy/agent/b"},
		"badid":  {"spiffe://tgproxy/agent/a%2Fb"},
		"domain": {"spiffe://other/agent/a"},
	} {
		c := &x509.Certificate{}
		for _, s := range uris {
			u, _ := url.Parse(s)
			c.URIs = append(c.URIs, u)
		}
		if _, err := AgentIDFromCert(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestCARoundTrip(t *testing.T) {
	ca := mustCA(t)
	k, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := LoadCA(ca.CertPEM(), k)
	if err != nil {
		t.Fatal(err)
	}
	// сертификат от загруженного CA проверяется пулом исходного
	a := mustAgent(t, ca2, "a1")
	if err := VerifyAgentPeer(ca.Pool(), "a1")(state(t, a.CertPEM)); err != nil {
		t.Fatal(err)
	}
	pool, err := PoolFromPEM(ca.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAgentPeer(pool, "a1")(state(t, a.CertPEM)); err != nil {
		t.Fatal(err)
	}
	if ca.Cert().KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("no CertSign")
	}
	if pub, ok := ca.Cert().PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Fatal("CA key not P-256")
	}
}

func TestLoadCAErrors(t *testing.T) {
	ca := mustCA(t)
	other := mustCA(t)
	ok, _ := ca.KeyPEM()
	otherKey, _ := other.KeyPEM()
	srv := mustServer(t, ca)
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKCS8PrivateKey(k384)
	cases := map[string][2][]byte{
		"bad cert":     {[]byte("x"), ok},
		"bad key":      {ca.CertPEM(), []byte("x")},
		"mismatch":     {ca.CertPEM(), otherKey},
		"not a CA":     {srv.CertPEM, srv.KeyPEM},
		"p384 key":     {ca.CertPEM(), pem.EncodeToMemory(&pem.Block{Type: pemKey, Bytes: der384})},
		"garbage pkcs": {ca.CertPEM(), pem.EncodeToMemory(&pem.Block{Type: pemKey, Bytes: []byte("x")})},
	}
	for n, c := range cases {
		if _, err := LoadCA(c[0], c[1]); err == nil {
			t.Errorf("%s: expected error", n)
		}
	}
	if _, err := PoolFromPEM([]byte("x")); err == nil {
		t.Error("PoolFromPEM accepted junk")
	}
	if _, err := NewCA("", time.Hour); err == nil {
		t.Error("empty cn accepted")
	}
	if _, err := NewCA("x", 0); err == nil {
		t.Error("zero ttl accepted")
	}
	if ca.CertPEM() == nil {
		t.Error("nil pem")
	}
}

type hsResult struct {
	srvErr, cliErr error
	state          tls.ConnectionState
}

// handshake поднимает TLS-сервер и клиент и возвращает ошибки обеих сторон.
func handshake(t *testing.T, srvCfg, cliCfg *tls.Config) (res hsResult) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = c.Close() }()
		tc := c.(*tls.Conn)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			done <- err
			return
		}
		// дождаться закрытия клиентом (в TLS1.3 отказ по клиент-серту приходит после handshake клиента)
		_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = tc.Read(make([]byte, 1))
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := tls.Dialer{Config: cliCfg}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err == nil {
		tc := conn.(*tls.Conn)
		res.state = tc.ConnectionState()
		// форсируем чтение алерта сервера
		_ = tc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, rerr := tc.Read(make([]byte, 1))
		var ne net.Error
		if rerr != nil && (!errors.As(rerr, &ne) || !ne.Timeout()) {
			res.cliErr = rerr
		}
		_ = tc.Close()
	} else {
		res.cliErr = err
	}
	select {
	case res.srvErr = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server timeout")
	}
	return res
}

func cfgs(t *testing.T, ca *CA, srvSide, cliSide Bundle, srvVerify, cliVerify func(tls.ConnectionState) error) (*tls.Config, *tls.Config) {
	t.Helper()
	sc, err := srvSide.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	cc, err := cliSide.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := ServerTLSConfig(sc, ca.Pool(), srvVerify)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ClientTLSConfig(cc, ca.Pool(), cliVerify)
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func TestHandshakeDial(t *testing.T) {
	// dial: сервер tgproxy — TLS-клиент, агент — TLS-сервер
	ca := mustCA(t)
	srv, agent := mustServer(t, ca), mustAgent(t, ca, "a1")
	s, c := cfgs(t, ca, agent, srv, VerifyServerPeer(ca.Pool()), VerifyAgentPeer(ca.Pool(), "a1"))
	r := handshake(t, s, c)
	if r.srvErr != nil || r.cliErr != nil {
		t.Fatalf("srv=%v cli=%v", r.srvErr, r.cliErr)
	}
	st := r.state
	if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" {
		t.Fatalf("version=%x alpn=%q", st.Version, st.NegotiatedProtocol)
	}
}

func TestHandshakeReverse(t *testing.T) {
	// reverse: сервер — TLS-сервер, агент — TLS-клиент
	ca := mustCA(t)
	srv, agent := mustServer(t, ca), mustAgent(t, ca, "a1")
	s, c := cfgs(t, ca, srv, agent, VerifyAgentPeer(ca.Pool(), "a1"), VerifyServerPeer(ca.Pool()))
	r := handshake(t, s, c)
	if r.srvErr != nil || r.cliErr != nil {
		t.Fatalf("srv=%v cli=%v", r.srvErr, r.cliErr)
	}
	st := r.state
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("version=%x", st.Version)
	}
}

func TestHandshakeRejects(t *testing.T) {
	ca := mustCA(t)
	srv, agent, agent2 := mustServer(t, ca), mustAgent(t, ca, "a1"), mustAgent(t, ca, "a2")

	// агент (TLS-сервер) принимает только клиента-сервер: клиент с сертом агента отклонён
	s, c := cfgs(t, ca, agent, agent2, VerifyServerPeer(ca.Pool()), VerifyAgentPeer(ca.Pool(), "a1"))
	if r := handshake(t, s, c); r.srvErr == nil && r.cliErr == nil {
		t.Fatal("agent cert accepted as client of agent")
	}

	// клиент ожидает a1, сервер предъявляет a2
	s, c = cfgs(t, ca, agent2, srv, VerifyServerPeer(ca.Pool()), VerifyAgentPeer(ca.Pool(), "a1"))
	if r := handshake(t, s, c); r.cliErr == nil {
		t.Fatalf("wrong agent accepted (srv=%v)", r.srvErr)
	}

	// клиент без клиентского сертификата
	sc, _ := agent.TLSCertificate()
	scfg, _ := ServerTLSConfig(sc, ca.Pool(), VerifyServerPeer(ca.Pool()))
	ccfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true} //nolint:gosec // тест
	if r := handshake(t, scfg, ccfg); r.srvErr == nil && r.cliErr == nil {
		t.Fatal("client without cert accepted")
	}

	// сертификат от чужого CA
	foreign := mustCA(t)
	fsrv := mustServer(t, foreign)
	s, c = cfgs(t, ca, agent, fsrv, VerifyServerPeer(ca.Pool()), VerifyAgentPeer(ca.Pool(), "a1"))
	if r := handshake(t, s, c); r.srvErr == nil && r.cliErr == nil {
		t.Fatal("foreign CA client accepted")
	}
}

func TestTLSConfigValidation(t *testing.T) {
	var cert tls.Certificate
	if _, err := ServerTLSConfig(cert, nil, VerifyServerPeer(nil)); err == nil {
		t.Fatal("nil pool accepted")
	}
	if _, err := ClientTLSConfig(cert, x509.NewCertPool(), nil); err == nil {
		t.Fatal("nil verify accepted")
	}
	if _, err := ServerTLSConfig(cert, x509.NewCertPool(), nil); err == nil {
		t.Fatal("nil verify accepted (server)")
	}
	if _, err := ClientTLSConfig(cert, nil, VerifyServerPeer(nil)); err == nil {
		t.Fatal("nil pool accepted (client)")
	}
}

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestDevInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := DevInit(dir, []string{"local"}); err != nil {
		t.Fatal(err)
	}
	if p := perm(t, dir); p != 0o700 {
		t.Fatalf("dir perm %o", p)
	}
	for _, n := range []string{FileCAKey, FileServerKey, FileAgentKey} {
		if p := perm(t, filepath.Join(dir, n)); p != 0o600 {
			t.Fatalf("%s perm %o", n, p)
		}
	}
	for _, n := range []string{FileCACert, FileServerCert, FileAgentCert} {
		if p := perm(t, filepath.Join(dir, n)); p&0o022 != 0 {
			t.Fatalf("%s perm %o", n, p)
		}
	}
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	caPEM, caKey := read(FileCACert), read(FileCAKey)
	ca, err := LoadCA(caPEM, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := PoolFromPEM(caPEM)
	if err := VerifyAgentPeer(pool, "local")(state(t, read(FileAgentCert))); err != nil {
		t.Fatal(err)
	}
	if err := VerifyServerPeer(pool)(state(t, read(FileServerCert))); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(read(FileAgentCert), read(FileAgentKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(read(FileServerCert), read(FileServerKey)); err != nil {
		t.Fatal(err)
	}
	_ = ca

	// повторный запуск не перезаписывает
	if err := DevInit(dir, []string{"local"}); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	if string(read(FileCACert)) != string(caPEM) || string(read(FileCAKey)) != string(caKey) {
		t.Fatal("CA overwritten")
	}
}

func TestDevInitDefaultsAndErrors(t *testing.T) {
	dir := t.TempDir()
	if err := DevInit(dir, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, FileAgentCert))
	pool, _ := PoolFromPEM(mustRead(t, filepath.Join(dir, FileCACert)))
	if err := VerifyAgentPeer(pool, "local")(state(t, b)); err != nil {
		t.Fatal(err)
	}
	if err := DevInit(t.TempDir(), []string{"bad/id"}); err == nil {
		t.Fatal("bad id accepted")
	}
	// каталог — файл
	f := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(f, nil, 0o600)
	if err := DevInit(filepath.Join(f, "sub"), nil); err == nil {
		t.Fatal("mkdir under file accepted")
	}
	// writeFile: гонка — CA уже создан между проверкой и записью
	d := t.TempDir()
	p := filepath.Join(d, FileCACert)
	_ = os.WriteFile(p, []byte("x"), 0o600)
	if err := writeFile(p, []byte("y"), 0o644); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	// запись в несуществующий каталог
	if err := writeFile(filepath.Join(d, "nope", "x"), nil, 0o600); err == nil {
		t.Fatal("expected error")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDevInitMultipleAgents(t *testing.T) {
	dir := t.TempDir()
	if err := DevInit(dir, []string{"a1", "a2"}); err != nil {
		t.Fatal(err)
	}
	pool, _ := PoolFromPEM(mustRead(t, filepath.Join(dir, FileCACert)))
	for _, id := range []string{"a1", "a2"} {
		b := mustRead(t, filepath.Join(dir, AgentCertFile(id)))
		if err := VerifyAgentPeer(pool, id)(state(t, b)); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if _, err := os.Stat(filepath.Join(dir, AgentKeyFile(id))); err != nil {
			t.Fatal(err)
		}
	}
	// первый — ещё и agent.crt
	if string(mustRead(t, filepath.Join(dir, FileAgentCert))) != string(mustRead(t, filepath.Join(dir, AgentCertFile("a1")))) {
		t.Fatal("agent.crt must equal first agent cert")
	}
	if err := DevInit(t.TempDir(), []string{"a1", "a1"}); err == nil {
		t.Fatal("duplicate ids accepted")
	}
}
