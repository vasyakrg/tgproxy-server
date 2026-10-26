package tlsin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type certSpec struct {
	cn        string
	dns       []string
	notBefore time.Time
	notAfter  time.Time
	serial    int64
	caKey     *ecdsa.PrivateKey // nil — самоподписанный
	caCert    *x509.Certificate
	isCA      bool
}

type issued struct {
	certPEM []byte
	keyPEM  []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func issue(t *testing.T, s certSpec) issued {
	t.Helper()
	if s.cn == "" {
		s.cn = "example.test"
	}
	if s.dns == nil {
		s.dns = []string{"example.test"}
	}
	if s.notBefore.IsZero() {
		s.notBefore = time.Now().Add(-time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	if s.serial == 0 {
		s.serial = time.Now().UnixNano()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(s.serial), Subject: pkix.Name{CommonName: s.cn}, DNSNames: s.dns,
		NotBefore: s.notBefore, NotAfter: s.notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: s.isCA,
	}
	if s.isCA {
		tpl.KeyUsage |= x509.KeyUsageCertSign
	}
	parent, signer := tpl, key
	if s.caCert != nil {
		parent, signer = s.caCert, s.caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	kder, _ := x509.MarshalECPrivateKey(key)
	return issued{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
		cert:    cert, key: key,
	}
}

// write кладёт пару в dir атомарно (tmp + rename), как это делает `mv`.
func (i issued) write(t *testing.T, dir string, keyMode os.FileMode) (certFile, keyFile string) {
	t.Helper()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	put := func(dst string, data []byte, mode os.FileMode) {
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(tmp, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			t.Fatal(err)
		}
	}
	put(certFile, i.certPEM, 0o644)
	put(keyFile, i.keyPEM, keyMode)
	return certFile, keyFile
}

type collector struct {
	mu  sync.Mutex
	evs []Event
	na  []time.Time
}

func (c *collector) event(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, e)
}

func (c *collector) metric(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.na = append(c.na, t)
}

func (c *collector) types() []EventType {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []EventType
	for _, e := range c.evs {
		out = append(out, e.Type)
	}
	return out
}

func (c *collector) count(tp EventType) int {
	n := 0
	for _, x := range c.types() {
		if x == tp {
			n++
		}
	}
	return n
}

func (c *collector) last() Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evs[len(c.evs)-1]
}

// serve поднимает TLS-листенер с конфигом провайдера и возвращает функцию
// handshake, отдающую серийник сертификата сервера.
func serve(t *testing.T, cfg *tls.Config) func(sni string) (*big.Int, error) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(ln, cfg)
	t.Cleanup(func() { _ = tl.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).HandshakeContext(context.Background())
				_ = c.Close()
			}()
		}
	}()
	return func(sni string) (*big.Int, error) {
		d := tls.Dialer{Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true}} //nolint:gosec // тест
		nc, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
		c, _ := nc.(*tls.Conn)
		if err != nil {
			return nil, err
		}
		defer func() { _ = c.Close() }()
		return c.ConnectionState().PeerCertificates[0].SerialNumber, nil
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}
