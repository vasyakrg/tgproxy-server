package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

func newAuthority(t *testing.T) (*Authority, store.CertRepo, *KEK) {
	t.Helper()
	repo := memtest.New().Certs()
	kek, _ := newTestKEK(t)
	a, err := LoadOrInit(context.Background(), repo, kek, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return a, repo, kek
}

func csrWith(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: der})
}

func TestLoadOrInitPersistsAndSealsKey(t *testing.T) {
	ctx := context.Background()
	repo := memtest.New().Certs()
	kek, _ := newTestKEK(t)
	a1, err := LoadOrInit(ctx, repo, kek, Options{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := repo.LoadCA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rec.SealedKey), "PRIVATE KEY") {
		t.Fatal("CA key stored in plaintext")
	}
	if _, err := kek.Open(rec.SealedKey, []byte("other")); err == nil {
		t.Fatal("AAD not bound")
	}
	// «перезапуск»
	a2, err := LoadOrInit(ctx, repo, kek, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a1.CAFingerprint() != a2.CAFingerprint() || string(a1.CertPEM()) != string(a2.CertPEM()) {
		t.Fatal("CA changed after restart")
	}
	// агент, подписанный до перезапуска, валиден для CA после него
	csr, _, _ := NewAgentCSR("a1")
	certPEM, _, err := a1.SignAgentCSR(ctx, csr, "a1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAgentPeer(a2.Pool(), "a1")(state(t, certPEM)); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintFormat(t *testing.T) {
	a, _, _ := newAuthority(t)
	fp := a.CAFingerprint()
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) != len("SHA256:")+43 || strings.Contains(fp, "=") {
		t.Fatalf("bad fingerprint %q", fp)
	}
	if fp != Fingerprint(a.ca.Cert()) || fp != a.CAFingerprint() {
		t.Fatal("unstable fingerprint")
	}
}

func TestLoadOrInitWrongKEK(t *testing.T) {
	ctx := context.Background()
	repo := memtest.New().Certs()
	kek1, _ := newTestKEK(t)
	if _, err := LoadOrInit(ctx, repo, kek1, Options{}); err != nil {
		t.Fatal(err)
	}
	before, _ := repo.LoadCA(ctx)
	kek2, _ := newTestKEK(t)
	if _, err := LoadOrInit(ctx, repo, kek2, Options{}); err == nil || !strings.Contains(err.Error(), "decrypt CA key") {
		t.Fatalf("want decrypt error, got %v", err)
	}
	after, _ := repo.LoadCA(ctx)
	if string(before.SealedKey) != string(after.SealedKey) {
		t.Fatal("CA overwritten with wrong KEK")
	}
}

func TestKEKBadPermsRejected(t *testing.T) {
	_, p := newTestKEK(t)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKEK(p); err == nil {
		t.Fatal("0644 KEK accepted")
	}
}

func TestLoadOrInitErrors(t *testing.T) {
	ctx := context.Background()
	kek, _ := newTestKEK(t)
	if _, err := LoadOrInit(ctx, nil, kek, Options{}); err == nil {
		t.Fatal("nil repo")
	}
	if _, err := LoadOrInit(ctx, memtest.New().Certs(), nil, Options{}); err == nil {
		t.Fatal("nil kek")
	}
	// повреждённая запись CA
	repo := memtest.New().Certs()
	sealed, _ := kek.Seal([]byte("not a key"), []byte(caAAD))
	_ = repo.SaveCA(ctx, store.CARecord{CertPEM: []byte("garbage"), SealedKey: sealed})
	if _, err := LoadOrInit(ctx, repo, kek, Options{}); err == nil {
		t.Fatal("garbage CA accepted")
	}
	// ошибка хранилища
	boom := errors.New("boom")
	if _, err := LoadOrInit(ctx, failRepo{CertRepo: memtest.New().Certs(), loadErr: boom}, kek, Options{}); !errors.Is(err, boom) {
		t.Fatalf("load err: %v", err)
	}
	if _, err := LoadOrInit(ctx, failRepo{CertRepo: memtest.New().Certs(), saveErr: boom}, kek, Options{}); !errors.Is(err, boom) {
		t.Fatalf("save err: %v", err)
	}
}

type failRepo struct {
	store.CertRepo
	loadErr, saveErr, putErr, denyErr, listErr, getErr error
}

func (f failRepo) LoadCA(ctx context.Context) (store.CARecord, error) {
	if f.loadErr != nil {
		return store.CARecord{}, f.loadErr
	}
	return f.CertRepo.LoadCA(ctx)
}

func (f failRepo) SaveCA(ctx context.Context, c store.CARecord) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	return f.CertRepo.SaveCA(ctx, c)
}

func (f failRepo) Put(ctx context.Context, c store.CertRecord) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.CertRepo.Put(ctx, c)
}

func (f failRepo) Deny(ctx context.Context, d store.DeniedCert) error {
	if f.denyErr != nil {
		return f.denyErr
	}
	return f.CertRepo.Deny(ctx, d)
}

func (f failRepo) ListDenied(ctx context.Context) ([]store.DeniedCert, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.CertRepo.ListDenied(ctx)
}

func (f failRepo) ListByAgent(ctx context.Context, id string) ([]store.CertRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.CertRepo.ListByAgent(ctx, id)
}

func (f failRepo) Get(ctx context.Context, s string) (store.CertRecord, error) {
	if f.getErr != nil {
		return store.CertRecord{}, f.getErr
	}
	return f.CertRepo.Get(ctx, s)
}

func TestSignAgentCSRRejectsKeyTypes(t *testing.T) {
	a, _, _ := newAuthority(t)
	ctx := context.Background()
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, key := range map[string]any{"p384": p384, "rsa": rsaKey, "ed25519": edKey} {
		csr := csrWith(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent/a1"}})
		if _, _, err := a.SignAgentCSR(ctx, csr, "a1", 0); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSignAgentCSRRejectsCAFlag(t *testing.T) {
	a, _, _ := newAuthority(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bc, _ := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{true})
	csr := csrWith(t, key, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "agent/a1"},
		ExtraExtensions: []pkix.Extension{{Id: oidBasicConstraints, Critical: true, Value: bc}},
	})
	if _, _, err := a.SignAgentCSR(context.Background(), csr, "a1", 0); err == nil || !strings.Contains(err.Error(), "basic constraints") {
		t.Fatalf("CA:true accepted: %v", err)
	}
}

func TestSignAgentCSRIgnoresExtraSAN(t *testing.T) {
	a, repo, _ := newAuthority(t)
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	evil, _ := url.Parse("spiffe://tgproxy/agent/admin")
	srv := ServerURI()
	csr := csrWith(t, key, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "tgproxy-server", Organization: []string{"evil"}},
		DNSNames:       []string{"tgproxy-server", "evil.example"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses: []string{"root@example.com"},
		URIs:           []*url.URL{evil, srv},
	})
	certPEM, serial, err := a.SignAgentCSR(ctx, csr, "a1", 0)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := parseCertPEM(certPEM)
	if len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://tgproxy/agent/a1" ||
		len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 {
		t.Fatalf("SANs: %v %v %v %v", c.URIs, c.DNSNames, c.IPAddresses, c.EmailAddresses)
	}
	if c.IsCA || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 2 || c.Subject.CommonName != "agent/a1" {
		t.Fatalf("props: %+v", c)
	}
	if got := c.NotAfter.Sub(c.NotBefore); got != DefaultTTL+skew {
		t.Fatalf("ttl %s", got)
	}
	rec, err := repo.Get(ctx, serial)
	if err != nil || rec.AgentID != "a1" || !rec.NotAfter.Equal(c.NotAfter) || serial != SerialString(c) {
		t.Fatalf("record: %+v %v", rec, err)
	}
	if err := VerifyAgentPeer(a.Pool(), "a1")(state(t, certPEM)); err != nil {
		t.Fatal(err)
	}
}

func TestSignAgentCSRErrors(t *testing.T) {
	a, _, _ := newAuthority(t)
	ctx := context.Background()
	csr, _, _ := NewAgentCSR("a1")
	cases := []struct {
		name string
		csr  []byte
		id   string
		ttl  time.Duration
	}{
		{"bad id", csr, "../x", 0},
		{"ttl too long", csr, "a1", DefaultTTL + time.Hour},
		{"not pem", []byte("x"), "a1", 0},
		{"bad der", pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: []byte("x")}), "a1", 0},
	}
	for _, c := range cases {
		if _, _, err := a.SignAgentCSR(ctx, c.csr, c.id, c.ttl); err == nil {
			t.Errorf("%s accepted", c.name)
		}
	}
	// испорченная подпись
	blk, _ := pem.Decode(csr)
	blk.Bytes[len(blk.Bytes)-3] ^= 0xff
	if _, _, err := a.SignAgentCSR(ctx, pem.EncodeToMemory(blk), "a1", 0); err == nil {
		t.Error("bad signature accepted")
	}
	// ошибка записи в БД
	a.repo = failRepo{CertRepo: a.repo, putErr: errors.New("boom")}
	if _, _, err := a.SignAgentCSR(ctx, csr, "a1", 0); err == nil {
		t.Error("put error swallowed")
	}
}

func TestServerCertCachedAndRotated(t *testing.T) {
	a, _, _ := newAuthority(t)
	ctx := context.Background()
	c1, err := a.ServerCert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := a.ServerCert(ctx)
	if c1 != c2 {
		t.Fatal("not cached")
	}
	x := a.srvX
	if len(x.URIs) != 1 || x.URIs[0].String() != "spiffe://tgproxy/server" {
		t.Fatalf("SAN %v", x.URIs)
	}
	if err := VerifyServerPeer(a.Pool())(state(t, pemOf(x))); err != nil {
		t.Fatal(err)
	}
	// 61 день вперёд → перевыпуск
	old := nowFunc
	t.Cleanup(func() { nowFunc = old })
	nowFunc = func() time.Time { return old().Add(61 * 24 * time.Hour) }
	c3, err := a.ServerCert(ctx)
	if err != nil || c3 == c1 {
		t.Fatalf("not rotated: %v", err)
	}
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemCert, Bytes: c.Raw})
}

func TestServerCertTTLExceedsCA(t *testing.T) {
	repo := memtest.New().Certs()
	kek, _ := newTestKEK(t)
	a, err := LoadOrInit(context.Background(), repo, kek, Options{CATTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ServerCert(context.Background()); err == nil {
		t.Fatal("ttl beyond CA accepted")
	}
}

func TestDueForRotation(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &x509.Certificate{NotBefore: t0, NotAfter: t0.Add(90 * 24 * time.Hour)}
	for _, tc := range []struct {
		days int
		want bool
	}{{0, false}, {59, false}, {60, true}, {61, true}, {90, true}, {100, true}} {
		if got := DueForRotation(c, t0.Add(time.Duration(tc.days)*24*time.Hour)); got != tc.want {
			t.Errorf("day %d: got %v", tc.days, got)
		}
	}
	if !DueForRotation(&x509.Certificate{NotBefore: t0, NotAfter: t0}, t0) {
		t.Error("zero lifetime must be due")
	}
}

func TestDenylistRevokedRejectedByVerifyAgentPeer(t *testing.T) {
	a, repo, _ := newAuthority(t)
	ctx := context.Background()
	csr, _, _ := NewAgentCSR("a1")
	certPEM, serial, err := a.SignAgentCSR(ctx, csr, "a1", 0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDenylist(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	verify := VerifyAgentPeer(a.Pool(), "a1", d.Check)
	cs := state(t, certPEM)
	if err := verify(cs); err != nil {
		t.Fatal(err)
	}
	if err := d.Revoke(ctx, strings.ToUpper(serial), "removed"); err != nil {
		t.Fatal(err)
	}
	if err := verify(cs); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked cert accepted: %v", err)
	}
	if err := d.Revoke(ctx, serial, "again"); err != nil { // идемпотентно
		t.Fatal(err)
	}
	list, _ := repo.ListDenied(ctx)
	if len(list) != 1 || list[0].AgentID != "a1" || list[0].Reason != "removed" {
		t.Fatalf("denied: %+v", list)
	}
	// другой процесс: перезагрузка из БД видит запись
	d2, _ := NewDenylist(ctx, repo)
	if !d2.IsDenied(serial) {
		t.Fatal("not persisted")
	}
}

func TestDenylistRevokeAgentAndRefresh(t *testing.T) {
	a, repo, _ := newAuthority(t)
	ctx := context.Background()
	for range 2 {
		csr, _, _ := NewAgentCSR("a1")
		if _, _, err := a.SignAgentCSR(ctx, csr, "a1", 0); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := NewDenylist(ctx, repo)
	n, err := d.RevokeAgent(ctx, "a1", "agent removed")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	other, _ := NewDenylist(ctx, repo)
	if err := repo.Deny(ctx, store.DeniedCert{Serial: "ff", NotAfter: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if other.IsDenied("ff") {
		t.Fatal("unexpected before refresh")
	}
	if err := other.Refresh(ctx); err != nil || !other.IsDenied("0xFF") {
		t.Fatalf("refresh: %v", err)
	}
	// неизвестный серийник: отзывается со сроком по умолчанию
	if err := d.Revoke(ctx, "abc123", "x"); err != nil || !d.IsDenied("abc123") {
		t.Fatal(err)
	}
	if err := d.Revoke(ctx, "  ", "x"); err == nil {
		t.Fatal("empty serial accepted")
	}
}

func TestDenylistErrors(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	base := memtest.New().Certs()
	if _, err := NewDenylist(ctx, failRepo{CertRepo: base, listErr: boom}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	d, _ := NewDenylist(ctx, base)
	d.repo = failRepo{CertRepo: base, denyErr: boom}
	if err := d.Revoke(ctx, "01", "x"); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	d.repo = failRepo{CertRepo: base, getErr: boom}
	if err := d.Revoke(ctx, "01", "x"); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	d.repo = failRepo{CertRepo: base, listErr: boom}
	if _, err := d.RevokeAgent(ctx, "a1", "x"); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	_ = base.Put(ctx, store.CertRecord{Serial: "0a", AgentID: "a1", CertPEM: []byte("x"), NotAfter: time.Now()})
	d.repo = failRepo{CertRepo: base, denyErr: boom}
	if _, err := d.RevokeAgent(ctx, "a1", "x"); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

func TestDenylistRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	base := memtest.New().Certs()
	d, _ := NewDenylist(ctx, base)
	errCh := make(chan error, 8)
	d.repo = failRepo{CertRepo: base, listErr: errors.New("boom")}
	done := make(chan struct{})
	go func() { d.Run(ctx, 5*time.Millisecond, func(err error) { errCh <- err }); close(done) }()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onErr not called")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// Параллельный init: ровно один создаёт CA, остальные получают ErrCAExists и
// ничего не перезаписывают.
func TestLoadOrInitParallelInsertOnly(t *testing.T) {
	ctx := context.Background()
	repo := memtest.New().Certs()
	kek, _ := newTestKEK(t)
	const n = 16
	start := make(chan struct{})
	errs := make(chan error, n)
	fps := make(chan string, n)
	for range n {
		go func() {
			<-start
			a, err := LoadOrInit(ctx, repo, kek, Options{})
			if err == nil {
				fps <- a.CAFingerprint()
			}
			errs <- err
		}()
	}
	close(start)
	var okCount, existsCount int
	for range n {
		switch err := <-errs; {
		case err == nil:
			okCount++
		case errors.Is(err, ErrCAExists):
			existsCount++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	// Читатели, пришедшие после записи, тоже успешны (загружают уже сохранённый CA).
	if okCount < 1 || okCount+existsCount != n {
		t.Fatalf("ok=%d exists=%d", okCount, existsCount)
	}
	close(fps)
	saved, err := LoadOrInit(ctx, repo, kek, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for fp := range fps {
		if fp != saved.CAFingerprint() {
			t.Fatalf("созданный CA %s отличается от сохранённого %s", fp, saved.CAFingerprint())
		}
	}
}
