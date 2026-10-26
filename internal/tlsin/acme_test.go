package tlsin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

// Реальный ACME-сервер (pebble) в тестах недоступен, а тестовый сервер
// x/crypto/acme не экспортируется, поэтому выпуск не эмулируется: проверяются
// конфигурация Manager (политика хостов, клиент/директория, ALPN, HTTP-01),
// использование кеша (сертификат, положенный в DirCache в формате autocert,
// отдаётся без обращения к CA, в том числе после «рестарта»), метаданные
// и события, а также ошибка выпуска против недоступной/некорректной CA.

const acmeHost = "example.test"

func acmeCfg(t *testing.T, dirURL string) config.IngressTLS {
	t.Helper()
	return config.IngressTLS{
		Mode: config.TLSModeACME, Domains: []string{acmeHost}, CacheDir: filepath.Join(t.TempDir(), "acme"),
		ACME: config.ACMEConfig{Email: "ops@example.test", DirectoryURL: dirURL},
	}
}

// seedCache кладёт в DirCache сертификат в формате autocert (ключ + цепочка).
func seedCache(t *testing.T, dir string, c issued) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(c.key)
	data := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), c.certPEM...)
	if err := os.WriteFile(filepath.Join(dir, acmeHost), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestACMEConfigErrors(t *testing.T) {
	base := acmeCfg(t, "")
	noDomains := base
	noDomains.Domains = nil
	noCache := base
	noCache.CacheDir = ""
	egress := base
	egress.ACME.ViaAgentEgress = true
	wide := base
	_ = os.MkdirAll(wide.CacheDir, 0o755)
	_ = os.Chmod(wide.CacheDir, 0o755)
	fileDir := base
	fileDir.CacheDir = filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(fileDir.CacheDir, nil, 0o600)
	for name, c := range map[string]config.IngressTLS{
		"no domains": noDomains, "no cache": noCache, "egress without client": egress, "wide cache": wide, "cache is a file": fileDir,
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestACMEManagerConfig(t *testing.T) {
	cfg := acmeCfg(t, "https://ca.example.test/dir")
	hc := &http.Client{Timeout: time.Second}
	p, err := New(cfg, WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	m := p.(*acmeProvider).mgr
	cl := m.Client
	if cl == nil || cl.DirectoryURL != "https://ca.example.test/dir" || cl.HTTPClient != hc {
		t.Fatalf("client: %#v", m.Client)
	}
	if m.Email != "ops@example.test" || m.Prompt == nil {
		t.Fatalf("manager: %+v", m)
	}
	if st, err := os.Stat(cfg.CacheDir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir: %v %v", st, err)
	}
	if err := m.HostPolicy(context.Background(), acmeHost); err != nil {
		t.Fatal(err)
	}
	if err := m.HostPolicy(context.Background(), "evil.test"); err == nil {
		t.Fatal("foreign host must be rejected")
	}
	tc := p.TLSConfig()
	if tc.GetCertificate == nil || tc.MinVersion != tls.VersionTLS12 || !contains(tc.NextProtos, acme.ALPNProto) {
		t.Fatalf("tls config: %+v", tc)
	}
	// без директории и клиента — значение по умолчанию (Let's Encrypt) внутри autocert
	p2, _ := New(acmeCfg(t, ""))
	if p2.(*acmeProvider).mgr.Client != nil {
		t.Fatal("default client expected")
	}
	// только клиент (egress): директория по умолчанию
	p3, _ := New(acmeCfg(t, ""), WithHTTPClient(hc))
	if p3.(*acmeProvider).mgr.Client.DirectoryURL != autocert.DefaultACMEDirectory {
		t.Fatal("default directory expected")
	}
	if p.Reload() != nil || p.Info().Mode != "acme" {
		t.Fatal("reload/info")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestACMEHTTP01Handler(t *testing.T) {
	p, _ := New(acmeCfg(t, ""))
	h := p.(HTTP01).HTTPHandler(nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+acmeHost+"/x", nil))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://") {
		t.Fatalf("redirect: %d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+acmeHost+"/.well-known/acme-challenge/unknown", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown token: %d", rec.Code)
	}
}

func TestACMECacheSurvivesRestart(t *testing.T) {
	cfg := acmeCfg(t, "http://127.0.0.1:1/unreachable") // обращение к CA провалило бы тест
	c := issue(t, certSpec{serial: 77, notAfter: time.Now().Add(60 * 24 * time.Hour)})
	seedCache(t, cfg.CacheDir, c)

	for i := 0; i < 2; i++ { // второй New — «рестарт» с тем же кешем
		var col collector
		p, err := New(cfg, WithEvents(col.event), WithMetrics(col.metric))
		if err != nil {
			t.Fatal(err)
		}
		hs := serve(t, p.TLSConfig())
		sn, err := hs(acmeHost)
		if err != nil || sn.Int64() != 77 {
			t.Fatalf("run %d: %v %v", i, sn, err)
		}
		info := p.Info()
		if info.Mode != "acme" || info.Subject != "CN=example.test" || !info.NotAfter.Equal(c.cert.NotAfter) || info.LastReload.IsZero() {
			t.Fatalf("info: %+v", info)
		}
		if col.count(EventReloaded) != 1 || len(col.na) != 1 {
			t.Fatalf("events %v", col.types())
		}
		// повторный хендшейк — без нового события
		_, _ = hs(acmeHost)
		if col.count(EventReloaded) != 1 {
			t.Fatal("duplicate reloaded event")
		}
		// чужой SNI отвергается политикой без алерта
		if _, err := hs("evil.test"); err == nil {
			t.Fatal("foreign SNI must fail")
		}
		if col.count(EventInvalid) != 0 {
			t.Fatal("foreign SNI must not raise alert")
		}
	}
}

func TestACMERunLoadsFromCacheAndExpiring(t *testing.T) {
	cfg := acmeCfg(t, "http://127.0.0.1:1/unreachable")
	notAfter := time.Now().Add(60 * 24 * time.Hour)
	seedCache(t, cfg.CacheDir, issue(t, certSpec{serial: 5, notAfter: notAfter}))
	now := time.Now()
	var col collector
	p, err := New(cfg, WithEvents(col.event), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	eventually(t, "eager load", func() bool { return p.Info().Subject != "" })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ap := p.(*acmeProvider)
	if col.count(EventExpiring) != 0 {
		t.Fatal("60 days left must not warn")
	}
	now = notAfter.Add(-10 * 24 * time.Hour)
	if err := ap.refresh(); err != nil {
		t.Fatal(err)
	}
	if col.count(EventExpiring) != 1 {
		t.Fatalf("expiring: %v", col.types())
	}
}

func TestACMEIssueFailureRaisesInvalid(t *testing.T) {
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer ca.Close()
	cfg := acmeCfg(t, ca.URL)
	var col collector
	p, _ := New(cfg, WithEvents(col.event), WithHTTPClient(ca.Client()))
	if err := p.(*acmeProvider).refresh(); err == nil {
		t.Fatal("refresh must fail against a broken CA")
	}
	if col.count(EventInvalid) != 1 || col.last().Err == nil || p.Info().LastError == "" {
		t.Fatalf("events %v info %+v", col.types(), p.Info())
	}
	ap := p.(*acmeProvider)
	ap.failed(acmeHost, col.last().Err)     // та же ошибка — без повторного события
	ap.failed("evil.test", errors.New("x")) // чужой хост — игнорируется
	if col.count(EventInvalid) != 1 {
		t.Fatalf("duplicate invalid: %v", col.types())
	}
}

func TestACMEALPNChallengeNotObserved(t *testing.T) {
	p, _ := New(acmeCfg(t, ""))
	h := &tls.ClientHelloInfo{ServerName: acmeHost, SupportedProtos: []string{acme.ALPNProto}}
	if _, err := p.GetCertificate(h); err == nil {
		t.Fatal("no token cert expected")
	}
	if p.Info().LastError != "" {
		t.Fatal("challenge failures must not touch Info")
	}
}
