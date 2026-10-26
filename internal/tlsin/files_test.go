package tlsin

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

func filesCfg(cf, kf string, domains ...string) config.IngressTLS {
	return config.IngressTLS{Mode: config.TLSModeFiles, CertFile: cf, KeyFile: kf, Domains: domains}
}

func TestFilesLoadAndInfo(t *testing.T) {
	dir := t.TempDir()
	c := issue(t, certSpec{serial: 11, dns: []string{"example.test", "alt.test"}})
	cf, kf := c.write(t, dir, 0o640)
	var col collector
	p, err := New(filesCfg(cf, kf, "example.test"), WithEvents(col.event), WithMetrics(col.metric))
	if err != nil {
		t.Fatal(err)
	}
	info := p.Info()
	if info.Mode != "files" || info.Subject != "CN=example.test" || len(info.SANs) != 2 || !info.NotAfter.Equal(c.cert.NotAfter) ||
		info.LastReload.IsZero() || info.LastError != "" || info.Issuer == "" {
		t.Fatalf("info: %+v", info)
	}
	if got := col.types(); len(got) != 1 || got[0] != EventReloaded || len(col.na) != 1 {
		t.Fatalf("events %v metrics %v", got, col.na)
	}
	hs := serve(t, p.TLSConfig())
	if sn, err := hs("example.test"); err != nil || sn.Int64() != 11 {
		t.Fatalf("handshake: %v %v", sn, err)
	}
}

func TestFilesRejectAtStart(t *testing.T) {
	now := time.Now()
	cases := map[string]func(t *testing.T, dir string) (string, string, string){
		"key perms": func(t *testing.T, dir string) (string, string, string) {
			cf, kf := issue(t, certSpec{}).write(t, dir, 0o644)
			return cf, kf, "mode"
		},
		"key group-write": func(t *testing.T, dir string) (string, string, string) {
			cf, kf := issue(t, certSpec{}).write(t, dir, 0o660)
			return cf, kf, "mode"
		},
		"expired": func(t *testing.T, dir string) (string, string, string) {
			cf, kf := issue(t, certSpec{notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)}).write(t, dir, 0o600)
			return cf, kf, "expired"
		},
		"not yet valid": func(t *testing.T, dir string) (string, string, string) {
			cf, kf := issue(t, certSpec{notBefore: now.Add(time.Hour)}).write(t, dir, 0o600)
			return cf, kf, "not valid yet"
		},
		"key mismatch": func(t *testing.T, dir string) (string, string, string) {
			cf, _ := issue(t, certSpec{}).write(t, dir, 0o600)
			other := t.TempDir()
			_, kf := issue(t, certSpec{}).write(t, other, 0o600)
			return cf, kf, "does not match"
		},
		"missing key": func(t *testing.T, dir string) (string, string, string) {
			cf, kf := issue(t, certSpec{}).write(t, dir, 0o600)
			_ = os.Remove(kf)
			return cf, kf, "no such file"
		},
		"garbage cert": func(t *testing.T, dir string) (string, string, string) {
			cf, kf := issue(t, certSpec{}).write(t, dir, 0o600)
			_ = os.WriteFile(cf, []byte("nope"), 0o644)
			return cf, kf, "tls"
		},
		"wrong domain": func(t *testing.T, dir string) (string, string, string) {
			cf, kf := issue(t, certSpec{dns: []string{"other.test"}}).write(t, dir, 0o600)
			return cf, kf, "other.test"
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			cf, kf, want := mk(t, t.TempDir())
			_, err := New(filesCfg(cf, kf, "example.test"))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("want error containing %q, got %v", want, err)
			}
		})
	}
}

func TestFilesBrokenChain(t *testing.T) {
	ca := issue(t, certSpec{cn: "ca", dns: []string{"ca.test"}, isCA: true})
	leaf := issue(t, certSpec{caKey: ca.key, caCert: ca.cert})
	stranger := issue(t, certSpec{cn: "stranger", dns: []string{"s.test"}, isCA: true})
	dir := t.TempDir()
	cf, kf := leaf.write(t, dir, 0o600)

	// правильная цепочка leaf+ca
	_ = os.WriteFile(cf, append(append([]byte{}, leaf.certPEM...), ca.certPEM...), 0o644)
	if _, err := New(filesCfg(cf, kf)); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	// чужой промежуточный
	_ = os.WriteFile(cf, append(append([]byte{}, leaf.certPEM...), stranger.certPEM...), 0o644)
	if _, err := New(filesCfg(cf, kf)); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("want chain error, got %v", err)
	}
	// мусор в цепочке
	broken := append(append([]byte{}, leaf.certPEM...), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")...)
	_ = os.WriteFile(cf, broken, 0o644)
	if _, err := New(filesCfg(cf, kf)); err == nil {
		t.Fatal("want error for broken chain element")
	}
}

func TestFilesReloadSwapMismatchExpired(t *testing.T) {
	dir := t.TempDir()
	first := issue(t, certSpec{serial: 1})
	cf, kf := first.write(t, dir, 0o600)
	var col collector
	p, err := New(filesCfg(cf, kf), WithEvents(col.event))
	if err != nil {
		t.Fatal(err)
	}
	hs := serve(t, p.TLSConfig())
	serial := func() int64 {
		sn, err := hs("example.test")
		if err != nil {
			t.Fatal(err)
		}
		return sn.Int64()
	}
	if serial() != 1 {
		t.Fatal("first cert expected")
	}

	// валидная замена — новый хендшейк получает новый серт
	issue(t, certSpec{serial: 2}).write(t, dir, 0o600)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if serial() != 2 || col.count(EventReloaded) != 2 {
		t.Fatalf("swap failed: serial=%d events=%v", serial(), col.types())
	}

	// ключ от другого сертификата: остаётся 2 + cert_invalid
	other := issue(t, certSpec{serial: 3})
	_ = os.WriteFile(cf, other.certPEM, 0o644)
	if err := p.Reload(); err == nil {
		t.Fatal("mismatch must fail")
	}
	if serial() != 2 || col.last().Type != EventInvalid || col.last().Err == nil || !col.last().NotAfter.Equal(p.Info().NotAfter) {
		t.Fatalf("mismatch: serial=%d last=%+v", serial(), col.last())
	}
	if p.Info().LastError == "" {
		t.Fatal("LastError must be set")
	}

	// истёкший: отказ
	now := time.Now()
	issue(t, certSpec{serial: 4, notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)}).write(t, dir, 0o600)
	if err := p.Reload(); err == nil || serial() != 2 {
		t.Fatalf("expired accepted: %v", err)
	}
	// права ключа расширили — отказ
	issue(t, certSpec{serial: 5}).write(t, dir, 0o644)
	if err := p.Reload(); err == nil || serial() != 2 {
		t.Fatalf("wide key accepted: %v", err)
	}
	// чинят — принимается, LastError сброшен
	issue(t, certSpec{serial: 6}).write(t, dir, 0o640)
	if err := p.Reload(); err != nil || serial() != 6 || p.Info().LastError != "" {
		t.Fatalf("recovery: %v", err)
	}
}

func TestFilesRunFsnotifyAndPoll(t *testing.T) {
	dir := t.TempDir()
	cf, kf := issue(t, certSpec{serial: 1}).write(t, dir, 0o600)
	var col collector
	p, err := New(filesCfg(cf, kf), WithEvents(col.event))
	if err != nil {
		t.Fatal(err)
	}
	fp := p.(*filesProvider)
	fp.o.debounce = 20 * time.Millisecond
	fp.o.pollInterval = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	hs := serve(t, p.TLSConfig())
	waitSerial := func(want int64) {
		t.Helper()
		eventually(t, "serial", func() bool { sn, err := hs("example.test"); return err == nil && sn.Cmp(big.NewInt(want)) == 0 })
	}
	// подмена на диске без рестарта и без Reload()
	issue(t, certSpec{serial: 2}).write(t, dir, 0o600)
	waitSerial(2)

	// сломанная пара: остаётся 2; событие invalid ровно один раз, несмотря на тикер
	_, _ = issue(t, certSpec{serial: 3}).write(t, dir, 0o600)
	_ = os.WriteFile(kf, issue(t, certSpec{}).keyPEM, 0o600)
	eventually(t, "invalid", func() bool { return col.count(EventInvalid) >= 1 })
	time.Sleep(200 * time.Millisecond)
	waitSerial(2)
	if n := col.count(EventInvalid); n > 2 { // допускаем промежуточный сбой при двухшаговой записи
		t.Fatalf("invalid repeated by poll: %d", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFilesPollByMtimeOnly(t *testing.T) {
	dir := t.TempDir()
	cf, kf := issue(t, certSpec{serial: 1}).write(t, dir, 0o600)
	var col collector
	p, _ := New(filesCfg(cf, kf), WithEvents(col.event))
	fp := p.(*filesProvider)
	fp.poll() // без изменений — ничего
	if col.count(EventReloaded) != 1 {
		t.Fatalf("spurious reload: %v", col.types())
	}
	issue(t, certSpec{serial: 2}).write(t, dir, 0o600)
	fp.poll()
	if col.count(EventReloaded) != 2 || fp.cur.Load().Leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("poll did not reload: %v", col.types())
	}
	// файл пропал: одно invalid, дальше тишина
	_ = os.Remove(cf)
	fp.poll()
	fp.poll()
	if col.count(EventInvalid) != 1 {
		t.Fatalf("invalid count %d", col.count(EventInvalid))
	}
}

func TestFilesExpiringFakeClock(t *testing.T) {
	dir := t.TempDir()
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	cf, kf := issue(t, certSpec{notAfter: notAfter}).write(t, dir, 0o600)
	now := time.Now()
	clock := func() time.Time { return now }
	var col collector
	p, err := New(filesCfg(cf, kf), WithEvents(col.event), WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	fp := p.(*filesProvider)
	if col.count(EventExpiring) != 0 {
		t.Fatal("30 days left must not warn")
	}
	now = notAfter.Add(-13 * 24 * time.Hour)
	fp.poll()
	if col.count(EventExpiring) != 1 || col.last().NotAfter.Sub(notAfter).Abs() > time.Second {
		t.Fatalf("expiring: %v", col.types())
	}
	fp.poll() // в течение часа не повторяется
	if col.count(EventExpiring) != 1 {
		t.Fatal("repeated within an hour")
	}
	now = now.Add(2 * time.Hour)
	fp.poll()
	if col.count(EventExpiring) != 2 {
		t.Fatalf("no repeat after an hour: %v", col.types())
	}
}

func TestFilesRunNoWatcherDirs(t *testing.T) {
	dir := t.TempDir()
	cf, kf := issue(t, certSpec{}).write(t, dir, 0o600)
	p, _ := New(filesCfg(cf, kf))
	fp := p.(*filesProvider)
	fp.certFile = filepath.Join(dir, "gone", "tls.crt") // каталог не наблюдаем — только тикер
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
