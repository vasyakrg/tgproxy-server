package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/release"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// newRelease кладёт в temp-кэш подписанный релиз версии v и возвращает источник пакетов.
func newRelease(t *testing.T, v string) (CachePackages, []byte) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deb := bytes.Repeat([]byte("deb-"+v+"-"), 4000)
	name := release.DebName(v, AgentArch)
	h := sha256.Sum256(deb)
	sums := []byte(hex.EncodeToString(h[:]) + "  " + name + "\n")
	r := minisign.NewReader(bytes.NewReader(sums))
	_, _ = io.Copy(io.Discard, r)
	sig := r.SignWithComments(priv, "timestamp:1 file:checksums.txt", "t")
	dir := t.TempDir()
	vd := release.VersionDir(dir, v)
	if err := os.MkdirAll(vd, 0o750); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string][]byte{name: deb, release.ChecksumsName: sums, release.SigName: sig} {
		if err := os.WriteFile(filepath.Join(vd, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return CachePackages{Dir: dir, Version: v, Arch: AgentArch, Verifier: verify.Verifier{Keys: []verify.PublicKey{pub}}}, deb
}

// getPkg шлёт GET /enroll/package/<name> с заданным Authorization.
func (f *fixture) getPkg(t *testing.T, name, auth, ip string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, PackagePathPrefix+name, nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	r.RemoteAddr = ip + ":5555"
	w := httptest.NewRecorder()
	f.svc.PackageHandler().ServeHTTP(w, r)
	return w
}

func (f *fixture) debName() string { return release.DebName(f.pkgs.Version, AgentArch) }

func TestPackageServedAndTokenNotConsumed(t *testing.T) {
	f := newFixture(t)
	is, err := f.svc.IssueFor(context.Background(), IssueRequest{Name: "pkg-a"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 { // повторное скачивание тем же токеном допустимо
		w := f.getPkg(t, f.debName(), "Bearer "+is.Token, "192.0.2.1")
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), f.deb) {
			t.Fatalf("download %d: %d (%d bytes)", i, w.Code, w.Body.Len())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("cache-control: %q", w.Header().Get("Cache-Control"))
		}
	}
	// токен по-прежнему годится для enrollment
	if w := f.enroll(t, is.Token, goodCSR(t)); w.Code != http.StatusOK {
		t.Fatalf("enroll after download: %d %s", w.Code, w.Body)
	}
	if logs := f.logs.String(); strings.Contains(logs, is.Token) {
		t.Errorf("token leaked into logs: %s", logs)
	}
	aud, _ := f.st.Audit().List(context.Background(), store.AuditQuery{})
	for _, e := range aud {
		if strings.Contains(e.Detail+e.Target+e.Action, is.Token) {
			t.Errorf("token leaked into audit: %+v", e)
		}
	}
}

func TestPackageRejectsBadTokens(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	used, _ := f.svc.IssueFor(ctx, IssueRequest{Name: "used"})
	if w := f.enroll(t, used.Token, goodCSR(t)); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	expired, _ := f.svc.IssueFor(ctx, IssueRequest{Name: "exp", TTL: time.Minute})
	f.clock.add(2 * time.Minute)
	cases := map[string]string{
		"no header": "", "used": "Bearer " + used.Token, "expired": "Bearer " + expired.Token,
		"garbage": "Bearer AAAA", "wrong scheme": "Basic " + used.Token, "empty bearer": "Bearer ",
		"unknown": "Bearer " + strings.Repeat("A", 43),
	}
	i := 0
	for name, auth := range cases {
		i++
		w := f.getPkg(t, f.debName(), auth, net.IPv4(198, 51, 100, byte(i)).String())
		if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != "unauthorized" {
			t.Errorf("%s: %d %q", name, w.Code, w.Body)
		}
	}
	// истёкший токен не скачивает и после смены статуса остальные не затронуты
	fresh, _ := f.svc.IssueFor(ctx, IssueRequest{Name: "fresh"})
	if w := f.getPkg(t, f.debName(), "Bearer "+fresh.Token, "203.0.113.1"); w.Code != http.StatusOK {
		t.Errorf("fresh: %d", w.Code)
	}
}

func TestPackageNames(t *testing.T) {
	f := newFixture(t)
	is, _ := f.svc.IssueFor(context.Background(), IssueRequest{Name: "names"})
	auth := "Bearer " + is.Token
	for name, want := range map[string]int{
		"../etc/passwd":                  http.StatusBadRequest,
		"..%2f..%2fetc%2fpasswd":         http.StatusBadRequest,
		"1.2.3/" + f.debName():           http.StatusBadRequest,
		"checksums.txt":                  http.StatusBadRequest,
		"tgproxy_1.2.3_amd64.deb.sig":    http.StatusBadRequest,
		"tgproxy_1.2_amd64.deb":          http.StatusBadRequest,
		"":                               http.StatusBadRequest,
		"tgproxy_9.9.9_amd64.deb":        http.StatusNotFound, // формат верный, но не версия сервера
		"tgproxy_1.2.3_arm64.deb":        http.StatusNotFound,
		"tgproxy_1.2.3_amd64.deb/../../": http.StatusBadRequest,
	} {
		if w := f.getPkg(t, name, auth, "192.0.2.50"); w.Code != want {
			t.Errorf("%q: got %d want %d", name, w.Code, want)
		}
		f.clock.add(time.Minute) // не упираться в rate-limit
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, PackagePathPrefix+f.debName(), nil)
	w := httptest.NewRecorder()
	f.svc.PackageHandler().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

func TestPackageMissingOrTampered(t *testing.T) {
	f := newFixture(t)
	is, _ := f.svc.IssueFor(context.Background(), IssueRequest{Name: "tamper"})
	auth := "Bearer " + is.Token
	p := filepath.Join(release.VersionDir(f.pkgs.Dir, f.pkgs.Version), f.debName())

	// подмена содержимого → sha256 не сходится → 404 (пакет не отдаётся)
	if err := os.WriteFile(p, []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := f.getPkg(t, f.debName(), auth, "192.0.2.60"); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "evil") {
		t.Errorf("tampered: %d", w.Code)
	}
	// симлинк вместо файла
	_ = os.Remove(p)
	if err := os.Symlink("/etc/hosts", p); err != nil {
		t.Fatal(err)
	}
	if w := f.getPkg(t, f.debName(), auth, "192.0.2.61"); w.Code != http.StatusNotFound {
		t.Errorf("symlink: %d", w.Code)
	}
	// нет файла
	_ = os.Remove(p)
	if w := f.getPkg(t, f.debName(), auth, "192.0.2.62"); w.Code != http.StatusNotFound {
		t.Errorf("missing: %d", w.Code)
	}
}

func TestPackageBadSignature(t *testing.T) {
	f := newFixture(t)
	sig := filepath.Join(release.VersionDir(f.pkgs.Dir, f.pkgs.Version), release.SigName)
	other, _ := newRelease(t, "1.2.3") // другой ключ подписи
	b, _ := os.ReadFile(filepath.Join(release.VersionDir(other.Dir, "1.2.3"), release.SigName))
	if err := os.WriteFile(sig, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pkgs.Current(); !errors.Is(err, ErrPackageUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.svc.IssueFor(context.Background(), IssueRequest{Name: "x"}); !errors.Is(err, ErrPackageUnavailable) {
		t.Fatalf("issue err = %v", err)
	}
	pend, _ := f.st.Enrollments().ListPending(context.Background(), f.clock.now())
	if len(pend) != 0 {
		t.Errorf("token created despite missing package: %d", len(pend))
	}
}

func TestPackageRateLimit(t *testing.T) {
	f := newFixture(t)
	for i := 1; i <= 2*DefaultPerMin; i++ {
		if w := f.getPkg(t, f.debName(), "Bearer AAAA", "198.51.100.7"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := f.getPkg(t, f.debName(), "Bearer AAAA", "198.51.100.7")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("limit: %d", w.Code)
	}
	// лимит /enroll независим
	if w := f.post(t, Request{Token: "AAAA", CSR: goodCSR(t)}, "198.51.100.7"); w.Code != http.StatusUnauthorized {
		t.Fatalf("enroll limiter affected: %d", w.Code)
	}
}

func TestIssueNeedsPackage(t *testing.T) {
	f := newFixture(t)
	f.svc.cfg.Packages = CachePackages{Dir: t.TempDir(), Version: "1.2.3", Arch: AgentArch, Verifier: f.pkgs.Verifier}
	_, err := f.svc.IssueFor(context.Background(), IssueRequest{Name: "np"})
	if !errors.Is(err, ErrPackageUnavailable) || !strings.Contains(err.Error(), "загрузите релиз 1.2.3 в Система → Обновления") {
		t.Fatalf("err = %v", err)
	}
	// dev-сборка (не релизная версия)
	f.svc.cfg.Packages = CachePackages{Dir: t.TempDir(), Version: "dev", Arch: AgentArch, Verifier: f.pkgs.Verifier}
	if _, err = f.svc.IssueFor(context.Background(), IssueRequest{Name: "np"}); !errors.Is(err, ErrPackageUnavailable) {
		t.Fatalf("dev err = %v", err)
	}
	// источник не настроен
	f.svc.cfg.Packages = nil
	if _, err = f.svc.IssueFor(context.Background(), IssueRequest{Name: "np"}); !errors.Is(err, ErrPackageUnavailable) {
		t.Fatalf("nil err = %v", err)
	}
	// «tgproxy уже установлен» работает без пакета
	is, err := f.svc.IssueFor(context.Background(), IssueRequest{Name: "np", InstalledOnly: true})
	if err != nil || is.Cmdline != is.CmdlineInstalled || strings.Contains(is.Cmdline, "curl") {
		t.Fatalf("installed-only: %v %q", err, is.Cmdline)
	}
}

func TestInstallCmd(t *testing.T) {
	f := newFixture(t)
	is, err := f.svc.IssueFor(context.Background(), IssueRequest{Name: "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(f.deb)
	for _, want := range []string{
		"set -eu", "mktemp -d", "trap 'rm -rf \"$T\"' EXIT",
		`dpkg --print-architecture)" = amd64`,
		"curl -fsS --proto =https --tlsv1.3 --cacert \"$T/ca.pem\" -H @-",
		"'https://tgp.example.com:8444/enroll/package/" + f.debName() + "'",
		"printf 'Authorization: Bearer %s\\n' '" + is.Token + "' | curl",
		"echo '" + hex.EncodeToString(h[:]) + "  " + f.debName() + "' | sha256sum -c -",
		`$S apt-get install -y "$T/` + f.debName() + `"`,
		`S=; [ "$(id -u)" -eq 0 ] || S=sudo`,
		`command -v curl >/dev/null || { $S apt-get update -qq && $S apt-get install -y -qq curl ca-certificates; }`,
		"-----BEGIN CERTIFICATE-----\\n",
		"printf %s '" + is.Token + "' | $S tgproxy agent enroll --token-stdin --server https://tgp.example.com:8444 --ca-fingerprint " + f.ca.CAFingerprint(),
		"$S systemctl enable --now tgproxy-agent",
	} {
		if !strings.Contains(is.Cmdline, want) {
			t.Errorf("cmdline lacks %q\n%s", want, is.Cmdline)
		}
	}
	for _, bad := range []string{" -k ", "--insecure", "--cacert-", "-H 'Authorization", "TGP_ENROLL_TOKEN"} {
		if strings.Contains(is.Cmdline, bad) {
			t.Errorf("cmdline must not contain %q", bad)
		}
	}
	// токен — только в builtin printf (до «|»), не в аргументах curl/sudo
	for _, ln := range strings.Split(is.Cmdline, "\n") {
		if !strings.Contains(ln, is.Token) {
			continue
		}
		if !strings.HasPrefix(ln, "printf ") {
			t.Errorf("token outside printf: %q", ln)
		}
		pipe := strings.Index(ln, "|")
		if pipe < 0 || strings.Contains(ln[pipe:], is.Token) {
			t.Errorf("token after pipe (argv): %q", ln)
		}
	}
	// короткий вариант — прежний вид
	if !strings.HasPrefix(is.CmdlineInstalled, "printf %s '"+is.Token+"' | sudo tgproxy agent enroll") || strings.Contains(is.CmdlineInstalled, "\n") {
		t.Errorf("installed cmd: %q", is.CmdlineInstalled)
	}
}
