package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newPkgDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	vd := filepath.Join(dir, "1.2.0")
	if err := os.MkdirAll(vd, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"tgproxy_1.2.0_amd64.deb": "DEB", "checksums.txt": "SUMS", "checksums.txt.minisig": "SIG", "evil.sh": "x",
	} {
		if err := os.WriteFile(filepath.Join(vd, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// секрет рядом с каталогом кэша: не должен быть достижим
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("TOP"), 0o600); err != nil {
		t.Fatal(err)
	}
	// симлинк на внешний файл внутри каталога версии
	if err := os.Symlink(filepath.Join(dir, "secret"), filepath.Join(vd, "tgproxy_1.2.0_arm64.deb")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func servePkg(h http.Handler, method, target string, agent bool) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, target, http.NoBody)
	if agent {
		req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, "ams-1"))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPackagesHandlerServesReleaseFiles(t *testing.T) {
	h := PackagesHandler(newPkgDir(t), nil)
	for path, want := range map[string]string{
		"/_agent_gw/packages/1.2.0/tgproxy_1.2.0_amd64.deb": "DEB",
		"/_agent_gw/packages/1.2.0/checksums.txt":           "SUMS",
		"/_agent_gw/packages/1.2.0/checksums.txt.minisig":   "SIG",
	} {
		rec := servePkg(h, http.MethodGet, path, true)
		if rec.Code != http.StatusOK || rec.Body.String() != want {
			t.Errorf("%s: %d %q, want 200 %q", path, rec.Code, rec.Body.String(), want)
		}
	}
}

func TestPackagesHandlerRequiresAgentIdentity(t *testing.T) {
	h := PackagesHandler(newPkgDir(t), nil)
	if rec := servePkg(h, http.MethodGet, "/_agent_gw/packages/1.2.0/checksums.txt", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("без сертификата агента: %d, want 401", rec.Code)
	}
	if rec := servePkg(h, http.MethodPost, "/_agent_gw/packages/1.2.0/checksums.txt", true); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d, want 405", rec.Code)
	}
}

func TestPackagesHandlerRejectsTraversalAndForeignNames(t *testing.T) {
	h := PackagesHandler(newPkgDir(t), nil)
	for _, path := range []string{
		"/_agent_gw/packages/../secret",
		"/_agent_gw/packages/1.2.0/../secret",
		"/_agent_gw/packages/1.2.0/..%2fsecret",
		"/_agent_gw/packages/..%2f..%2fetc/passwd",
		"/_agent_gw/packages/1.2.0/%2e%2e/secret",
		"/_agent_gw/packages/1.2.0/evil.sh",                 // имя не из раскладки
		"/_agent_gw/packages/1.2.0/tgproxy_1.2.1_amd64.deb", // чужая версия в имени
		"/_agent_gw/packages/1.2.0/tgproxy_1.2.0_amd64.deb/x",
		"/_agent_gw/packages/1.2.0/tgproxy_1.2.0_arm64.deb", // симлинк наружу
		"/_agent_gw/packages/1.2.0/",
		"/_agent_gw/packages/1.2.0",
		"/_agent_gw/packages/9.9.9/checksums.txt", // нет такой версии
		"/_agent_gw/packages/1.2/checksums.txt",
		"/_agent_gw/packages/",
	} {
		rec := servePkg(h, http.MethodGet, path, true)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 404/400", path, rec.Code)
		}
		if b := rec.Body.String(); b == "TOP" || b == "x" || b == "x\n" {
			t.Errorf("%s: утечка содержимого %q", path, b)
		}
	}
}
