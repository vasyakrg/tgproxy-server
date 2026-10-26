package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/server/updater"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type signer struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{pub, priv}
}

func (s signer) sign(msg []byte) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	_, _ = io.Copy(io.Discard, r)
	return r.SignWithComments(s.priv, "timestamp:1 file:checksums.txt", "t")
}

type release struct {
	version string
	name    string
	deb     []byte
	sums    []byte
	sig     []byte
}

func makeRelease(t *testing.T, s signer, version string) release {
	t.Helper()
	deb := bytes.Repeat([]byte("deb-"+version+"-"), 2000)
	h := sha256.Sum256(deb)
	name := updater.DebName(version, "amd64")
	sums := []byte(fmt.Sprintf("%s  %s\n%s  other.tar.gz\n", hex.EncodeToString(h[:]), name, strings.Repeat("0", 64)))
	return release{version: version, name: name, deb: deb, sums: sums, sig: s.sign(sums)}
}

// memSource — Source из памяти для Check/Stage.
type memSource struct {
	rel   updater.Release
	files map[string][]byte
	err   error
}

func (m *memSource) Latest(context.Context) (updater.Release, error) { return m.rel, m.err }
func (m *memSource) Fetch(_ context.Context, a updater.Asset) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.files[a.Name])), nil
}

func sourceFor(r release) *memSource {
	m := &memSource{files: map[string][]byte{r.name: r.deb, updater.ChecksumsName: r.sums, updater.SigName: r.sig}}
	m.rel = updater.Release{Version: r.version, Tag: "v" + r.version, Notes: "## Новое\n- фича <b>x</b>"}
	for n, b := range m.files {
		m.rel.Assets = append(m.rel.Assets, updater.Asset{Name: n, Size: int64(len(b))})
	}
	return m
}

type sysEnv struct {
	mux     *http.ServeMux
	svc     *api.SystemService
	up      *updater.Updater
	staging string
	upload  string
	st      *memtest.Store
	signer  signer
	src     *memSource
}

type sysOpt func(*api.SystemConfig)

func newSys(t *testing.T, wrap api.Wrap, opts ...sysOpt) *sysEnv {
	t.Helper()
	e := &sysEnv{signer: newSigner(t), st: memtest.New()}
	root := t.TempDir()
	e.staging = filepath.Join(root, "updates")
	e.upload = filepath.Join(e.staging, "upload")
	e.src = sourceFor(makeRelease(t, e.signer, "1.5.0"))
	sw := &api.SourceSwitch{Base: e.src, Upload: updater.UploadSource{Dir: e.upload, Arch: "amd64"}}
	up, err := updater.New(updater.Config{
		Source: sw, SourceName: "github", StagingDir: e.staging, Arch: "amd64",
		PubKeys: []verify.PublicKey{e.signer.pub}, Current: "1.4.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	e.up = up
	cfg := api.SystemConfig{
		Updater: up, Switch: sw, Source: api.SourceInfo{Kind: "github", Detail: "vasyakrg/tgproxy-server"}, Version: "1.4.1",
		UploadDir: e.upload, Arch: "amd64", PubKeys: []verify.PublicKey{e.signer.pub},
		ResultPath: filepath.Join(e.staging, "result.json"), Audit: e.st.Audit(),
	}
	for _, o := range opts {
		o(&cfg)
	}
	e.svc = api.NewSystemService(cfg)
	e.mux = http.NewServeMux()
	(&api.SystemAPI{Service: e.svc}).Routes(e.mux, wrap)
	return e
}

func (e *sysEnv) do(method, url string, body io.Reader, ctype string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, url, body)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

type part struct{ field, filename string }

func multipartBody(t *testing.T, parts map[part][]byte, order []part) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range order {
		fw, err := w.CreateFormFile(p.field, p.filename)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(parts[p])
	}
	_ = w.Close()
	return &buf, w.FormDataContentType()
}

func fullUpload(t *testing.T, r release) (io.Reader, string) {
	t.Helper()
	d, c, s := part{api.FieldDeb, r.name}, part{api.FieldChecksums, "checksums.txt"}, part{api.FieldSignature, "checksums.txt.minisig"}
	return multipartBody(t, map[part][]byte{d: r.deb, c: r.sums, s: r.sig}, []part{d, c, s})
}

func (e *sysEnv) post(t *testing.T, url string, body io.Reader, ctype string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(http.MethodPost, url, body, ctype)
}

func isEmptyDir(t *testing.T, dir string) bool {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Logf("остался файл: %s", e.Name())
	}
	return len(ents) == 0
}

func errKind(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct{ Error string }
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("json: %v: %s", err, rec.Body)
	}
	return b.Error
}

func TestUploadWithoutSignatureIs422AndNothingSaved(t *testing.T) {
	e := newSys(t, nil)
	r := makeRelease(t, e.signer, "1.6.0")
	d, c := part{api.FieldDeb, r.name}, part{api.FieldChecksums, "checksums.txt"}
	body, ct := multipartBody(t, map[part][]byte{d: r.deb, c: r.sums}, []part{d, c})
	rec := e.post(t, "/api/v1/system/upload", body, ct)
	if rec.Code != http.StatusUnprocessableEntity || errKind(t, rec) != "missing" {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if !isEmptyDir(t, e.upload) {
		t.Fatal("после отказа в каталоге загрузки остались файлы")
	}
}

func TestUploadForeignSignatureIs422AndNothingSaved(t *testing.T) {
	e := newSys(t, nil)
	r := makeRelease(t, newSigner(t), "1.6.0") // подписано чужим ключом
	body, ct := fullUpload(t, r)
	rec := e.post(t, "/api/v1/system/upload", body, ct)
	if rec.Code != http.StatusUnprocessableEntity || errKind(t, rec) != "bad_signature" {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if !isEmptyDir(t, e.upload) {
		t.Fatal("после отказа остались файлы")
	}
	if v := e.svc.Version(); v.Source != "github" || v.Available != "" {
		t.Fatalf("источник не должен переключаться: %+v", v)
	}
}

func TestUploadRejections(t *testing.T) {
	e := newSys(t, nil, func(c *api.SystemConfig) { c.MinVersion = "1.2.0" })
	good := makeRelease(t, e.signer, "1.6.0")
	cases := []struct {
		name string
		make func() (io.Reader, string)
		kind string
	}{
		{"sha256 пакета не совпал", func() (io.Reader, string) {
			r := good
			r.deb = append([]byte("x"), r.deb...)
			return fullUpload(t, r)
		}, "bad_checksum"},
		{"подделан checksums", func() (io.Reader, string) {
			r := good
			r.sums = append([]byte("# hi\n"), r.sums...)
			return fullUpload(t, r)
		}, "bad_signature"},
		{"пакета нет в checksums", func() (io.Reader, string) {
			r := good
			r.name = "tgproxy_1.7.0_amd64.deb"
			r.sums = []byte(strings.Repeat("0", 64) + "  other.tar.gz\n")
			r.sig = e.signer.sign(r.sums)
			return fullUpload(t, r)
		}, "bad_checksum"},
		{"не то имя файла", func() (io.Reader, string) {
			r := good
			r.name = "evil.deb"
			return fullUpload(t, r)
		}, "bad_name"},
		{"не та архитектура", func() (io.Reader, string) {
			r := good
			r.name = "tgproxy_1.6.0_arm64.deb"
			return fullUpload(t, r)
		}, "bad_name"},
		{"версия не новее", func() (io.Reader, string) { return fullUpload(t, makeRelease(t, e.signer, "1.4.1")) }, "not_newer"},
		{"версия ниже min_version", func() (io.Reader, string) { return fullUpload(t, makeRelease(t, e.signer, "1.1.0")) }, "bad_version"},
		{"поле передано дважды", func() (io.Reader, string) {
			d := part{api.FieldDeb, good.name}
			return multipartBody(t, map[part][]byte{d: good.deb}, []part{d, d})
		}, "bad_form"},
		{"лишнее поле", func() (io.Reader, string) {
			x := part{"evil", "x"}
			return multipartBody(t, map[part][]byte{x: []byte("x")}, []part{x})
		}, "bad_form"},
		{"пустой checksums", func() (io.Reader, string) {
			r := good
			r.sums = nil
			return fullUpload(t, r)
		}, "missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, ct := tc.make()
			rec := e.post(t, "/api/v1/system/upload", body, ct)
			if rec.Code != http.StatusUnprocessableEntity || errKind(t, rec) != tc.kind {
				t.Fatalf("code=%d body=%s, want 422 %s", rec.Code, rec.Body, tc.kind)
			}
			if !isEmptyDir(t, e.upload) {
				t.Fatal("остались файлы")
			}
		})
	}
	if rec := e.post(t, "/api/v1/system/upload", strings.NewReader("x=1"), "application/x-www-form-urlencoded"); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("не multipart: %d", rec.Code)
	}
}

func TestUploadTooLargeIs413AndNothingSaved(t *testing.T) {
	e := newSys(t, nil, func(c *api.SystemConfig) { c.MaxUpload = 1024 })
	r := makeRelease(t, e.signer, "1.6.0") // deb ≈ 18 КБ > 1 КБ
	body, ct := fullUpload(t, r)
	rec := e.post(t, "/api/v1/system/upload", body, ct)
	if rec.Code != http.StatusRequestEntityTooLarge || errKind(t, rec) != "too_large" {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if !isEmptyDir(t, e.upload) {
		t.Fatal("остались файлы")
	}
}

func TestUploadHugeBodyIs413(t *testing.T) {
	e := newSys(t, nil, func(c *api.SystemConfig) { c.MaxUpload = 4 << 10 })
	pr, pw := io.Pipe()
	w := multipart.NewWriter(pw)
	go func() {
		fw, _ := w.CreateFormFile(api.FieldDeb, "tgproxy_1.6.0_amd64.deb")
		_, _ = io.Copy(fw, io.LimitReader(zeroReader{}, 6<<20)) // тело заметно больше лимита
		_ = w.Close()
		_ = pw.Close()
	}()
	rec := e.post(t, "/api/v1/system/upload", pr, w.FormDataContentType())
	_, _ = io.Copy(io.Discard, pr)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if !isEmptyDir(t, e.upload) {
		t.Fatal("остались файлы")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestUploadThenInstallOnce(t *testing.T) {
	e := newSys(t, nil)
	r := makeRelease(t, e.signer, "1.6.0")
	body, ct := fullUpload(t, r)
	rec := e.post(t, "/api/v1/system/upload", body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	var v api.VersionInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Uploaded != "1.6.0" || v.Target != "1.6.0" || v.Source != "github" || v.DebSize != int64(len(r.deb)) {
		t.Fatalf("version: %+v", v)
	}
	// плановая проверка идёт в настроенный источник, а не в каталог загрузки
	if rec = e.post(t, "/api/v1/system/check", nil, ""); rec.Code != 200 {
		t.Fatalf("check: %d %s", rec.Code, rec.Body)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Available != "1.5.0" || v.Uploaded != "1.6.0" || v.Source != "github" {
		t.Fatalf("после check: %+v", v)
	}
	for _, n := range []string{r.name, "checksums.txt", "checksums.txt.minisig"} {
		if _, err := os.Stat(filepath.Join(e.upload, n)); err != nil {
			t.Fatalf("нет %s: %v", n, err)
		}
	}
	// без подтверждения — не ставится
	rec = e.post(t, "/api/v1/system/update", strings.NewReader(`{"version":"1.6.0"}`), "application/json")
	if rec.Code != http.StatusBadRequest || errKind(t, rec) != "confirm_required" {
		t.Fatalf("без confirm: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(e.staging, "staged", updater.RequestName)); err == nil {
		t.Fatal("request создан без подтверждения")
	}
	// первое нажатие — 202, второй request не создаётся
	rec = e.post(t, "/api/v1/system/update?confirm=yes", strings.NewReader(`{"version":"1.6.0"}`), "application/json")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("install: %d %s", rec.Code, rec.Body)
	}
	reqPath := filepath.Join(e.staging, "staged", updater.RequestName)
	first, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	rec = e.post(t, "/api/v1/system/update?confirm=yes", strings.NewReader(`{"version":"1.6.0"}`), "application/json")
	if rec.Code != http.StatusConflict || errKind(t, rec) != "already_pending" {
		t.Fatalf("повторный install: %d %s", rec.Code, rec.Body)
	}
	second, _ := os.ReadFile(reqPath)
	if !bytes.Equal(first, second) {
		t.Fatal("request перезаписан повторным нажатием")
	}
	if ents, _ := filepath.Glob(filepath.Join(e.staging, ".staging-*")); len(ents) != 0 {
		t.Fatalf("остались временные каталоги: %v", ents)
	}
	if got := e.svc.Version().Staged; got != "1.6.0" {
		t.Fatalf("staged = %q", got)
	}
	// загрузка заменяет прошлый набор целиком
	r2 := makeRelease(t, e.signer, "1.7.0")
	body, ct = fullUpload(t, r2)
	if rec = e.post(t, "/api/v1/system/upload", body, ct); rec.Code != http.StatusOK {
		t.Fatalf("upload 2: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(e.upload, r.name)); err == nil {
		t.Fatal("старый deb не удалён")
	}
	acts := auditActions(t, e.st)
	for _, want := range []string{"system.upload", "system.update"} {
		if !strings.Contains(acts, want) {
			t.Fatalf("в аудите нет %s: %s", want, acts)
		}
	}
}

func auditActions(t *testing.T, st *memtest.Store) string {
	t.Helper()
	items, err := st.Audit().List(context.Background(), store.AuditQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, it := range items {
		b.WriteString(it.Action + " ")
	}
	return b.String()
}

func TestCheckVersionReleases(t *testing.T) {
	e := newSys(t, nil)
	var rel struct{ Items []api.ReleaseInfo }
	rec := e.do(http.MethodGet, "/api/v1/system/releases", nil, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &rel)
	if rec.Code != 200 || len(rel.Items) != 0 {
		t.Fatalf("до проверки релизов нет: %d %s", rec.Code, rec.Body)
	}
	var v api.VersionInfo
	_ = json.Unmarshal(e.do(http.MethodGet, "/api/v1/system/version", nil, "").Body.Bytes(), &v)
	if !v.Enabled || v.Current != "1.4.1" || v.Available != "" || v.Source != "github" || v.SourceDetail == "" {
		t.Fatalf("version: %+v", v)
	}
	rec = e.post(t, "/api/v1/system/check", nil, "")
	if rec.Code != 200 {
		t.Fatalf("check: %d %s", rec.Code, rec.Body)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Available != "1.5.0" || v.CheckedAt == "" || !strings.Contains(v.Notes, "фича") || v.DebName != "tgproxy_1.5.0_amd64.deb" {
		t.Fatalf("после check: %+v", v)
	}
	_ = json.Unmarshal(e.do(http.MethodGet, "/api/v1/system/releases", nil, "").Body.Bytes(), &rel)
	if len(rel.Items) != 1 || rel.Items[0].Version != "1.5.0" || !rel.Items[0].Newer {
		t.Fatalf("releases: %+v", rel.Items)
	}
	// ошибка источника — 502 с понятным сообщением, токен не утекает
	e.src.err = errors.New("dial tcp: 7012345678:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw3 refused")
	rec = e.post(t, "/api/v1/system/check", nil, "")
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "AAHdqTcv") {
		t.Fatalf("ошибка источника: %d %s", rec.Code, rec.Body)
	}
}

func TestInstallValidationAndUnavailable(t *testing.T) {
	e := newSys(t, nil)
	if rec := e.post(t, "/api/v1/system/update?confirm=yes", strings.NewReader(`{"version":"zzz"}`), "application/json"); rec.Code != 422 {
		t.Fatalf("плохая версия: %d", rec.Code)
	}
	if rec := e.post(t, "/api/v1/system/update?confirm=yes", strings.NewReader(`{"version":"1.4.1"}`), "application/json"); rec.Code != 422 || errKind(t, rec) != "not_newer" {
		t.Fatalf("не новее: %d %s", rec.Code, rec.Body)
	}
	if rec := e.post(t, "/api/v1/system/update?confirm=yes", strings.NewReader(`{"version":"9.9.9"}`), "application/json"); rec.Code != 404 {
		t.Fatalf("версии нет в источнике: %d %s", rec.Code, rec.Body)
	}
	if rec := e.post(t, "/api/v1/system/update?confirm=yes", strings.NewReader(`{bad`), "application/json"); rec.Code != 400 {
		t.Fatalf("плохой JSON: %d", rec.Code)
	}
}

func TestInstallRejectsBadSignatureFromSource(t *testing.T) {
	e := newSys(t, nil)
	e.src.files[updater.SigName] = newSigner(t).sign(e.src.files[updater.ChecksumsName])
	rec := e.post(t, "/api/v1/system/update?confirm=yes", strings.NewReader(`{"version":"1.5.0"}`), "application/json")
	if rec.Code != 422 || errKind(t, rec) != "verification_failed" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(e.staging, "staged")); err == nil {
		t.Fatal("staged создан для неподписанного релиза")
	}
}

func TestUpdatesDisabled(t *testing.T) {
	e := newSys(t, nil, func(c *api.SystemConfig) { c.Updater = nil })
	var v api.VersionInfo
	_ = json.Unmarshal(e.do(http.MethodGet, "/api/v1/system/version", nil, "").Body.Bytes(), &v)
	if v.Enabled || v.Current != "1.4.1" {
		t.Fatalf("version: %+v", v)
	}
	for _, u := range []string{"/api/v1/system/check", "/api/v1/system/update?confirm=yes", "/api/v1/system/upload"} {
		body, ct := io.Reader(strings.NewReader(`{"version":"1.5.0"}`)), "application/json"
		if strings.HasSuffix(u, "upload") {
			body, ct = fullUpload(t, makeRelease(t, e.signer, "1.6.0"))
		}
		if rec := e.post(t, u, body, ct); rec.Code != http.StatusNotImplemented {
			t.Errorf("%s: %d %s", u, rec.Code, rec.Body)
		}
	}
	if len(e.svc.Releases()) != 0 {
		t.Fatal("релизов быть не должно")
	}
}

func TestInstallResultFromFile(t *testing.T) {
	e := newSys(t, nil)
	path := filepath.Join(e.staging, "result.json")
	write := func(s string) {
		t.Helper()
		if err := os.MkdirAll(e.staging, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if e.svc.Version().Result != nil {
		t.Fatal("файла нет — итога нет")
	}
	write(`{"version":"1.5.0","ok":false,"rolled_back":true,"error":"healthz timeout 7012345678:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw3","at":"2026-03-01T12:00:00Z"}`)
	r := e.svc.Version().Result
	if r == nil || r.OK || !r.RolledBack || r.Version != "1.5.0" || strings.Contains(r.Error, "AAHdqTcv") {
		t.Fatalf("result: %+v", r)
	}
	write(`not json`)
	if e.svc.Version().Result != nil {
		t.Fatal("битый файл игнорируется")
	}
}

func TestSystemAPIRequiresSessionAndSameOrigin(t *testing.T) {
	deny := api.Wrap(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	})
	e := newSys(t, deny)
	for _, rt := range [][2]string{
		{"GET", "/api/v1/system/version"}, {"GET", "/api/v1/system/releases"}, {"POST", "/api/v1/system/check"},
		{"POST", "/api/v1/system/update"}, {"POST", "/api/v1/system/upload"},
	} {
		if rec := e.do(rt[0], rt[1], nil, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%v без сессии: %d", rt, rec.Code)
		}
	}
	// кросс-доменный POST отсекается Protect до обработчика
	var hit atomic.Int32
	prot := api.Wrap(func(h http.Handler) http.Handler {
		return auth.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1); h.ServeHTTP(w, r) }))
	})
	e = newSys(t, prot)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/system/check", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || hit.Load() != 0 {
		t.Fatalf("cross-site: %d hit=%d", rec.Code, hit.Load())
	}
}
