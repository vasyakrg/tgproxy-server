package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// githubStub эмулирует GitHub Releases API + CDN вложений.
func githubStub(t *testing.T, art artifacts, mutate func(*ghRelease)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != acceptJSON {
			http.Error(w, "accept", 400)
			return
		}
		gr := ghRelease{TagName: "v" + art.version, Body: "changelog"}
		for n, b := range art.files() {
			gr.Assets = append(gr.Assets, struct {
				Name string `json:"name"`
				URL  string `json:"browser_download_url"`
				Size int64  `json:"size"`
			}{n, srv.URL + "/dl/" + n, int64(len(b))})
		}
		if mutate != nil {
			mutate(&gr)
		}
		_ = json.NewEncoder(w).Encode(gr)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := art.files()[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func plainGetter() Getter {
	return func(ctx context.Context, raw, accept string) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		return http.DefaultClient.Do(req)
	}
}

func TestGitHubSourceEndToEnd(t *testing.T) {
	k := newKeys(t)
	art := makeArtifacts(t, k, "1.2.0")
	srv := githubStub(t, art, nil)
	src := &GitHubSource{Repo: "o/r", APIBase: srv.URL, Get: plainGetter()}

	root := t.TempDir()
	u, err := New(Config{
		Source: src, SourceName: "github", DownloadsDir: filepath.Join(root, "p"), StagingDir: filepath.Join(root, "u"),
		Arch: "amd64", PubKeys: []verify.PublicKey{k.pub}, Current: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	rel, err := u.Check(context.Background())
	if err != nil || rel.Version != "1.2.0" || rel.Tag != "v1.2.0" || len(rel.Assets) != 3 {
		t.Fatalf("rel=%+v err=%v", rel, err)
	}
	if err := u.Stage(context.Background(), "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(root, "u", "staged", RequestName)) {
		t.Fatal("request не создан")
	}
}

func TestGitHubLatestErrors(t *testing.T) {
	k := newKeys(t)
	art := makeArtifacts(t, k, "1.2.0")
	cases := map[string]struct {
		mutate func(*ghRelease)
		want   error
	}{
		"draft":      {func(g *ghRelease) { g.Draft = true }, ErrNoRelease},
		"prerelease": {func(g *ghRelease) { g.Prerelease = true }, ErrNoRelease},
		"bad tag":    {func(g *ghRelease) { g.TagName = "nightly" }, verify.ErrBadVersion},
	}
	for n, c := range cases {
		srv := githubStub(t, art, c.mutate)
		src := &GitHubSource{Repo: "o/r", APIBase: srv.URL, Get: plainGetter()}
		if _, err := src.Latest(context.Background()); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v", n, err)
		}
	}
	srv := githubStub(t, art, nil)
	if _, err := (&GitHubSource{Repo: "x/y", APIBase: srv.URL, Get: plainGetter()}).Latest(context.Background()); !errors.Is(err, ErrNoRelease) {
		t.Errorf("404: %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{not json") }))
	defer bad.Close()
	if _, err := (&GitHubSource{Repo: "o/r", APIBase: bad.URL + "/", Get: plainGetter()}).Latest(context.Background()); err == nil {
		t.Error("ожидалась ошибка JSON")
	}
	e500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer e500.Close()
	if _, err := (&GitHubSource{Repo: "o/r", APIBase: e500.URL, Get: plainGetter()}).Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("500: %v", err)
	}
	if _, err := (&GitHubSource{Repo: "o/r", APIBase: "http://127.0.0.1:1", Get: plainGetter()}).Latest(context.Background()); err == nil {
		t.Error("ожидалась сетевая ошибка")
	}
}

func TestGitHubFetchErrors(t *testing.T) {
	k := newKeys(t)
	srv := githubStub(t, makeArtifacts(t, k, "1.2.0"), nil)
	src := &GitHubSource{Repo: "o/r", APIBase: srv.URL, Get: plainGetter()}
	if _, err := src.Fetch(context.Background(), Asset{Name: "x", URL: srv.URL + "/dl/missing"}); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v", err)
	}
	if _, err := src.Fetch(context.Background(), Asset{Name: "x", URL: "http://127.0.0.1:1/x"}); err == nil {
		t.Error("ожидалась ошибка")
	}
	rc, err := src.Fetch(context.Background(), Asset{Name: ChecksumsName, URL: srv.URL + "/dl/" + ChecksumsName})
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
}

func TestGitHubHostAllowed(t *testing.T) {
	for u, want := range map[string]bool{
		"https://github.com/o/r/releases/download/v1/x.deb": true,
		"https://api.github.com/repos/o/r/releases/latest":  true,
		"https://objects.githubusercontent.com/x":           true,
		"https://release-assets.githubusercontent.com/x":    true,
		"http://github.com/x":                               false,
		"https://evil.example/x":                            false,
		"https://github.com.evil.example/x":                 false,
		"https://user@github.com/x":                         false,
		"https://GitHub.com/x":                              true,
		"::bad":                                             false,
	} {
		if got := GitHubHostAllowed(u); got != want {
			t.Errorf("%s: %v, want %v", u, got, want)
		}
	}
	src := &GitHubSource{Repo: "o/r", AllowURL: GitHubHostAllowed, Get: func(context.Context, string, string) (*http.Response, error) {
		t.Fatal("Get не должен вызываться для URL вне allowlist")
		return nil, nil
	}}
	if _, err := src.Fetch(context.Background(), Asset{Name: "x", URL: "https://evil.example/x"}); err == nil {
		t.Error("ожидался отказ")
	}
}

func TestNewGitHubSourceProxy(t *testing.T) {
	k := newKeys(t)
	art := makeArtifacts(t, k, "1.3.0")
	var mu sync.Mutex
	var viaProxy []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		viaProxy = append(viaProxy, r.URL.String())
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			_ = json.NewEncoder(w).Encode(ghRelease{TagName: "v" + art.version})
			return
		}
		_, _ = w.Write(art.sums)
	}))
	defer proxy.Close()

	src, err := NewGitHubSource("o/r", proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	src.AllowURL = nil
	src.APIBase = "http://api.github.invalid"
	rel, err := src.Latest(context.Background())
	if err != nil || rel.Version != "1.3.0" {
		t.Fatalf("rel=%+v err=%v", rel, err)
	}
	rc, err := src.Fetch(context.Background(), Asset{Name: ChecksumsName, URL: "http://github.invalid/dl/checksums.txt"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(b, art.sums) {
		t.Error("тело через прокси не совпало")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(viaProxy) != 2 || !strings.HasPrefix(viaProxy[0], "http://api.github.invalid/") {
		t.Errorf("запросы не прошли через прокси: %v", viaProxy)
	}

	for _, bad := range []string{"ftp://x", "::", "http://"} {
		if _, err := NewGitHubSource("o/r", bad); err == nil {
			t.Errorf("%q: ожидалась ошибка", bad)
		}
	}
	if s, err := NewGitHubSource("o/r", ""); err != nil || s.Get == nil || s.AllowURL == nil {
		t.Errorf("s=%+v err=%v", s, err)
	}
}

func TestGitHubDirectRedirectAllowlist(t *testing.T) {
	// Редирект наружу allowlist'а отвергается клиентом прямого источника.
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "evil") }))
	defer evil.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusFound)
	}))
	defer redir.Close()
	src, err := NewGitHubSource("o/r", "")
	if err != nil {
		t.Fatal(err)
	}
	// Обходим предварительную проверку URL, оставляя CheckRedirect боевым.
	src.AllowURL = func(raw string) bool { return strings.HasPrefix(raw, redir.URL) }
	if _, err := src.Fetch(context.Background(), Asset{Name: "x", URL: redir.URL + "/x"}); err == nil {
		t.Fatal("редирект вне allowlist должен быть отвергнут")
	}
}

// fakeAgentTransport записывает запросы к агенту и отвечает как egress.
type fakeAgentTransport struct {
	mu    sync.Mutex
	reqs  []*http.Request
	reply func(r *http.Request) *http.Response
}

func (f *fakeAgentTransport) RoundTrip(_ context.Context, _ transport.AgentRef, req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	return f.reply(req), nil
}
func (f *fakeAgentTransport) Status(context.Context, transport.AgentRef) (*transport.AgentStatus, error) {
	return nil, errors.New("unused")
}

func resp(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func TestAgentEgressSource(t *testing.T) {
	k := newKeys(t)
	art := makeArtifacts(t, k, "1.4.0")
	ft := &fakeAgentTransport{}
	ft.reply = func(r *http.Request) *http.Response {
		target := r.URL.Query().Get("url")
		switch {
		case strings.HasSuffix(target, "/releases/latest"):
			b, _ := json.Marshal(ghRelease{TagName: "v1.4.0", Assets: []struct {
				Name string `json:"name"`
				URL  string `json:"browser_download_url"`
				Size int64  `json:"size"`
			}{{ChecksumsName, "https://github.com/o/r/releases/download/v1.4.0/checksums.txt", 10}, {"evil", "https://evil.example/x", 1}}})
			return resp(200, string(b))
		case strings.HasSuffix(target, "checksums.txt"):
			return resp(200, string(art.sums))
		}
		return resp(403, "denied")
	}
	src := NewAgentEgressSource("o/r", ft, transport.AgentRef{ID: "a1", Mode: config.AgentModeDial})
	rel, err := src.Latest(context.Background())
	if err != nil || rel.Version != "1.4.0" {
		t.Fatalf("rel=%+v err=%v", rel, err)
	}
	a, _ := rel.Asset(ChecksumsName)
	rc, err := src.Fetch(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()

	// Запросы к агенту: GET /_agent/egress?url=<https github>, Accept пробрасывается.
	if len(ft.reqs) != 2 {
		t.Fatalf("запросов к агенту: %d", len(ft.reqs))
	}
	for _, r := range ft.reqs {
		if r.Method != http.MethodGet || r.URL.Path != "/_agent/egress" {
			t.Errorf("запрос: %s %s", r.Method, r.URL)
		}
		u, _ := url.Parse(r.URL.Query().Get("url"))
		if u.Scheme != "https" || !githubHosts[u.Host] {
			t.Errorf("url параметр: %s", u)
		}
	}
	if ft.reqs[0].Header.Get("Accept") != acceptJSON {
		t.Error("Accept не передан агенту")
	}

	// URL вне allowlist даже не уходит агенту.
	n := len(ft.reqs)
	if _, err := src.Fetch(context.Background(), Asset{Name: "evil", URL: "https://evil.example/x"}); err == nil {
		t.Error("ожидался отказ")
	}
	if len(ft.reqs) != n {
		t.Error("запрос на чужой хост ушёл агенту")
	}
	// 403 агента → ошибка.
	if _, err := src.Fetch(context.Background(), Asset{Name: "x", URL: "https://github.com/forbidden"}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("err = %v", err)
	}
}

func TestUploadSource(t *testing.T) {
	dir := t.TempDir()
	write := func(n, c string) { _ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600) }
	write("tgproxy_1.2.0_amd64.deb", "a")
	write("tgproxy_1.10.0_amd64.deb", "b")
	write("tgproxy_1.9.0_arm64.deb", "c")
	write("tgproxy_junk_amd64.deb", "d")
	write("random.txt", "e")
	write(ChecksumsName, "sums")
	write(SigName, "sig")
	_ = os.Mkdir(filepath.Join(dir, "sub"), 0o750)

	src := UploadSource{Dir: dir, Arch: "amd64"}
	rel, err := src.Latest(context.Background())
	if err != nil || rel.Version != "1.10.0" {
		t.Fatalf("rel=%+v err=%v", rel, err)
	}
	for _, n := range []string{"tgproxy_1.10.0_amd64.deb", ChecksumsName, SigName} {
		if _, ok := rel.Asset(n); !ok {
			t.Errorf("нет %s", n)
		}
	}
	a, _ := rel.Asset(ChecksumsName)
	rc, err := src.Fetch(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "sums" {
		t.Errorf("b = %q", b)
	}

	for _, bad := range []string{"../x", "a/b", "", ".hidden", "sub"} {
		if _, err := src.Fetch(context.Background(), Asset{Name: bad}); err == nil {
			t.Errorf("%q: ожидалась ошибка", bad)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link.deb")); err == nil {
		if _, err := src.Fetch(context.Background(), Asset{Name: "link.deb"}); err == nil {
			t.Error("симлинк должен отвергаться")
		}
	}
	if _, err := src.Fetch(context.Background(), Asset{Name: "absent.deb"}); err == nil {
		t.Error("ожидалась ошибка")
	}
	if _, err := (UploadSource{Dir: filepath.Join(dir, "none"), Arch: "amd64"}).Latest(context.Background()); !errors.Is(err, ErrNoRelease) {
		t.Errorf("err = %v", err)
	}
	if _, err := (UploadSource{Dir: t.TempDir(), Arch: "amd64"}).Latest(context.Background()); !errors.Is(err, ErrNoRelease) {
		t.Errorf("пустой каталог: %v", err)
	}
	if _, err := (UploadSource{Dir: filepath.Join(dir, "random.txt"), Arch: "amd64"}).Latest(context.Background()); err == nil {
		t.Error("не каталог: ожидалась ошибка")
	}
}

func TestUploadSourceFullFlow(t *testing.T) {
	k := newKeys(t)
	art := makeArtifacts(t, k, "1.5.0")
	dir := t.TempDir()
	for n, b := range art.files() {
		_ = os.WriteFile(filepath.Join(dir, n), b, 0o600)
	}
	root := t.TempDir()
	u, err := New(Config{
		Source: UploadSource{Dir: dir, Arch: "amd64"}, SourceName: "upload",
		DownloadsDir: filepath.Join(root, "p"), StagingDir: filepath.Join(root, "u"),
		Arch: "amd64", PubKeys: []verify.PublicKey{k.pub}, Current: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := u.Stage(context.Background(), "1.5.0"); err != nil {
		t.Fatal(err)
	}
}
