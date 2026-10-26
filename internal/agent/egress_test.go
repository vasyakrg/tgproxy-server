package agent

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// egressEnv — TLS-сервер, подставляемый вместо любых хостов; hosts фиксирует,
// к каким хостам реально пошёл бы агент.
type egressEnv struct {
	h     *egressHandler
	mu    sync.Mutex
	hosts []string
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newEgressEnv(t *testing.T, upstream http.HandlerFunc) *egressEnv {
	t.Helper()
	srv := httptest.NewTLSServer(upstream)
	t.Cleanup(srv.Close)
	e := &egressEnv{}
	base := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- тест
	e.h = &egressHandler{
		allow: egressAllowlist,
		rt: rtFunc(func(r *http.Request) (*http.Response, error) {
			e.mu.Lock()
			e.hosts = append(e.hosts, r.URL.Host)
			e.mu.Unlock()
			r2 := r.Clone(r.Context())
			u := *r.URL
			su, _ := url.Parse(srv.URL)
			u.Host = su.Host
			r2.URL = &u
			r2.Host = r.URL.Host
			return base.RoundTrip(r2)
		}),
		maxBytes: 1 << 10,
		timeout:  5 * time.Second,
	}
	return e
}

func (e *egressEnv) get(method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), method, "/_agent/egress?url="+url.QueryEscape(target), nil)
	e.h.ServeHTTP(rec, r)
	return rec
}

func TestEgressAllowed(t *testing.T) {
	e := newEgressEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") != "tgproxy-agent-egress" {
			http.Error(w, "headers", 400)
			return
		}
		_, _ = io.WriteString(w, "payload")
	})
	for _, host := range []string{"github.com", "api.github.com", "objects.githubusercontent.com", "GitHub.com", "github.com:443", "github.com."} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/_agent/egress?url="+url.QueryEscape("https://"+host+"/a/b?c=d"), nil)
		r.Header.Set("Accept", "application/vnd.github+json")
		e.h.ServeHTTP(rec, r)
		if rec.Code != 200 || rec.Body.String() != "payload" {
			t.Errorf("%s: code=%d body=%q", host, rec.Code, rec.Body.String())
		}
	}
}

func TestEgressDenied(t *testing.T) {
	e := newEgressEnv(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "x") })
	for name, target := range map[string]string{
		"чужой хост":    "https://evil.example/x",
		"поддомен":      "https://evil.github.com/x",
		"суффикс":       "https://notgithub.com/x",
		"префикс-обман": "https://github.com.evil.example/x",
		"http":          "http://github.com/x",
		"IP-литерал":    "https://140.82.112.3/x",
		"IPv6-литерал":  "https://[::1]/x",
		"loopback":      "https://127.0.0.1/x",
		"userinfo":      "https://github.com@evil.example/x",
		"userinfo2":     "https://user:pw@github.com/x",
		"чужой порт":    "https://github.com:8443/x",
		"file":          "file:///etc/passwd",
		"без схемы":     "github.com/x",
		"пустой":        "",
		"opaque":        "https:github.com",
		"мусор":         "://",
		"gopher":        "gopher://github.com/",
	} {
		rec := e.get(http.MethodGet, target)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s (%q): code = %d, want 403", name, target, rec.Code)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.hosts) != 0 {
		t.Fatalf("агент ходил на %v при отказе", e.hosts)
	}
}

func TestEgressMethodNotGET(t *testing.T) {
	e := newEgressEnv(t, func(http.ResponseWriter, *http.Request) {})
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead} {
		if rec := e.get(m, "https://github.com/x"); rec.Code != http.StatusForbidden {
			t.Errorf("%s: code = %d", m, rec.Code)
		}
	}
}

func TestEgressNoURLParam(t *testing.T) {
	e := newEgressEnv(t, func(http.ResponseWriter, *http.Request) {})
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/_agent/egress", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestEgressRedirects(t *testing.T) {
	e := newEgressEnv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-allowed":
			http.Redirect(w, r, "https://objects.githubusercontent.com/file", http.StatusFound)
		case "/to-evil":
			http.Redirect(w, r, "https://evil.example/file", http.StatusFound)
		case "/to-http":
			http.Redirect(w, r, "http://github.com/file", http.StatusFound)
		case "/to-ip":
			http.Redirect(w, r, "https://169.254.169.254/latest", http.StatusFound)
		case "/to-userinfo":
			http.Redirect(w, r, "https://github.com@evil.example/", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "https://github.com/loop", http.StatusFound)
		default:
			_, _ = io.WriteString(w, "final")
		}
	})
	if rec := e.get(http.MethodGet, "https://github.com/to-allowed"); rec.Code != 200 || rec.Body.String() != "final" {
		t.Errorf("внутри allowlist: code=%d body=%q", rec.Code, rec.Body.String())
	}
	for _, p := range []string{"to-evil", "to-http", "to-ip", "to-userinfo", "loop"} {
		if rec := e.get(http.MethodGet, "https://github.com/"+p); rec.Code != http.StatusForbidden {
			t.Errorf("%s: code = %d, want 403", p, rec.Code)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, h := range e.hosts {
		if h != "github.com" && h != "objects.githubusercontent.com" {
			t.Errorf("запрос ушёл на %s", h)
		}
	}
}

func TestEgressLimits(t *testing.T) {
	e := newEgressEnv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/declared":
			w.Header().Set("Content-Length", "5000")
			_, _ = io.WriteString(w, strings.Repeat("a", 5000))
		case "/chunked":
			f := w.(http.Flusher)
			for i := 0; i < 5; i++ {
				_, _ = io.WriteString(w, strings.Repeat("a", 500))
				f.Flush()
			}
		case "/missing":
			http.NotFound(w, r)
		default:
			_, _ = io.WriteString(w, strings.Repeat("a", 1024))
		}
	})
	if rec := e.get(http.MethodGet, "https://github.com/declared"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("declared: code = %d", rec.Code)
	}
	if rec := e.get(http.MethodGet, "https://github.com/exact"); rec.Code != 200 || rec.Body.Len() != 1024 {
		t.Errorf("exact: code=%d len=%d", rec.Code, rec.Body.Len())
	}
	if rec := e.get(http.MethodGet, "https://github.com/missing"); rec.Code != 404 {
		t.Errorf("статус upstream должен пробрасываться: %d", rec.Code)
	}
	func() {
		defer func() {
			if r := recover(); r != http.ErrAbortHandler {
				t.Errorf("chunked > лимита: recover = %v, want ErrAbortHandler", r)
			}
		}()
		e.get(http.MethodGet, "https://github.com/chunked")
	}()
}

func TestEgressUpstreamDown(t *testing.T) {
	h := &egressHandler{
		allow:    egressAllowlist,
		rt:       rtFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }),
		maxBytes: 10, timeout: time.Second,
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/_agent/egress?url=https%3A%2F%2Fgithub.com%2Fx", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestEgressDialControl(t *testing.T) {
	for _, a := range []string{"127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443", "169.254.169.254:80", "[::1]:443", "[::ffff:127.0.0.1]:443", "0.0.0.0:1", "224.0.0.1:1"} {
		if err := egressDialControl("tcp", a, nil); err == nil {
			t.Errorf("%s: ожидался отказ", a)
		}
	}
	if err := egressDialControl("tcp", "140.82.112.3:443", nil); err != nil {
		t.Errorf("публичный адрес отвергнут: %v", err)
	}
	for _, bad := range []string{"nohostport", "github.com:443"} {
		if err := egressDialControl("tcp", bad, nil); err == nil {
			t.Errorf("%s: ожидалась ошибка", bad)
		}
	}
}

func TestEgressRouteRegistered(t *testing.T) {
	a := &Agent{}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	resp, err := doReq(http.MethodPost, srv.URL+"/_agent/egress?url=https://github.com/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST: code = %d", resp.StatusCode)
	}
	resp, err = doReq(http.MethodGet, srv.URL+"/_agent/egress?url=https://evil.example/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET evil: code = %d", resp.StatusCode)
	}
}

func TestNewEgressHandlerDefaults(t *testing.T) {
	h := newEgressHandler()
	if h.maxBytes != 200<<20 || h.timeout != 10*time.Minute || len(h.allow) == 0 {
		t.Fatalf("%+v", h)
	}
}

func doReq(method, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, u, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}
