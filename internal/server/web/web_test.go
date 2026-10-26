package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/server/web"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
)

type fakeSession struct{}

func (fakeSession) Current(*http.Request) (string, string, bool) { return "vasya", "csrf-1", true }

func do(h http.Handler, method, url string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, url, nil))
	return rec
}

func TestStaticHeaders(t *testing.T) {
	rt := web.NewRouter(web.Deps{})
	tests := []struct{ url, ct string }{
		{"/static/css/app.css", "text/css; charset=utf-8"},
		{"/static/js/app.js", "text/javascript; charset=utf-8"},
		{"/static/fonts/ibm-plex-sans-latin-400-normal.woff2", "font/woff2"},
		{"/static/img/logo-64.png", "image/png"},
		{"/static/img/favicon.ico", "image/x-icon"},
	}
	for _, tc := range tests {
		rec := do(rt, http.MethodGet, views.Asset(strings.TrimPrefix(tc.url, "/static/")))
		if rec.Code != 200 {
			t.Fatalf("%s: %d", tc.url, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != tc.ct {
			t.Errorf("%s: Content-Type=%q", tc.url, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("%s: Cache-Control=%q", tc.url, got)
		}
		if rec.Header().Get("ETag") == "" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: нет ETag/nosniff", tc.url)
		}
	}
	// без ?v или с неверным v — не immutable
	for _, u := range []string{"/static/css/app.css", "/static/css/app.css?v=deadbeef0000"} {
		if cc := do(rt, http.MethodGet, u).Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
			t.Errorf("%s: не должно быть immutable (%q)", u, cc)
		}
	}
}

func TestStaticConditionalAndHead(t *testing.T) {
	rt := web.NewRouter(web.Deps{})
	etag := do(rt, http.MethodGet, "/static/css/app.css").Header().Get("ETag")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/static/css/app.css", nil)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", rec.Code)
	}
	if rec := do(rt, http.MethodHead, "/static/css/app.css"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("HEAD: %d len=%d", rec.Code, rec.Body.Len())
	}
	if rec := do(rt, http.MethodPost, "/static/css/app.css"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}

func TestStaticNoDirectoryListing(t *testing.T) {
	rt := web.NewRouter(web.Deps{})
	for _, u := range []string{
		"/static/", "/static", "/static/css", "/static/css/", "/static/fonts/", "/static/vendor/htmx",
		"/static/nope.css", "/static/../go.mod", "/static/%2e%2e/embed.go", "/static//css/app.css",
	} {
		rec := do(rt, http.MethodGet, u)
		if rec.Code == 200 || strings.Contains(rec.Body.String(), "<pre>") {
			t.Errorf("%s: code=%d body=%q", u, rec.Code, rec.Body.String())
		}
	}
}

func TestOverviewStubAndNotFound(t *testing.T) {
	rt := web.NewRouter(web.Deps{Version: "v1.2.3", Session: fakeSession{}})

	rec := do(rt, http.MethodGet, "/")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "<title>Обзор — tgproxy</title>") ||
		!strings.Contains(body, `aria-current="page"`) || !strings.Contains(body, "v1.2.3") ||
		!strings.Contains(body, `name="csrf" value="csrf-1"`) {
		t.Errorf("обзор: %d\n%s", rec.Code, body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type=%q", ct)
	}

	rec = do(rt, http.MethodGet, "/nope")
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Страница не найдена") ||
		!strings.Contains(rec.Body.String(), `class="sidebar"`) {
		t.Errorf("404: %d", rec.Code)
	}
}

func TestMountAndSetOverview(t *testing.T) {
	rt := web.NewRouter(web.Deps{})
	rt.Mount("GET /agents", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("agents")) }))
	if rec := do(rt, http.MethodGet, "/agents"); rec.Body.String() != "agents" {
		t.Errorf("mount: %q", rec.Body.String())
	}
	rt.SetOverview(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("real")) }))
	if rec := do(rt, http.MethodGet, "/"); rec.Body.String() != "real" {
		t.Errorf("override: %q", rec.Body.String())
	}
	if rec := do(rt, http.MethodGet, "/agents/x"); rec.Code != http.StatusNotFound {
		t.Errorf("подпуть без регистрации: %d", rec.Code)
	}
}
