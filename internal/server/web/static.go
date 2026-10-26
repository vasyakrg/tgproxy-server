// Package web — HTTP-слой веб-UI: раздача статики и роутер страниц.
package web

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	webfs "github.com/vasyakrg/tgproxy-server/web"
)

const (
	cacheImmutable  = "public, max-age=31536000, immutable"
	cacheRevalidate = "public, no-cache"
)

var contentTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".json":  "application/json",
	".png":   "image/png",
	".ico":   "image/x-icon",
	".svg":   "image/svg+xml",
	".woff2": "font/woff2",
	".txt":   "text/plain; charset=utf-8",
	".md":    "text/markdown; charset=utf-8",
}

// StaticHandler раздаёт вшитый web.Static под /static/.
// Ссылки с ?v=<hash> (views.Asset) кэшируются как immutable на год; остальные — с ревалидацией по ETag.
// Листинг директорий запрещён (404), методы кроме GET/HEAD — 405.
func StaticHandler() http.Handler {
	root, err := fs.Sub(webfs.Static, "static")
	if err != nil {
		panic("web: embed static: " + err.Error()) // невозможно: каталог static вшит на этапе сборки
	}
	return http.StripPrefix("/static/", staticFS(root))
}

func staticFS(root fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Path
		if name == "" || strings.HasSuffix(name, "/") || !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		f, err := root.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close() //nolint:errcheck // read-only embed
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		rs, ok := f.(readSeeker)
		if !ok {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		h := w.Header()
		if ct, ok := contentTypes[strings.ToLower(path.Ext(name))]; ok {
			h.Set("Content-Type", ct)
		}
		h.Set("X-Content-Type-Options", "nosniff")
		hash := views.AssetHash(name)
		if hash != "" {
			h.Set("ETag", `"`+hash+`"`)
		}
		if hash != "" && r.URL.Query().Get("v") == hash {
			h.Set("Cache-Control", cacheImmutable)
		} else {
			h.Set("Cache-Control", cacheRevalidate)
		}
		// modtime нулевой: у embed.FS его нет; условные запросы идут по ETag.
		http.ServeContent(w, r, name, st.ModTime(), rs)
	})
}

type readSeeker interface {
	Read([]byte) (int, error)
	Seek(int64, int) (int64, error)
}
