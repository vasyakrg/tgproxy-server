package web

import (
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
)

// Session отдаёт данные текущего пользователя для сайдбара. Реализует пакет auth.
type Session interface {
	// Current возвращает логин и CSRF-токен; ok=false — сессии нет.
	Current(r *http.Request) (user, csrf string, ok bool)
}

// Deps — зависимости веб-слоя. Все поля необязательны.
type Deps struct {
	Version string       // версия сервера (в сайдбаре)
	Session Session      // nil — сайдбар без логина/CSRF
	Logger  *slog.Logger // nil — slog.Default()
}

// Router — корневой обработчик веб-UI.
type Router struct {
	mux  *http.ServeMux
	deps Deps
	home atomic.Pointer[http.Handler]
}

// NewRouter собирает каркас: /static/, заглушка «Обзор» на /, 404 на всё остальное.
// Реальные экраны подключаются через Mount (до начала обслуживания).
func NewRouter(deps Deps) *Router {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	rt := &Router{mux: http.NewServeMux(), deps: deps}
	rt.mux.Handle("/static/", StaticHandler())
	rt.mux.HandleFunc("GET /{$}", rt.serveHome)
	rt.mux.HandleFunc("/", rt.notFound)
	return rt
}

// Mount регистрирует обработчик экрана (паттерн http.ServeMux, например "GET /agents").
// Паттерн "GET /{$}" занят заглушкой Обзора — реальный Обзор подключается через SetOverview.
func (rt *Router) Mount(pattern string, h http.Handler) { rt.mux.Handle(pattern, h) }

// SetOverview заменяет заглушку Обзора реальным экраном (вызывать до начала обслуживания).
func (rt *Router) SetOverview(h http.Handler) { rt.home.Store(&h) }

func (rt *Router) serveHome(w http.ResponseWriter, r *http.Request) {
	if h := rt.home.Load(); h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	rt.overview(w, r)
}

// ServeHTTP реализует http.Handler.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) { rt.mux.ServeHTTP(w, r) }

// Meta собирает PageMeta для запроса: версия, логин и CSRF из Session.
func (rt *Router) Meta(r *http.Request, title, active string) views.PageMeta {
	m := views.PageMeta{Title: title, Active: active, Version: rt.deps.Version}
	if rt.deps.Session != nil {
		if user, csrf, ok := rt.deps.Session.Current(r); ok {
			m.User, m.CSRF = user, csrf
		}
	}
	return m
}

// Render отдаёт страницу на Layout с заданным статусом.
func (rt *Router) Render(w http.ResponseWriter, r *http.Request, status int, meta views.PageMeta, body templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := views.Layout(meta, body).Render(r.Context(), w); err != nil {
		rt.deps.Logger.WarnContext(r.Context(), "web: render failed", "path", r.URL.Path, "err", err)
	}
}

func (rt *Router) overview(w http.ResponseWriter, r *http.Request) {
	rt.Render(w, r, http.StatusOK, rt.Meta(r, "Обзор", views.NavOverview), views.OverviewStub())
}

func (rt *Router) notFound(w http.ResponseWriter, r *http.Request) {
	rt.Render(w, r, http.StatusNotFound, rt.Meta(r, "Не найдено", ""), views.NotFound())
}
