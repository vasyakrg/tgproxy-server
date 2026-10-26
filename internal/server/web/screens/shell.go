// Package screens — экраны веб-UI (Обзор, Ошибки, ...): HTTP-хендлеры и templ-вьюхи.
package screens

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
)

// Shell — каркас страницы (реализует *web.Router).
type Shell interface {
	Meta(r *http.Request, title, active string) views.PageMeta
	Render(w http.ResponseWriter, r *http.Request, status int, meta views.PageMeta, body templ.Component)
}

// AgentLister — реестр агентов (реализует *agents.Registry).
type AgentLister interface {
	List() []agents.State
}

// isFragment: htmx-запрос, которому нужен кусок страницы, а не целый документ.
// Восстановление истории браузера (кнопка «назад») требует полную страницу.
func isFragment(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
}

func renderFragment(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Add("Vary", "HX-Request")
	w.WriteHeader(status)
	_ = c.Render(r.Context(), w)
}

func renderPage(sh Shell, w http.ResponseWriter, r *http.Request, status int, title, nav string, c templ.Component) {
	w.Header().Add("Vary", "HX-Request")
	sh.Render(w, r, status, sh.Meta(r, title, nav), c)
}

// ---------- форматирование (ru) ----------

func comma(s string) string { return strings.Replace(s, ".", ",", 1) }

// fmtRPS: до 10 — один знак после запятой, дальше — целое.
func fmtRPS(v float64) string {
	if v < 10 {
		return comma(strconv.FormatFloat(v, 'f', 1, 64))
	}
	return strconv.FormatFloat(v, 'f', 0, 64)
}

func fmtPct(v float64) string { return comma(strconv.FormatFloat(v, 'f', 1, 64)) + " %" }

func fmtMs(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) + " мс" }

func fmtInt(n int64) string { return strconv.FormatInt(n, 10) }

func clockIn(t time.Time, loc *time.Location, layout string) string {
	if t.IsZero() {
		return "—"
	}
	if loc != nil {
		t = t.In(loc)
	}
	return t.Format(layout)
}
