package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type ctxKey struct{}

// SessionFromContext возвращает сессию, положенную RequireAuth.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(*Session)
	return s, ok
}

// ContentSecurityPolicy — CSP админки (без inline-скриптов и стилей).
const ContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'"

// SecurityHeaders выставляет защитные заголовки на каждый ответ.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// Protect = SecurityHeaders + http.CrossOriginProtection на изменяющие методы
// (кросс-доменный POST/PUT/DELETE -> 403).
func Protect(next http.Handler) http.Handler {
	return SecurityHeaders(http.NewCrossOriginProtection().Handler(next))
}

// RequireAuth пропускает только запросы с действующей сессией. Без сессии:
// /api/* -> 401 JSON; htmx-запрос -> 401 + HX-Redirect: /login; иначе 302 на /login.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := a.Authenticate(r)
		if err != nil {
			if !errors.Is(err, ErrNoSession) {
				a.log.Error("authenticate", "err", err)
				writeJSON(w, http.StatusInternalServerError, errBody{Error: "internal"})
				return
			}
			deny(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	})
}

func deny(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/"):
		writeJSON(w, http.StatusUnauthorized, errBody{Error: "unauthorized", Message: "требуется вход"})
	case r.Header.Get("HX-Request") == "true":
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusUnauthorized)
	default:
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}
