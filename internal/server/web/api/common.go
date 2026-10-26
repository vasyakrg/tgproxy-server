// Package api — JSON-ручки админки (/api/v1/stats/*, /api/v1/errors). Хендлеры сами
// сессию не проверяют: wiring оборачивает Routes в RequireAuth (+Protect).
package api

import (
	"encoding/json"
	"net/http"
)

// Wrap оборачивает хендлер (RequireAuth, Protect и т.п.). nil — без обёртки.
type Wrap func(http.Handler) http.Handler

func (w Wrap) apply(h http.Handler) http.Handler {
	if w == nil {
		return h
	}
	return w(h)
}

type errBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, errBody{Error: kind, Message: msg})
}
