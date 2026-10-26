package tgapi

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// WriteError writes a Telegram-style JSON error:
// {"ok":false,"error_code":N,"description":"..."}; a positive retryAfter adds
// parameters.retry_after and the Retry-After header.
func WriteError(w http.ResponseWriter, code int, desc string, retryAfter int) {
	env := Envelope{OK: false, ErrorCode: code, Description: desc}
	if retryAfter > 0 {
		env.Parameters = &ResponseParameters{RetryAfter: retryAfter}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	body, _ := json.Marshal(env) // plain struct: cannot fail
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = w.Write(body)
}
