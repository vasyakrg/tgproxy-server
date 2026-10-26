package metrics

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ErrBearerRequired — пустой bearer при не-loopback листенере.
var ErrBearerRequired = errors.New("metrics: bearer token is required for non-loopback listener")

// NewHandler возвращает /metrics-handler с проверкой bearer (constant-time).
// Пустой bearer допустим только при allowNoAuthOnLoopback=true — флаг
// выставляет вызывающий, убедившись, что listener слушает loopback.
func NewHandler(reg *prometheus.Registry, bearer string, allowNoAuthOnLoopback bool) (http.Handler, error) {
	inner := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	if bearer == "" {
		if !allowNoAuthOnLoopback {
			return nil, ErrBearerRequired
		}
		return inner, nil
	}
	want := sha256.Sum256([]byte(bearer))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "bearer "
		h := r.Header.Get("Authorization")
		var got [sha256.Size]byte
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			got = sha256.Sum256([]byte(h[len(prefix):]))
		} else {
			h = "" // сравнение всё равно выполняется с нулевым хешем
		}
		if h == "" || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	}), nil
}
