package agent

import (
	"net/http"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

const (
	defaultTimeout = 30 * time.Second
	maxTimeout     = 65 * time.Second
)

// requestTimeout разбирает X-TGP-Timeout-Ms: нет/мусор → 30s, потолок 65s.
func requestTimeout(h http.Header) time.Duration {
	raw := h.Get(tgapi.HeaderTimeoutMs)
	if raw == "" {
		return defaultTimeout
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ms <= 0 {
		return defaultTimeout
	}
	if ms > int64(maxTimeout/time.Millisecond) {
		return maxTimeout
	}
	return time.Duration(ms) * time.Millisecond
}
