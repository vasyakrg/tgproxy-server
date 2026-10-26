package proxy

import (
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// hopByHop — заголовки уровня соединения (RFC 9110 §7.6.1).
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// stripped — заголовки клиента, которые не должны дойти до агента.
var stripped = []string{
	"Forwarded", "X-Real-Ip", "Via", "Cookie", "Authorization", "Expect",
	tgapi.HeaderProxyKey, tgapi.HeaderRequestID,
}

// isInternal сообщает, что заголовок служебный (X-TGP-*).
func isInternal(k string) bool {
	return strings.HasPrefix(textproto.CanonicalMIMEHeaderKey(k), "X-Tgp-")
}

// cleanRequestHeaders удаляет из заголовков клиента всё, что нельзя
// пересылать агенту, и проставляет служебные X-Request-ID и X-TGP-Bot-ID.
// X-TGP-Timeout-Ms и X-TGP-Attempt ставит router.
func cleanRequestHeaders(h http.Header, requestID string, botID int64) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
	for _, k := range stripped {
		h.Del(k)
	}
	for k := range h {
		if isInternal(k) || strings.HasPrefix(textproto.CanonicalMIMEHeaderKey(k), "X-Forwarded-") {
			delete(h, k)
		}
	}
	h.Set(tgapi.HeaderRequestID, requestID)
	h.Set(tgapi.HeaderBotID, strconv.FormatInt(botID, 10))
}

// copyResponseHeaders переносит заголовки ответа агента клиенту без
// hop-by-hop и служебных X-TGP-*; добавляет X-Request-ID.
func copyResponseHeaders(dst, src http.Header, requestID string) {
	skip := map[string]bool{}
	for _, v := range src.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			skip[textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for _, k := range hopByHop {
		skip[k] = true
	}
	for k, vs := range src {
		if skip[k] || isInternal(k) || k == tgapi.HeaderRequestID {
			continue
		}
		dst[k] = append([]string(nil), vs...)
	}
	dst.Set(tgapi.HeaderRequestID, requestID)
}
