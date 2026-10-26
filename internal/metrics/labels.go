package metrics

import "strconv"

// Фиксированный набор значений метки code.
const (
	CodeProxyErr = "proxy_err" // ответа от upstream не было (code <= 0)
	Code5xx      = "5xx"
	CodeOther    = "other"
)

// CodeLabel сводит HTTP-код к ограниченному набору
// 200|400|401|403|404|409|413|429|5xx|proxy_err|other.
func CodeLabel(code int) string {
	switch code {
	case 200, 400, 401, 403, 404, 409, 413, 429:
		return strconv.Itoa(code)
	}
	switch {
	case code <= 0:
		return CodeProxyErr
	case code >= 500 && code <= 599:
		return Code5xx
	}
	return CodeOther
}
