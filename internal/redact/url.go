package redact

import "net/url"

// URL renders u with the user password, bot token and client key masked.
func URL(u *url.URL) string {
	if u == nil {
		return ""
	}
	return String(u.Redacted())
}
