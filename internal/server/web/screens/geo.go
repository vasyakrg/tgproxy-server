package screens

import (
	"net/netip"
	"net/url"

	"github.com/vasyakrg/tgproxy-server/internal/geoip"
)

// GeoLookup — определение страны по IP (реализует *geoip.DB; nil и nil-база допустимы).
type GeoLookup interface {
	LookupString(ip string) string
	Available() bool
}

// geoView возвращает ISO-код и emoji-флаг для IP; пустые, если базы нет или адрес не публичный.
func geoView(g GeoLookup, ip string) (code, flag string) {
	if g == nil || !g.Available() {
		return "", ""
	}
	code = g.LookupString(ip)
	return code, geoip.Flag(code)
}

func geoAvailable(g GeoLookup) bool { return g != nil && g.Available() }

// banFormURL — ссылка на форму бана для IP (из экрана «Ошибки»).
func banFormURL(ip, from string) string {
	v := url.Values{}
	v.Set("ip", ip)
	v.Set("from", from)
	return "/bans/new?" + v.Encode()
}

func addrString(p netip.Prefix) string {
	if p.Addr().Is4() {
		return p.Addr().String()
	}
	return p.String()
}
