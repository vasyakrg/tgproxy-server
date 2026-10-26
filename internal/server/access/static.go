// Package access решает, подходит ли запрос под правила доступа (сеть и/или
// скрытый ключ) и применяет rate-limit правила. Правила — из конфига
// (NewStatic) или из БД с кэшем и инвалидацией по версии (NewFromStore).
package access

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// ErrDenied — ни одно правило не подошло.
var ErrDenied = errors.New("access: denied")

// RuleInfo описывает сработавшее правило.
type RuleInfo struct {
	ID   int64 // 0 для правил из конфига
	Name string
	RPS  float64
}

type rule struct {
	info   RuleInfo
	cidrs  []netip.Prefix
	hash   []byte
	score  int    // 3 ключ+сеть, 2 ключ, 1 сеть
	limKey string // ключ лимитера: стабилен между снимками
}

func newRule(id int64, name string, cidrs []netip.Prefix, hash []byte, rps float64) rule {
	ru := rule{info: RuleInfo{ID: id, Name: name, RPS: rps}, cidrs: cidrs, hash: hash}
	switch {
	case len(hash) > 0 && len(cidrs) > 0:
		ru.score = 3
	case len(hash) > 0:
		ru.score = 2
	default:
		ru.score = 1
	}
	if id > 0 {
		ru.limKey = "id:" + strconv.FormatInt(id, 10)
	} else {
		ru.limKey = "name:" + name
	}
	return ru
}

// NewStatic строит Checker из конфиговых правил. Правило без сети и без ключа —
// ошибка (открытый relay).
func NewStatic(rules []config.AccessRule, trusted []netip.Prefix, opts ...Option) (*Checker, error) {
	c := newChecker(trusted, opts)
	rs := make([]rule, 0, len(rules))
	for _, r := range rules {
		hasKey := r.HasKey()
		if hasKey && len(r.KeyHash) != sha256.Size {
			return nil, errors.New("access: rule " + r.Name + " has key without loaded hash")
		}
		if !hasKey && len(r.CIDRs) == 0 {
			return nil, errors.New("access: rule " + r.Name + " has neither cidrs nor key")
		}
		rs = append(rs, newRule(0, r.Name, r.CIDRs, r.KeyHash, r.RPS))
	}
	c.install(&snapshot{rules: rs})
	return c, nil
}

// Check возвращает наиболее специфичное подходящее правило или ErrDenied.
func (c *Checker) Check(r *http.Request, route tgapi.Route) (RuleInfo, error) {
	rules := c.snap.Load().rules
	ip := c.clientIP(r)
	key := route.ClientKey
	if key == "" {
		key = r.Header.Get(tgapi.HeaderProxyKey)
	}
	var sum [sha256.Size]byte
	if key != "" {
		sum = sha256.Sum256([]byte(key))
	}
	best := -1
	for i := range rules {
		ru := &rules[i]
		var ok bool
		if key != "" {
			// сравниваем со всеми ключевыми правилами без раннего выхода
			ok = ru.score >= 2 && subtle.ConstantTimeCompare(sum[:], ru.hash) == 1
		} else {
			ok = ru.score == 1
		}
		if ok && len(ru.cidrs) > 0 && !contains(ru.cidrs, ip) {
			ok = false
		}
		if ok && (best < 0 || ru.score > rules[best].score) {
			best = i
		}
	}
	if best < 0 {
		return RuleInfo{}, ErrDenied
	}
	ru := &rules[best]
	if err := c.limit(r.Context(), ru); err != nil {
		return RuleInfo{}, err
	}
	return ru.info, nil
}

func contains(ps []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP: RemoteAddr; X-Forwarded-For учитывается, только если сам
// RemoteAddr — доверенный прокси (берём правый недоверенный адрес).
func (c *Checker) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	remote = remote.Unmap()
	if !contains(c.trusted, remote) {
		return remote
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return netip.Addr{} // мусор в цепочке — не доверяем
		}
		a = a.Unmap()
		if !contains(c.trusted, a) {
			return a
		}
	}
	return remote
}

// ClientIP возвращает адрес клиента с учётом trusted_proxies (та же логика, что при проверке
// доступа); пустая строка — адрес не определён.
func (c *Checker) ClientIP(r *http.Request) string {
	if ip := c.clientIP(r); ip.IsValid() {
		return ip.String()
	}
	return ""
}
