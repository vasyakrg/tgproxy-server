package ban

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const resolveTimeout = 2 * time.Second

// Resolver разрешает имя хоста агента в адреса.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// StaticProtector — защита от самоблокировки. Не банятся:
//   - loopback, приватные (RFC 1918 / ULA), link-local, multicast, unspecified: за прокси-цепочкой
//     клиент без trusted_proxies выглядит как такой адрес, бан заблокировал бы всех;
//   - trusted_proxies;
//   - адреса агентов (хост из url; имена разрешаются через DNS);
//   - сети действующих правил доступа (клиент из разрешённой сети без ключа — ошибка настройки,
//     а не атака; сети /0 не считаются защитой, иначе автобан не работал бы при правилах «любая сеть + ключ»).
type StaticProtector struct {
	Trusted []netip.Prefix
	// Agents / Networks читаются в момент проверки (автобан и ручной бан случаются редко).
	Agents   func(ctx context.Context) ([]store.Agent, error)
	Networks func(ctx context.Context) ([]netip.Prefix, error)
	Resolve  Resolver // nil — системный DNS
}

// Protected реализует Protector.
func (p StaticProtector) Protected(ctx context.Context, pf netip.Prefix) string {
	a := pf.Addr().Unmap()
	switch {
	case !a.IsValid() || a.IsUnspecified():
		return "адрес не определён"
	case a.IsLoopback():
		return "loopback-адрес"
	case a.IsPrivate():
		return "приватный адрес (адрес прокси-цепочки)"
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast():
		return "служебный адрес"
	}
	for _, t := range p.Trusted {
		if t.Overlaps(pf) {
			return "адрес доверенного прокси (trusted_proxies)"
		}
	}
	if p.Networks != nil {
		if nets, err := p.Networks(ctx); err == nil {
			for _, n := range nets {
				if n.Bits() > 0 && n.Overlaps(pf) {
					return "сеть правила доступа"
				}
			}
		}
	}
	if p.Agents != nil {
		if list, err := p.Agents(ctx); err == nil {
			for _, ag := range list {
				if p.agentMatches(ctx, ag, pf) {
					return "адрес агента " + ag.ID
				}
			}
		}
	}
	return ""
}

func (p StaticProtector) agentMatches(ctx context.Context, ag store.Agent, pf netip.Prefix) bool {
	if ag.URL == "" {
		return false
	}
	u, err := url.Parse(ag.URL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		return pf.Contains(a.Unmap())
	}
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	resolve := p.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	addrs, err := resolve(rctx, host)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if pf.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}
