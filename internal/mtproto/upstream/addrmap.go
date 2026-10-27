package upstream

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/9seconds/mtg/v2/essentials"
)

// addrMap строит таблицу «нормализованный адрес → номер DC» из публичных
// адресов ядра сети Telegram (essentials.TelegramCoreAddresses).
func addrMap() map[netip.AddrPort]int {
	m := make(map[netip.AddrPort]int)
	for dc, list := range essentials.TelegramCoreAddresses {
		for _, s := range list {
			if ap, err := netip.ParseAddrPort(s); err == nil {
				m[ap] = dc
			}
		}
	}
	return m
}

// parseAddr разбирает "host:port" в netip.AddrPort; хост обязан быть IP.
func parseAddr(address string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)), nil
}
