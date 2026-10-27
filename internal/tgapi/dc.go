package tgapi

import (
	"net/netip"
	"slices"
)

// Вшитая таблица адресов дата-центров Telegram. Источник — публичные адреса
// ядра сети (совпадают с essentials.TelegramCoreAddresses в mtg v2.2.8;
// сверка — в internal/mtproto, tgapi не импортирует mtg). Порт всегда 443.
// Обновляется только релизом.
var dcTable = map[int]struct{ v4, v6 []netip.AddrPort }{
	1:   {ap("149.154.175.50:443"), ap("[2001:b28:f23d:f001::a]:443")},
	2:   {ap("149.154.167.51:443", "95.161.76.100:443"), ap("[2001:67c:4e8:f002::a]:443")},
	3:   {ap("149.154.175.100:443"), ap("[2001:b28:f23d:f003::a]:443")},
	4:   {ap("149.154.167.91:443"), ap("[2001:67c:4e8:f004::a]:443")},
	5:   {ap("149.154.171.5:443"), ap("[2001:b28:f23f:f005::a]:443")},
	203: {ap("91.105.192.100:443"), ap("[2a0a:f280:203:a:5000::100]:443")},
}

// Официальные сети Telegram (AS62041/AS59930/AS62014/AS211157).
var telegramPrefixes = pfx(
	"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
	"91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22", "95.161.64.0/20",
	"185.76.151.0/24", "91.105.192.0/23",
	"2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48",
	"2001:b28:f23c::/48", "2a0a:f280::/32",
)

func ap(s ...string) []netip.AddrPort {
	out := make([]netip.AddrPort, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddrPort(v)
	}
	return out
}

func pfx(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

func absDC(dc int) int {
	if dc < 0 {
		return -dc
	}
	return dc
}

// KnownDC сообщает, есть ли DC в таблице. Отрицательный номер (media)
// трактуется как abs(dc).
func KnownDC(dc int) bool {
	_, ok := dcTable[absDC(dc)]
	return ok
}

// DCAddrs возвращает копию адресов DC (IPv4 или IPv6); для неизвестного DC — nil.
func DCAddrs(dc int, v6 bool) []netip.AddrPort {
	e, ok := dcTable[absDC(dc)]
	if !ok {
		return nil
	}
	if v6 {
		return slices.Clone(e.v6)
	}
	return slices.Clone(e.v4)
}

// KnownDCs возвращает отсортированные положительные номера известных DC.
func KnownDCs() []int {
	out := make([]int, 0, len(dcTable))
	for k := range dcTable {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TelegramPrefixes возвращает копию списка сетей Telegram (allowlist dial-control).
func TelegramPrefixes() []netip.Prefix {
	return slices.Clone(telegramPrefixes)
}
