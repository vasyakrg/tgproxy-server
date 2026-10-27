// Package geoip определяет страну клиента по IP из локальной базы mmdb
// (DB-IP «IP to Country Lite», CC BY 4.0). Никаких сетевых запросов: база лежит
// в пакете (/usr/share/tgproxy/geoip) и читается mmap-ом. Нет файла — Lookup
// просто возвращает пустую строку, остальной сервер работает как обычно.
package geoip

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DefaultFile — путь базы по умолчанию (кладёт deb-пакет).
const DefaultFile = "/usr/share/tgproxy/geoip/dbip-country-lite.mmdb"

// Attribution — текст атрибуции CC BY 4.0 для футера и README.
const (
	AttributionText = "IP Geolocation by DB-IP"
	AttributionURL  = "https://db-ip.com"
)

// DB — открытая база. Нулевое значение и nil безопасны: Lookup вернёт "".
type DB struct {
	r *maxminddb.Reader
}

type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Open открывает базу. Пустой path или отсутствующий файл — не ошибка:
// возвращается (nil, nil), флаги в UI просто не показываются.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // «базы нет» — штатный режим
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil //nolint:nilnil // «базы нет» — штатный режим
		}
		return nil, fmt.Errorf("geoip: %w", err)
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open %s: %w", path, err)
	}
	return &DB{r: r}, nil
}

// Close освобождает базу.
func (d *DB) Close() error {
	if d == nil || d.r == nil {
		return nil
	}
	return d.r.Close()
}

// Available сообщает, что база загружена.
func (d *DB) Available() bool { return d != nil && d.r != nil }

// Lookup возвращает ISO 3166-1 alpha-2 (верхний регистр). Приватные,
// loopback, link-local и прочие нероутируемые адреса, а также ненайденные — "".
func (d *DB) Lookup(ip netip.Addr) string {
	if !d.Available() || !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap()
	if !routable(ip) {
		return ""
	}
	var rec record
	if err := d.r.Lookup(ip).Decode(&rec); err != nil {
		return ""
	}
	return normalize(rec.Country.ISOCode)
}

// LookupString — Lookup для строкового адреса ("" при ошибке разбора).
func (d *DB) LookupString(s string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return d.Lookup(ip)
}

func routable(ip netip.Addr) bool {
	switch {
	case ip.IsPrivate(), ip.IsLoopback(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified(), ip.IsInterfaceLocalMulticast():
		return false
	}
	if ip.Is4() {
		b := ip.As4()
		// CGNAT 100.64/10, TEST-NET, benchmark 198.18/15, 240/4 (reserved)
		switch {
		case b[0] == 100 && b[1]&0xC0 == 64,
			b[0] == 192 && b[1] == 0 && b[2] == 2,
			b[0] == 198 && b[1] == 51 && b[2] == 100,
			b[0] == 203 && b[1] == 0 && b[2] == 113,
			b[0] == 198 && (b[1] == 18 || b[1] == 19),
			b[0] >= 240:
			return false
		}
	}
	return true
}

func normalize(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return code
}

// Flag возвращает emoji-флаг из ISO-кода (regional indicator symbols); "" для
// некорректного кода. Картинок и сетевых запросов нет.
func Flag(code string) string {
	code = normalize(code)
	if code == "" {
		return ""
	}
	const base = 0x1F1E6 - 'A'
	return string([]rune{base + rune(code[0]), base + rune(code[1])})
}
