// Package link строит и разбирает ссылки подключения к MTProto-прокси
// (tg://proxy и https://t.me/proxy) с FakeTLS-секретом «ee».
//
// Ключ секрета никогда не попадает в тексты ошибок.
package link

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

const (
	keyLen        = 16
	fakeTLSPrefix = 0xee
	maxDomainLen  = 253
)

// ErrNotFakeTLS — секрет не в формате FakeTLS (dd или без префикса).
var ErrNotFakeTLS = errors.New("link: нужен FakeTLS ee-секрет")

// Build собирает ссылки tg:// и https://t.me/proxy.
func Build(host string, port int, key [16]byte, domain string) (tg, https string) {
	secret := "ee" + hex.EncodeToString(key[:]) + hex.EncodeToString([]byte(domain))
	// secret — hex, экранирование не нужно; собираем руками, чтобы порядок был стабильным.
	enc := "server=" + url.QueryEscape(host) + "&port=" + strconv.Itoa(port) + "&secret=" + secret
	return "tg://proxy?" + enc, "https://t.me/proxy?" + enc
}

// Parse разбирает ссылку tg://proxy?... или https://t.me/proxy?....
func Parse(raw string) (host string, port int, key [16]byte, domain string, err error) {
	u, perr := url.Parse(strings.TrimSpace(raw))
	if perr != nil || u == nil {
		return "", 0, key, "", errors.New("link: некорректная ссылка")
	}
	switch u.Scheme {
	case "tg":
		if u.Host != "proxy" {
			return "", 0, key, "", errors.New("link: ожидается tg://proxy")
		}
	case "https":
		h := strings.ToLower(u.Host)
		if (h != "t.me" && h != "telegram.me") || strings.TrimSuffix(u.Path, "/") != "/proxy" {
			return "", 0, key, "", errors.New("link: ожидается https://t.me/proxy")
		}
	default:
		return "", 0, key, "", errors.New("link: неподдерживаемая схема ссылки")
	}
	q := u.Query()
	host = q.Get("server")
	if host == "" {
		return "", 0, key, "", errors.New("link: нет параметра server")
	}
	port, perr = strconv.Atoi(q.Get("port"))
	if perr != nil || port < 1 || port > 65535 {
		return "", 0, key, "", errors.New("link: некорректный port")
	}
	key, domain, err = parseSecret(q.Get("secret"))
	if err != nil {
		return "", 0, [16]byte{}, "", err
	}
	return host, port, key, domain, nil
}

func parseSecret(s string) (key [16]byte, domain string, err error) {
	if s == "" {
		return key, "", errors.New("link: нет параметра secret")
	}
	raw, derr := hex.DecodeString(s)
	if derr != nil {
		t := strings.TrimRight(s, "=")
		if raw, derr = base64.RawURLEncoding.DecodeString(t); derr != nil {
			if raw, derr = base64.RawStdEncoding.DecodeString(t); derr != nil {
				return key, "", errors.New("link: secret не hex и не base64")
			}
		}
	}
	// Plain (16 байт) и dd (17 байт) — не FakeTLS.
	if len(raw) == keyLen || (len(raw) == keyLen+1 && raw[0] == 0xdd) || (len(raw) > 0 && raw[0] != fakeTLSPrefix) {
		return key, "", ErrNotFakeTLS
	}
	if len(raw) <= 1+keyLen {
		return key, "", errors.New("link: secret слишком короткий (нет домена)")
	}
	copy(key[:], raw[1:1+keyLen])
	d := raw[1+keyLen:]
	if len(d) > maxDomainLen {
		return [16]byte{}, "", errors.New("link: домен в secret слишком длинный")
	}
	for _, b := range d {
		if b <= 0x20 || b >= 0x7f {
			return [16]byte{}, "", errors.New("link: домен в secret содержит недопустимые символы")
		}
	}
	return key, string(d), nil
}
