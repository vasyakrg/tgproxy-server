package installer

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

var (
	hostLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	userRe      = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	versionRe   = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~-]{0,63}$`)
	sanRe       = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
	absPathRe   = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,200}$`)
)

func validateHost(h string) error {
	if h == "" || len(h) > 253 {
		return fmt.Errorf("installer: некорректный хост %q", h)
	}
	if _, err := netip.ParseAddr(h); err == nil {
		if strings.Contains(h, "%") {
			return fmt.Errorf("installer: некорректный хост %q", h)
		}
		return nil
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabelRe.MatchString(l) {
			return fmt.Errorf("installer: некорректный хост %q", h)
		}
	}
	return nil
}

func validatePort(what string, p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("installer: %s вне диапазона 1..65535: %d", what, p)
	}
	return nil
}

func validateUser(u string) error {
	if !userRe.MatchString(u) {
		return fmt.Errorf("installer: некорректное имя пользователя %q", u)
	}
	return nil
}

func validateName(n string) error {
	if !pki.ValidAgentID(n) {
		return fmt.Errorf("installer: некорректное имя агента %q (допустимо: латиница, цифры, . _ -, до 63 символов)", n)
	}
	return nil
}
