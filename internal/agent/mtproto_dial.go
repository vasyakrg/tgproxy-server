package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

var errDCDenied = errors.New("mtproto: dc address not allowed")

// dcDialControl — Control для net.Dialer релея MTProto: по образцу
// egressDialControl запрещает loopback/private/link-local/multicast/unspecified
// и дополнительно требует адрес из официальных сетей Telegram.
//
// testTable=true (таблица DC подменена конфигом, только тесты) снимает
// требование allowlist и разрешает loopback; multicast/unspecified запрещены всегда.
func dcDialControl(testTable bool) func(network, address string, c syscall.RawConn) error {
	prefixes := tgapi.TelegramPrefixes()
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		ip = ip.Unmap()
		if ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("%w: internal address", errDCDenied)
		}
		if testTable {
			return nil
		}
		if ip.IsLoopback() || ip.IsPrivate() {
			return fmt.Errorf("%w: internal address", errDCDenied)
		}
		for _, p := range prefixes {
			if p.Contains(ip) {
				return nil
			}
		}
		return fmt.Errorf("%w: not a telegram network", errDCDenied)
	}
}

// dcDialer соединяется с DC строго по IP-литералам таблицы (без DNS).
type dcDialer struct {
	d *net.Dialer
}

func newDCDialer(testTable bool) *dcDialer {
	return &dcDialer{d: &net.Dialer{KeepAlive: 30 * time.Second, Control: dcDialControl(testTable)}}
}

// dial перебирает адреса по порядку в рамках общего ctx; возвращает первое
// успешное TCP-соединение либо последнюю ошибку.
func (d *dcDialer) dial(ctx context.Context, addrs []netip.AddrPort) (net.Conn, error) {
	var last error
	for _, ap := range addrs {
		c, err := d.d.DialContext(ctx, "tcp", ap.String())
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errors.New("mtproto: no dc addresses")
	}
	return nil, last
}
