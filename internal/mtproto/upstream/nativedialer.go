package upstream

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
)

// nativeDialer — обычный net.Dialer: mtg использует его только для fronting на
// loopback, трафик к DC им не ходит.
func nativeDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout}
}

func nativeHTTPClient(d *net.Dialer, timeout time.Duration,
	dial func(ctx context.Context, network, address string) (essentials.Conn, error),
) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if dial != nil {
				return dial(ctx, network, address)
			}
			return d.DialContext(ctx, network, address)
		},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}
