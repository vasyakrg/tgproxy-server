package mux

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/pires/go-proxyproto"
)

var errNotProxyV2 = errors.New("mux: ожидался PROXY v2 с командой PROXY и TCP-адресом")

// FrontingAddr — адрес внутреннего fronting-листенера (127.0.0.1:порт) для
// mtg (DomainFrontingIP/Port, ProxyProtocol=true).
func (l *Listener) FrontingAddr() *net.TCPAddr {
	return l.front.Addr().(*net.TCPAddr)
}

func (l *Listener) frontingLoop() {
	defer l.wg.Done()
	for {
		raw, err := l.front.Accept()
		if err != nil {
			if l.isClosed() || !l.acceptRetry(err) {
				return
			}
			continue
		}
		if !l.spawn(func() { l.frontingHandle(raw) }) {
			_ = raw.Close()
			return
		}
	}
}

// frontingHandle принимает только loopback и только PROXY v2; соединение
// отдаётся TLS-обработчику с RemoteAddr = исходный IP клиента.
func (l *Listener) frontingHandle(raw net.Conn) {
	if ip, ok := addrOf(raw.RemoteAddr()); !ok || !ip.IsLoopback() {
		_ = raw.Close()
		return
	}
	if !l.track(raw) {
		_ = raw.Close()
		return
	}
	pc := proxyproto.NewConn(raw,
		proxyproto.ValidateHeader(validateV2),
		proxyproto.SetReadHeaderTimeout(l.opts.HandshakeTimeout),
	)
	pc.ProxyHeaderPolicy = proxyproto.REQUIRE
	// Читаем заголовок сразу: сбой PROXY отсекается здесь, а не в TLS-обработчике.
	if pc.ProxyHeader() == nil {
		l.untrack(raw)
		_ = raw.Close()
		return
	}
	l.untrack(raw)
	l.deliver(pc)
}

func validateV2(h *proxyproto.Header) error {
	if h.Version != 2 || h.Command.IsLocal() {
		return errNotProxyV2
	}
	ap, err := netip.ParseAddrPort(h.SourceAddr.String())
	if err != nil {
		return fmt.Errorf("%w: %v", errNotProxyV2, err)
	}
	if _, ok := h.SourceAddr.(*net.TCPAddr); !ok || !ap.IsValid() {
		return errNotProxyV2
	}
	return nil
}
