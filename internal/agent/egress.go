package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Лимиты egress-канала обновлений (docs/architecture.md §4).
const (
	egressMaxBytes  = 200 << 20
	egressTimeout   = 10 * time.Minute
	egressMaxRedir  = 5
	egressQueryName = "url"
)

// egressAllowlist — единственные хосты, на которые агент ходит по просьбе
// сервера. release-assets.* — актуальный CDN вложений GitHub Releases
// (редирект с github.com/.../releases/download).
var egressAllowlist = []string{
	"github.com",
	"api.github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
}

var errEgressDenied = errors.New("egress: url not allowed")

// egressHandler реализует GET /_agent/egress?url=: узкий fetch-прокси для
// канала обновлений «через агента». Не универсальный прокси: только GET,
// только https:443, хосты строго из allowlist (включая каждый редирект).
type egressHandler struct {
	allow    []string
	rt       http.RoundTripper
	maxBytes int64
	timeout  time.Duration
}

func newEgressHandler() *egressHandler {
	return &egressHandler{
		allow:    egressAllowlist,
		rt:       newEgressTransport(),
		maxBytes: egressMaxBytes,
		timeout:  egressTimeout,
	}
}

// newEgressTransport не использует системный прокси и не соединяется с
// внутренними адресами (loopback/private/link-local) даже для allowlist-хоста.
func newEgressTransport() *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: egressDialControl}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    true,
	}
}

func egressDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%w: internal address", errEgressDenied)
	}
	return nil
}

// check проверяет URL по строгому правилу: https, без userinfo, порт только
// 443, хост — точное совпадение с allowlist (IP-литералы не проходят по определению).
func (h *egressHandler) check(u *url.URL) error {
	switch {
	case u == nil, !strings.EqualFold(u.Scheme, "https"), u.User != nil, u.Opaque != "":
		return errEgressDenied
	}
	if p := u.Port(); p != "" && p != "443" {
		return errEgressDenied
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, a := range h.allow {
		if host == a {
			return nil
		}
	}
	return errEgressDenied
}

func (h *egressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAgentError(w, http.StatusForbidden, "", "tgproxy: egress: only GET")
		return
	}
	raw := r.URL.Query().Get(egressQueryName)
	target, err := url.Parse(raw)
	if raw == "" || err != nil || h.check(target) != nil {
		writeAgentError(w, http.StatusForbidden, "", "tgproxy: egress: url not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil) // #nosec G704 -- URL прошёл h.check (allowlist)
	if err != nil {
		writeAgentError(w, http.StatusForbidden, "", "tgproxy: egress: url not allowed")
		return
	}
	req.Header.Set("User-Agent", "tgproxy-agent-egress")
	if acc := r.Header.Get("Accept"); acc != "" && len(acc) <= 200 {
		req.Header.Set("Accept", acc)
	}

	client := &http.Client{
		Transport: h.rt,
		CheckRedirect: func(rr *http.Request, via []*http.Request) error {
			if len(via) >= egressMaxRedir {
				return fmt.Errorf("%w: too many redirects", errEgressDenied)
			}
			return h.check(rr.URL)
		},
	}
	resp, err := client.Do(req) // #nosec G107 G704 -- URL проверен allowlist'ом, редиректы тоже
	if err != nil {
		if errors.Is(err, errEgressDenied) {
			writeAgentError(w, http.StatusForbidden, "", "tgproxy: egress: redirect not allowed")
			return
		}
		writeAgentError(w, http.StatusBadGateway, "", "tgproxy: egress: upstream unavailable")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.ContentLength > h.maxBytes {
		writeAgentError(w, http.StatusRequestEntityTooLarge, "", "tgproxy: egress: too large")
		return
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(resp.StatusCode)
	n, err := io.Copy(w, io.LimitReader(resp.Body, h.maxBytes+1))
	if err != nil || n > h.maxBytes {
		// Усечённый/переросший ответ нельзя выдавать за целый: рвём поток.
		panic(http.ErrAbortHandler)
	}
}
