package agent

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

type proxy struct {
	a  *Agent
	rp *httputil.ReverseProxy
}

func newUpstreamTransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy: nil, // агент ходит в Telegram напрямую, HTTP(S)_PROXY игнорируется
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // прозрачно: не трогаем Accept-Encoding
	}
}

func newProxy(a *Agent) *proxy {
	p := &proxy{a: a}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      a.transport,
		FlushInterval:  -1,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   a.errorHandler,
		ErrorLog:       slogErrorLog(a),
	}
	return p
}

// requestStrip — заголовки, которые не должны попасть в Telegram.
var requestStrip = []string{
	"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	"X-Real-Ip", "Via", "Cookie", "Authorization", "Proxy-Authorization",
	tgapi.HeaderRequestID, tgapi.HeaderProxyKey,
}

func (p *proxy) rewrite(pr *httputil.ProxyRequest) {
	in, out := pr.In, pr.Out
	out.URL.Scheme = p.a.upstream.Scheme
	out.URL.Host = p.a.upstream.Host
	out.URL.Path = "/" + strings.TrimPrefix(in.URL.Path, tgapi.AgentTGPrefix)
	out.URL.RawPath = ""
	if in.URL.RawPath != "" {
		out.URL.RawPath = "/" + strings.TrimPrefix(in.URL.RawPath, tgapi.AgentTGPrefix)
	}
	out.Host = p.a.upstream.Host

	for _, h := range requestStrip {
		out.Header.Del(h)
	}
	for k := range out.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-tgp-") {
			delete(out.Header, k)
		}
	}
	if _, ok := out.Header["User-Agent"]; !ok {
		out.Header.Set("User-Agent", "") // не подставлять Go-http-client
	}
}

func (p *proxy) modifyResponse(resp *http.Response) error {
	h := resp.Header
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-tgp-") {
			delete(h, k)
		}
	}
	h.Del("Set-Cookie")
	h.Del("Alt-Svc")
	h.Del("Server")
	h.Set(tgapi.HeaderSource, tgapi.SourceTelegram)
	if t := trackerFrom(resp.Request.Context()); t != nil {
		d := t.upstream()
		p.a.stats.observeRTT(d)
		h.Set(tgapi.HeaderUpstreamMs, itoa(d.Milliseconds()))
	}
	return nil
}

func (a *Agent) handleTG(w http.ResponseWriter, r *http.Request) {
	if a.draining.Load() {
		a.stats.recordError(tgapi.PhasePreSend)
		writeAgentError(w, http.StatusServiceUnavailable, tgapi.PhasePreSend, "tgproxy: agent is draining")
		return
	}
	if len(r.URL.Path) <= len(tgapi.AgentTGPrefix) {
		writeAgentError(w, http.StatusNotFound, "", "tgproxy: not found")
		return
	}
	a.stats.begin()
	defer a.stats.end()

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout(r.Header))
	defer cancel()
	t := newPhaseTracker(a.now())
	ctx = httptrace.WithClientTrace(ctx, t.clientTrace())
	ctx = context.WithValue(ctx, trackerKey{}, t)
	a.proxy.rp.ServeHTTP(w, r.WithContext(ctx))
}

// slogErrorLog направляет логи net/http в slog (с редакцией).
func slogErrorLog(a *Agent) *log.Logger { //nolint:forbidigo // http.Server.ErrorLog требует *log.Logger, обёртка над slog
	return slog.NewLogLogger(a.logger.Handler(), slog.LevelWarn)
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
