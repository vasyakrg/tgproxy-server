package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// headerDC дублирует {dc} из пути (docs/mtproto.md §5); расхождение — 400.
const headerDC = "X-TGP-DC"

const relayBufSize = 32 << 10

var relayBufs = sync.Pool{New: func() any { b := make([]byte, relayBufSize); return &b }}

// mtprotoRelay — TCP-релей к дата-центрам Telegram для MTProto-стримов сервера
// (POST /_agent/mtproto/dc/{dc}, docs/mtproto.md §5). Адрес берётся только из
// вшитой таблицы tgapi (или тестового оверрайда конфига), DNS и адреса от
// сервера не используются.
type mtprotoRelay struct {
	a        *Agent
	lim      atomic.Pointer[config.AgentMTProtoConfig] // лимиты; меняются через SetMTProtoLimits
	override map[int][]netip.AddrPort                  // тест-оверрайд таблицы DC; nil — вшитая
	dialer   *dcDialer
	dialFn   func(ctx context.Context, addrs []netip.AddrPort) (net.Conn, error)
	streams  atomic.Int64
}

func newMTProtoRelay(a *Agent) *mtprotoRelay {
	r := &mtprotoRelay{a: a, override: a.cfg.MTProtoDCOverride()}
	c := a.cfg.MTProto
	r.lim.Store(&c)
	r.dialer = newDCDialer(r.override != nil)
	r.dialFn = r.dialer.dial
	return r
}

// cfg возвращает текущие лимиты релея.
func (r *mtprotoRelay) cfg() config.AgentMTProtoConfig { return *r.lim.Load() }

// SetMTProtoLimits применяет max_streams, dial/idle/max_duration, ipv6 и
// dc_probe_interval на лету (SIGHUP) без разрыва живых стримов: новые лимиты
// действуют на новые стримы. enabled не меняется (только рестарт).
func (a *Agent) SetMTProtoLimits(next config.AgentMTProtoConfig) {
	next.Enabled = a.mtp.cfg().Enabled
	a.mtp.lim.Store(&next)
	a.SetDCProbeInterval(next.DCProbeInterval)
}

// MTProtoEnabled сообщает, включён ли релей MTProto (mtproto.enabled).
func (a *Agent) MTProtoEnabled() bool { return a.mtp.cfg().Enabled }

// MTProtoStreams возвращает число активных MTProto-стримов (для /_agent/status).
func (a *Agent) MTProtoStreams() int { return int(a.mtp.streams.Load()) }

func (r *mtprotoRelay) acquire() bool {
	for {
		n := r.streams.Load()
		if n >= int64(r.cfg().MaxStreams) {
			return false
		}
		if r.streams.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (r *mtprotoRelay) release() { r.streams.Add(-1) }

// addrs возвращает адреса DC для dial: при ipv6 — сначала IPv6, затем IPv4.
func (r *mtprotoRelay) addrs(dc int) []netip.AddrPort {
	if r.override != nil {
		return r.override[dc]
	}
	if r.cfg().IPv6 {
		return append(tgapi.DCAddrs(dc, true), tgapi.DCAddrs(dc, false)...)
	}
	return tgapi.DCAddrs(dc, false)
}

func (a *Agent) handleMTProto(w http.ResponseWriter, req *http.Request) {
	a.mtp.serve(w, req)
}

func (r *mtprotoRelay) serve(w http.ResponseWriter, req *http.Request) {
	if !r.cfg().Enabled {
		writeAgentError(w, http.StatusNotFound, "", "tgproxy: not found")
		return
	}
	// Отрицательные номера (media) сервер не присылает: mtg отбрасывает знак.
	// Принимать их агенту незачем — fail-closed, как и 0/мусор.
	dc, err := strconv.Atoi(req.PathValue("dc"))
	if err != nil || dc <= 0 {
		writeAgentError(w, http.StatusBadRequest, "", "tgproxy: mtproto: bad dc")
		return
	}
	if h := req.Header.Get(headerDC); h != "" && h != strconv.Itoa(dc) {
		writeAgentError(w, http.StatusBadRequest, "", "tgproxy: mtproto: dc mismatch")
		return
	}
	addrs := r.addrs(dc)
	if len(addrs) == 0 {
		writeAgentError(w, http.StatusForbidden, "", "tgproxy: mtproto: dc not allowed")
		return
	}
	if r.a.Draining() {
		writeAgentError(w, http.StatusServiceUnavailable, tgapi.PhasePreSend, "tgproxy: mtproto: agent draining")
		return
	}
	if !r.acquire() {
		writeAgentError(w, http.StatusServiceUnavailable, tgapi.PhasePreSend, "tgproxy: mtproto: stream limit")
		return
	}
	defer r.release()

	conn, ok := r.connect(w, req, dc, addrs)
	if !ok {
		return
	}
	r.relay(w, req, dc, conn) //nolint:contextcheck // ctx запроса берётся из req внутри relay
}

// connect устанавливает TCP к DC; при ошибке сам отвечает клиенту.
func (r *mtprotoRelay) connect(w http.ResponseWriter, req *http.Request, dc int, addrs []netip.AddrPort) (net.Conn, bool) {
	ctx, cancel := context.WithTimeout(req.Context(), r.cfg().DialTimeout)
	defer cancel()
	conn, err := r.dialFn(ctx, addrs)
	if err == nil {
		return conn, true
	}
	switch {
	case errors.Is(err, errDCDenied):
		writeAgentError(w, http.StatusForbidden, "", "tgproxy: mtproto: dc not allowed")
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || isTimeout(err):
		r.a.rec.DialError(DialTimeout)
		r.a.logger.Warn("mtproto dial timeout", "dc", dc)
		writeAgentError(w, http.StatusBadGateway, tgapi.PhaseTimeout, "tgproxy: mtproto: dc dial timeout")
	default:
		r.a.rec.DialError(dialErrorKind(err, tgapi.PhaseDial))
		r.a.logger.Warn("mtproto dial failed", "dc", dc, "err", redact.String(err.Error()))
		writeAgentError(w, http.StatusBadGateway, tgapi.PhaseDial, "tgproxy: mtproto: dc unavailable")
	}
	return nil, false
}

// relay шлёт 200 сразу после connect и гоняет байты r.Body <-> TCP <-> w до
// EOF DC, ошибки, idle_timeout, max_duration или отмены запроса.
func (r *mtprotoRelay) relay(w http.ResponseWriter, req *http.Request, dc int, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex() // h2 — всегда full-duplex; для h1 ошибка допустима

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}

	start := r.a.now()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	touch := func() { last.Store(time.Now().UnixNano()) }

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() { r.watch(req.Context(), conn, &last, done) })
	wg.Go(func() { r.upstream(req.Body, conn, touch) })

	r.downstream(w, rc, conn, touch)

	// DC закрыл поток/ошибка: рвём оба направления и дожидаемся горутин.
	_ = conn.Close()
	_ = rc.SetReadDeadline(time.Unix(1, 0)) // разблокирует чтение r.Body
	close(done)
	wg.Wait()
	r.a.logger.Debug("mtproto stream closed", "dc", dc, "duration", r.a.now().Sub(start))
}

// upstream: тело запроса -> DC. EOF клиента — half-close (DC ещё может отвечать);
// иная ошибка закрывает соединение целиком.
func (r *mtprotoRelay) upstream(body io.Reader, conn net.Conn, touch func()) {
	bp := relayBufs.Get().(*[]byte)
	defer relayBufs.Put(bp)
	buf := *bp
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			touch()
			if _, werr := conn.Write(buf[:n]); werr != nil {
				_ = conn.Close()
				return
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			} else {
				_ = conn.Close()
			}
			return
		}
	}
}

// downstream: DC -> тело ответа, Flush после каждой записи.
func (r *mtprotoRelay) downstream(w http.ResponseWriter, rc *http.ResponseController, conn net.Conn, touch func()) {
	bp := relayBufs.Get().(*[]byte)
	defer relayBufs.Put(bp)
	buf := *bp
	for {
		n, rerr := conn.Read(buf)
		if n > 0 {
			touch()
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if ferr := rc.Flush(); ferr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

// watch закрывает conn по idle_timeout, max_duration или отмене запроса.
func (r *mtprotoRelay) watch(ctx context.Context, conn net.Conn, last *atomic.Int64, done <-chan struct{}) {
	idle := r.cfg().IdleTimeout
	maxT := time.NewTimer(r.cfg().MaxDuration)
	defer maxT.Stop()
	idleT := time.NewTimer(idle)
	defer idleT.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
		case <-maxT.C:
		case <-idleT.C:
			since := time.Since(time.Unix(0, last.Load()))
			if since < idle {
				idleT.Reset(idle - since)
				continue
			}
		}
		_ = conn.Close()
		return
	}
}
