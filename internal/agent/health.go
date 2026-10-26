package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
)

const (
	healthTTL        = 10 * time.Second
	healthProbeLimit = 5 * time.Second
)

// healthProbe кэширует результат TLS-пробы до Telegram на healthTTL.
type healthProbe struct {
	probe func(context.Context) error
	now   func() time.Time

	mu     sync.Mutex
	at     time.Time
	err    error
	filled bool
}

func newHealthProbe(probe func(context.Context) error, now func() time.Time) *healthProbe {
	return &healthProbe{probe: probe, now: now}
}

func (h *healthProbe) check(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.filled && h.now().Sub(h.at) < healthTTL {
		return h.err
	}
	pctx, cancel := context.WithTimeout(ctx, healthProbeLimit)
	defer cancel()
	h.err = h.probe(pctx)
	h.at, h.filled = h.now(), true
	return h.err
}

// probeUpstream делает TLS-рукопожатие с хостом Telegram.
func (a *Agent) probeUpstream(ctx context.Context) error {
	host := a.upstream.Host
	if a.upstream.Port() == "" {
		host = net.JoinHostPort(a.upstream.Hostname(), "443")
	}
	cfg := a.upTLS.Clone()
	cfg.ServerName = a.upstream.Hostname()
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: healthProbeLimit}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (a *Agent) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := a.health.check(r.Context()); err != nil {
		a.logger.Warn("healthz: upstream probe failed", "err", redact.String(err.Error()))
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": redact.String(err.Error())})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
