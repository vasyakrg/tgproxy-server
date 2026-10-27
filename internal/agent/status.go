package agent

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

type statusResponse struct {
	Version       string           `json:"version"`
	Commit        string           `json:"commit"`
	UptimeS       int64            `json:"uptime_s"`
	Inflight      int64            `json:"inflight"`
	RPS1m         float64          `json:"rps_1m"`
	ErrorsByPhase map[string]int64 `json:"errors_by_phase"`
	UpstreamRTTMs float64          `json:"upstream_rtt_ms"`
	Draining      bool             `json:"draining"`
	CertNotAfter  time.Time        `json:"cert_not_after"`
	Mode          string           `json:"mode"`
	ReverseConns  int              `json:"reverse_conns"`
	ReverseState  string           `json:"reverse_state,omitempty"`
	// Capabilities/MTProto публикуются только при mtproto.enabled.
	Capabilities []string                 `json:"capabilities,omitempty"`
	MTProto      *transport.MTProtoStatus `json:"mtproto,omitempty"`
}

func (a *Agent) handleStatus(w http.ResponseWriter, _ *http.Request) {
	mode, _, conns, state := a.mgr.snapshot()
	w.Header().Set("Content-Type", "application/json")
	resp := statusResponse{
		Version:       a.currentVersion(),
		Commit:        buildinfo.Commit,
		UptimeS:       int64(a.now().Sub(a.started).Seconds()),
		Inflight:      a.stats.inflight.Load(),
		RPS1m:         a.stats.rps1m(),
		ErrorsByPhase: a.stats.errorsByPhase(),
		UpstreamRTTMs: a.stats.upstreamRTT(),
		Draining:      a.draining.Load(),
		CertNotAfter:  a.certNotAfter().UTC(),
		Mode:          string(mode),
		ReverseConns:  conns,
		ReverseState:  state,
	}
	if a.MTProtoEnabled() {
		resp.Capabilities = []string{transport.CapMTProto}
		resp.MTProto = &transport.MTProtoStatus{Streams: a.MTProtoStreams(), DC: a.dcp.snapshot()}
	}
	_ = json.NewEncoder(w).Encode(resp)
}
