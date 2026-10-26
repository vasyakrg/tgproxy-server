package agent

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
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
}

func (a *Agent) handleStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statusResponse{
		Version:       buildinfo.Version,
		Commit:        buildinfo.Commit,
		UptimeS:       int64(a.now().Sub(a.started).Seconds()),
		Inflight:      a.stats.inflight.Load(),
		RPS1m:         a.stats.rps1m(),
		ErrorsByPhase: a.stats.errorsByPhase(),
		UpstreamRTTMs: a.stats.upstreamRTT(),
		Draining:      a.draining.Load(),
		CertNotAfter:  a.notAfter.UTC(),
	})
}
