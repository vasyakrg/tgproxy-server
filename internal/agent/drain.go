package agent

import (
	"encoding/json"
	"net/http"
)

// handleDrain: POST включает drain, DELETE отменяет.
func (a *Agent) handleDrain(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		a.SetDraining(on)
		a.logger.Info("agent drain changed", "draining", on)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "draining": on})
	}
}
