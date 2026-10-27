package agent

import (
	"encoding/json"
	"net/http"
)

const maxPoolBody = 1 << 10

// mtprotoClassHandler — обработчик MTProto-класса reverse-соединений: только
// POST /_agent/mtproto/dc/{dc} и PUT /_agent/mtproto/pool; остальное (в т.ч.
// Bot API и управление агентом) по этому каналу недоступно.
func (a *Agent) mtprotoClassHandler(c *Connector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /_agent/mtproto/dc/{dc}", a.handleMTProto)
	mux.HandleFunc("PUT /_agent/mtproto/pool", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Conns *int `json:"conns"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPoolBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || req.Conns == nil {
			writeAgentError(w, http.StatusBadRequest, "", "tgproxy: mtproto pool: bad body")
			return
		}
		n := c.Resize(*req.Conns)
		a.logger.Debug("mtproto pool resized", "requested", *req.Conns, "target", n)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeAgentError(w, http.StatusNotFound, "", "tgproxy: not found")
	})
	return mux
}
