package agent

import (
	"net/http"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Handler возвращает корневой HTTP-обработчик агента (/tg/*, /_agent/*);
// общий для dial-листенера и reverse-коннектора.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(tgapi.AgentTGPrefix, a.handleTG)
	mux.HandleFunc("GET /_agent/healthz", a.handleHealthz)
	mux.HandleFunc("GET /_agent/status", a.handleStatus)
	mux.HandleFunc("POST /_agent/drain", a.handleDrain(true))
	mux.HandleFunc("DELETE /_agent/drain", a.handleDrain(false))
	mux.Handle("/_agent/egress", newEgressHandler())
	mux.HandleFunc("POST /_agent/update", a.handleUpdate)
	mux.HandleFunc("GET /_agent/update", a.handleUpdateStatus)
	mux.HandleFunc("PUT /_agent/config", a.handleConfig)
	mux.HandleFunc("POST /_agent/csr", a.handleCSR)
	mux.HandleFunc("PUT /_agent/cert", a.handleCert)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeAgentError(w, http.StatusNotFound, "", "tgproxy: not found")
	})
	return mux
}
