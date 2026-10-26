package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

const maxConfigBody = 4 << 10

type configRequest struct {
	Mode      config.AgentMode `json:"mode"`
	ServerURL string           `json:"server_url"`
}

// handleConfig — PUT /_agent/config {mode, server_url}: смена режима связи без
// рестарта процесса. Вызывается сервером по каналу, идентичность которого уже
// проверена (mTLS dial или исходящий reverse с VerifyServerPeer).
//
// 400 — не JSON; 422 — невалидные значения; 409 — конфиг нельзя сохранить или
// применить (состояние не меняется).
func (a *Agent) handleConfig(w http.ResponseWriter, r *http.Request) {
	var req configRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAgentError(w, http.StatusBadRequest, "", "tgproxy: bad config json")
		return
	}
	m := a.mgr
	m.opMu.Lock()
	defer m.opMu.Unlock()

	curMode, curURL, _, _ := m.snapshot()
	switch req.Mode {
	case config.AgentModeDial, config.AgentModeReverse, config.AgentModeBoth:
	default:
		writeAgentError(w, http.StatusUnprocessableEntity, "", "tgproxy: mode must be dial|reverse|both")
		return
	}
	url := req.ServerURL
	if url == "" && !wantConnector(req.Mode) {
		url = curURL // для dial адрес сервера не обязателен — остаётся прежним
	}
	if wantConnector(req.Mode) {
		if _, err := parseServerURL(url); err != nil {
			writeAgentError(w, http.StatusUnprocessableEntity, "", "tgproxy: "+err.Error())
			return
		}
	} else if url != "" {
		if _, err := parseServerURL(url); err != nil {
			writeAgentError(w, http.StatusUnprocessableEntity, "", "tgproxy: "+err.Error())
			return
		}
	}

	if err := a.saveConn(a.cfg.Path(), req.Mode, req.ServerURL); err != nil {
		a.logger.Warn("agent config not saved", "err", err)
		writeAgentError(w, http.StatusConflict, "", "tgproxy: cannot persist config: "+err.Error())
		return
	}
	teardown, err := m.switchTo(req.Mode, url) //nolint:contextcheck // жизненный цикл агента, а не запроса
	if err != nil {
		if rerr := a.saveConn(a.cfg.Path(), curMode, curURL); rerr != nil {
			err = errors.Join(err, fmt.Errorf("rollback: %w", rerr))
		}
		writeAgentError(w, http.StatusConflict, "", "tgproxy: cannot apply config: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": req.Mode, "server_url": url})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	// Остановка вытесняемых компонентов — после ответа: запрос мог прийти
	// именно по закрываемому каналу (graceful дожидается завершения хендлера).
	teardown()
}
