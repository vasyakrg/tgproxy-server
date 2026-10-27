package api

import (
	"net/http"
	"slices"
)

// MTProtoStats — снимок MTProto для GET /api/v1/mtproto/stats.
// Реализация источника (wiring) заполняет:
//   - Enabled — mtproto.enabled на сервере;
//   - Agents — по каждому агенту реестра: Capable (State.MTProtoView), Streams агента
//     (LastStatus.MTProto.Streams) и ячейки DC (Up/RTTMs из MTProtoView);
//     Streams/Errors ячейки — из метрик по (agent, dc), если они доступны, иначе 0;
//   - Totals — ActiveConns/BytesIn/BytesOut из того же источника, что ряды истории,
//     SecretsActive — число неотозванных секретов.
type MTProtoStats struct {
	Enabled bool               `json:"enabled"`
	Agents  []MTProtoAgentStat `json:"agents"`
	Totals  MTProtoTotals      `json:"totals"`
}

// MTProtoAgentStat — строка матрицы: агент и его DC.
type MTProtoAgentStat struct {
	AgentID string `json:"agent_id"`
	Capable bool   `json:"capable"`
	Streams int    `json:"streams"`
	// DC — по возрастанию номера.
	DC []MTProtoDCStat `json:"dc"`
}

// MTProtoDCStat — ячейка agent×dc.
type MTProtoDCStat struct {
	DC      int     `json:"dc"`
	Up      bool    `json:"up"`
	RTTMs   float64 `json:"rtt_ms"`
	Streams int     `json:"streams"`
	Errors  int64   `json:"errors"`
}

// MTProtoTotals — итоги.
type MTProtoTotals struct {
	ActiveConns   int64 `json:"active_conns"`
	BytesIn       int64 `json:"bytes_in"`
	BytesOut      int64 `json:"bytes_out"`
	SecretsActive int   `json:"secrets_active"`
}

// MTProtoStatsSource — источник снимка (реализует wiring).
type MTProtoStatsSource interface {
	Snapshot() MTProtoStats
}

// MTProtoStatsAPI — GET /api/v1/mtproto/stats.
type MTProtoStatsAPI struct {
	Source MTProtoStatsSource // nil — enabled:false
}

// Routes регистрирует маршрут; wrap — RequireAuth (+Protect).
func (a *MTProtoStatsAPI) Routes(mux *http.ServeMux, wrap Wrap) {
	mux.Handle("GET /api/v1/mtproto/stats", wrap.apply(http.HandlerFunc(a.stats)))
}

func (a *MTProtoStatsAPI) stats(w http.ResponseWriter, _ *http.Request) {
	var s MTProtoStats
	if a.Source != nil {
		s = a.Source.Snapshot()
	}
	if !s.Enabled {
		s = MTProtoStats{} // выключено — пустая матрица и нулевые итоги
	}
	agents := make([]MTProtoAgentStat, 0, len(s.Agents))
	for _, ag := range s.Agents {
		ag.DC = slices.Clone(ag.DC)
		if ag.DC == nil {
			ag.DC = []MTProtoDCStat{}
		}
		slices.SortFunc(ag.DC, func(x, y MTProtoDCStat) int { return x.DC - y.DC })
		agents = append(agents, ag)
	}
	slices.SortStableFunc(agents, func(x, y MTProtoAgentStat) int {
		switch {
		case x.AgentID < y.AgentID:
			return -1
		case x.AgentID > y.AgentID:
			return 1
		}
		return 0
	})
	s.Agents = agents
	writeJSON(w, http.StatusOK, s)
}
