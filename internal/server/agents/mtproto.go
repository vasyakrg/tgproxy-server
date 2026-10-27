package agents

import (
	"slices"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// MTProtoView возвращает, объявил ли агент capability mtproto/1, и состояние
// DC из последнего статуса. Нет статуса или раздела mtproto — (false/…, nil).
// Номера DC, не разбираемые как целое, пропускаются.
func (s State) MTProtoView() (capable bool, dc map[int]balancer.DCState) {
	st := s.LastStatus
	if st == nil {
		return false, nil
	}
	capable = st.HasCapability(transport.CapMTProto)
	if st.MTProto == nil {
		return capable, nil
	}
	dc = make(map[int]balancer.DCState, len(st.MTProto.DC))
	for k, v := range st.MTProto.DC {
		n, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		dc[n] = balancer.DCState{Up: v.Up, RTT: time.Duration(v.RTTMs * float64(time.Millisecond))}
	}
	return capable, dc
}

// KeyedCandidate собирает кандидата для balancer.Keyed.Update из снимка агента.
// Weight — вес агента в БД; Healthy — Up реестра; Draining — эффективный.
func (s State) KeyedCandidate() balancer.KeyedCandidate {
	capable, dc := s.MTProtoView()
	return balancer.KeyedCandidate{
		ID: s.Agent.ID, Weight: s.Agent.Weight, Healthy: s.Up, Draining: s.Draining,
		Capable: capable, DC: dc,
	}
}

// mtprotoChanged — различаются ли capabilities или (up, rtt) по DC. Streams не
// учитываются (меняется на каждый опрос, балансировщик считает свои).
func mtprotoChanged(old, cur *transport.AgentStatus) bool {
	var oc, nc []string
	var om, nm *transport.MTProtoStatus
	if old != nil {
		oc, om = old.Capabilities, old.MTProto
	}
	oc, nc = slices.Clone(oc), slices.Clone(cur.Capabilities)
	nm = cur.MTProto
	slices.Sort(oc)
	slices.Sort(nc)
	if !slices.Equal(oc, nc) {
		return true
	}
	if (om == nil) != (nm == nil) {
		return true
	}
	if om == nil {
		return false
	}
	if len(om.DC) != len(nm.DC) {
		return true
	}
	for k, v := range om.DC {
		if w, ok := nm.DC[k]; !ok || w != v {
			return true
		}
	}
	return false
}
