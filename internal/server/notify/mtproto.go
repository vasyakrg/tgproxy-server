package notify

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"
)

const (
	defaultMTProtoDCDownAfter  = time.Minute
	defaultMTProtoOverloadFrac = 0.9
	defaultMTProtoOverloadFor  = 5 * time.Minute
)

// MTProtoAgent — capable-агент (с поддержкой MTProto) и состояние его DC.
type MTProtoAgent struct {
	ID string
	// DCUp — доступность DC по результатам probe агента (dc → up). Отсутствие
	// записи = DC агентом не проверялся, «упавшим» не считается.
	DCUp map[int]bool
}

// MTProtoSnapshot — снимок состояния MTProto для ObserveMTProto (wiring вызывает периодически).
type MTProtoSnapshot struct {
	Enabled     bool           // MTProto включён
	Agents      []MTProtoAgent // только capable-агенты (up и с capability)
	ActiveConns int            // активные клиентские соединения
	MaxConns    int            // глобальный лимит; <= 0 → правило overload выключено
}

type mtprotoState struct {
	dcDownSince map[int]time.Time
	dcFiring    map[int]bool
	overSince   time.Time
}

func mtprotoDCKey(dc int) string {
	return AlertKey(MTProtoDCUnreachable, "dc"+strconv.Itoa(dc))
}

// ObserveMTProto применяет правила MTProto-алертов к снимку:
//   - mtproto_dc_unreachable (ключ по DC): DC down на всех capable-агентах дольше 1 мин;
//     resolved, когда DC поднялся хотя бы на одном;
//   - mtproto_no_capable_agents: MTProto включён, capable-агентов 0;
//   - mtproto_overload: ActiveConns > 90% MaxConns непрерывно 5 мин.
//
// При Enabled=false все три состояния сбрасываются (resolved).
func (e *Evaluator) ObserveMTProto(ctx context.Context, s MTProtoSnapshot) {
	now := e.o.Clock()
	e.mu.Lock()
	defer e.mu.Unlock()
	st := &e.mtp
	if st.dcDownSince == nil {
		st.dcDownSince = map[int]time.Time{}
		st.dcFiring = map[int]bool{}
	}

	down := map[int]bool{}
	if s.Enabled {
		down = dcsDownEverywhere(s.Agents)
	}
	for dc := range st.dcDownSince {
		if !down[dc] {
			delete(st.dcDownSince, dc)
		}
	}
	dcs := make([]int, 0, len(down))
	for dc := range down {
		dcs = append(dcs, dc)
		if _, ok := st.dcDownSince[dc]; !ok {
			st.dcDownSince[dc] = now
		}
	}
	slices.Sort(dcs)
	for _, dc := range dcs {
		if now.Sub(st.dcDownSince[dc]) > defaultMTProtoDCDownAfter {
			st.dcFiring[dc] = true
			e.fire(ctx, Alert{
				Type: MTProtoDCUnreachable, Key: mtprotoDCKey(dc), Severity: SeverityCritical,
				Title: fmt.Sprintf("MTProto: DC%d недоступен", dc),
				Text:  fmt.Sprintf("DC%d не отвечает ни на одном агенте с поддержкой MTProto (агентов: %d).", dc, len(s.Agents)),
			})
		}
	}
	for dc := range st.dcFiring {
		if !down[dc] {
			delete(st.dcFiring, dc)
			e.resolve(ctx, mtprotoDCKey(dc))
		}
	}

	e.set(ctx, s.Enabled && len(s.Agents) == 0, Alert{
		Type: MTProtoNoCapableAgents, Severity: SeverityCritical,
		Title: "MTProto: нет агентов с поддержкой",
		Text:  "MTProto включён, но ни один доступный агент не умеет его обслуживать.",
	})

	over := s.Enabled && s.MaxConns > 0 && float64(s.ActiveConns) > defaultMTProtoOverloadFrac*float64(s.MaxConns)
	switch {
	case !over:
		st.overSince = time.Time{}
		e.resolve(ctx, string(MTProtoOverload))
	default:
		if st.overSince.IsZero() {
			st.overSince = now
		}
		if now.Sub(st.overSince) >= defaultMTProtoOverloadFor {
			e.fire(ctx, Alert{
				Type: MTProtoOverload, Severity: SeverityWarning,
				Title: "MTProto: перегрузка по соединениям",
				Text:  fmt.Sprintf("Активных соединений: %d из %d (>90%% дольше 5 минут).", s.ActiveConns, s.MaxConns),
			})
		}
	}
}

// dcsDownEverywhere — DC, помеченные down на всех capable-агентах (и хотя бы
// один агент его проверил). Агент без записи по DC голоса не имеет, но и не «спасает» DC.
func dcsDownEverywhere(ags []MTProtoAgent) map[int]bool {
	out := map[int]bool{}
	if len(ags) == 0 {
		return out
	}
	seen := map[int]bool{}
	for _, a := range ags {
		for dc := range a.DCUp {
			seen[dc] = true
		}
	}
	for dc := range seen {
		allDown := true
		for _, a := range ags {
			if up, ok := a.DCUp[dc]; ok && up {
				allDown = false
				break
			}
		}
		if allDown {
			out[dc] = true
		}
	}
	return out
}
