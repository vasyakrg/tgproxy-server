package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// agentMTProto — метрики MTProto-релея агента (docs/mtproto.md §13).
type agentMTProto struct {
	streams *prometheus.GaugeVec
	dialErr *prometheus.CounterVec
	bytes   *prometheus.CounterVec
}

func newAgentMTProto(reg prometheus.Registerer) agentMTProto {
	m := agentMTProto{
		streams: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: "agent_mtproto_streams",
			Help: "Active MTProto streams of the agent per DC."}, []string{"dc"}),
		dialErr: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "agent_mtproto_dial_errors_total",
			Help: "MTProto DC dial errors."}, []string{"dc", "kind"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "agent_mtproto_bytes_total",
			Help: "MTProto bytes relayed (in = client to DC, out = DC to client)."}, []string{"direction"}),
	}
	reg.MustRegister(m.streams, m.dialErr, m.bytes)
	return m
}

// MTProtoStreams меняет число активных стримов к DC на delta.
func (a *Agent) MTProtoStreams(dc, delta int) {
	a.mtp.streams.WithLabelValues(strconv.Itoa(dc)).Add(float64(delta))
}

// MTProtoDialError — ошибка соединения с DC (kind: dns|refused|timeout|tls|other).
func (a *Agent) MTProtoDialError(dc int, kind string) {
	switch kind {
	case "dns", "refused", "timeout", "tls":
	default:
		kind = "other"
	}
	a.mtp.dialErr.WithLabelValues(strconv.Itoa(dc), kind).Inc()
}

// MTProtoBytes — объём MTProto-трафика; direction: in|out. n<=0 игнорируется.
func (a *Agent) MTProtoBytes(direction string, n int) {
	if n > 0 && (direction == "in" || direction == "out") {
		a.mtp.bytes.WithLabelValues(direction).Add(float64(n))
	}
}
