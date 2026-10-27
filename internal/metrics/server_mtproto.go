package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// mtprotoMetrics — серверные метрики MTProto (docs/mtproto.md §13).
// В метки не попадают IP и ключи: secret — имя, agent — имя агента, dc — номер.
type mtprotoMetrics struct {
	clientConns      *prometheus.GaugeVec
	conns            *prometheus.CounterVec
	hsFail           *prometheus.CounterVec
	fallthroughTotal prometheus.Counter
	bytes            *prometheus.CounterVec
	streams          *prometheus.GaugeVec
	dcRTT            *prometheus.GaugeVec
	dcUp             *prometheus.GaugeVec
	upErrors         *prometheus.CounterVec
	session          prometheus.Histogram
}

var sessionBuckets = []float64{1, 5, 15, 60, 300, 900, 3600, 14400, 86400}

func newMTProtoMetrics(reg prometheus.Registerer) mtprotoMetrics {
	c := func(name, help string, labels ...string) *prometheus.CounterVec {
		return prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: name, Help: help}, labels)
	}
	g := func(name, help string, labels ...string) *prometheus.GaugeVec {
		return prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help}, labels)
	}
	m := mtprotoMetrics{
		clientConns: g("mtproto_client_conns", "Active MTProto client connections (listener: shared|dedicated).", "listener"),
		conns: c("mtproto_connections_total",
			"MTProto connections by secret name and result (ok|replay|conn_limit|no_agents|upstream_error|closed).", "secret", "result"),
		hsFail: c("mtproto_handshake_failures_total",
			"Failed FakeTLS handshakes (timeout|bad_record|replay|time_skew|conn_limit).", "reason"),
		fallthroughTotal: prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: "mtproto_fallthrough_total",
			Help: "Connections handed over to the TLS fronting site."}),
		bytes:    c("mtproto_bytes_total", "MTProto bytes via agents (direction: in = client to Telegram, out = Telegram to client).", "direction", "agent"),
		streams:  g("mtproto_streams", "Active MTProto streams per agent and DC.", "agent", "dc"),
		dcRTT:    g("mtproto_dc_rtt_seconds", "Last probed RTT from the agent to the DC.", "agent", "dc"),
		dcUp:     g("mtproto_dc_up", "1 if the DC is reachable from the agent.", "agent", "dc"),
		upErrors: c("mtproto_upstream_errors_total", "Errors opening MTProto streams via agents.", "agent", "dc", "phase"),
		session: prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: namespace, Name: "mtproto_session_duration_seconds",
			Help: "Duration of finished MTProto sessions.", Buckets: sessionBuckets}),
	}
	reg.MustRegister(m.clientConns, m.conns, m.hsFail, m.fallthroughTotal, m.bytes, m.streams, m.dcRTT, m.dcUp, m.upErrors, m.session)
	return m
}

func dcLabel(dc int) string { return strconv.Itoa(dc) }

// MTProtoClientConns меняет число клиентских соединений слушателя на delta (+1/-1).
func (s *Server) MTProtoClientConns(listener string, delta int) {
	switch listener {
	case "shared", "dedicated":
	default:
		listener = "other"
	}
	s.mtp.clientConns.WithLabelValues(listener).Add(float64(delta))
}

// MTProtoConnection — итог соединения секрета secret (имя). Неизвестный result → "closed".
func (s *Server) MTProtoConnection(secret, result string) {
	switch result {
	case "ok", "replay", "conn_limit", "no_agents", "upstream_error", "closed":
	default:
		result = "closed"
	}
	s.mtp.conns.WithLabelValues(secret, result).Inc()
}

// MTProtoHandshakeFailure — отказ рукопожатия. Неизвестная причина → "bad_record".
func (s *Server) MTProtoHandshakeFailure(reason string) {
	switch reason {
	case "timeout", "bad_record", "replay", "time_skew", "conn_limit":
	default:
		reason = "bad_record"
	}
	s.mtp.hsFail.WithLabelValues(reason).Inc()
}

// MTProtoFallthrough — соединение отдано TLS-сайту.
func (s *Server) MTProtoFallthrough() { s.mtp.fallthroughTotal.Inc() }

// MTProtoBytes — байты через агента; direction: in|out. n<=0 игнорируется.
func (s *Server) MTProtoBytes(agent, direction string, n int) {
	if n <= 0 || (direction != "in" && direction != "out") {
		return
	}
	s.mtp.bytes.WithLabelValues(direction, agent).Add(float64(n))
}

// MTProtoStreams меняет число активных стримов (agent, dc) на delta.
func (s *Server) MTProtoStreams(agent string, dc, delta int) {
	s.mtp.streams.WithLabelValues(agent, dcLabel(dc)).Add(float64(delta))
}

// MTProtoUpstreamError — ошибка открытия стрима (phase: dial|timeout|no_agent|unknown_dc|other).
func (s *Server) MTProtoUpstreamError(agent string, dc int, phase string) {
	switch phase {
	case "dial", "timeout", "no_agent", "unknown_dc":
	default:
		phase = "other"
	}
	s.mtp.upErrors.WithLabelValues(agent, dcLabel(dc), phase).Inc()
}

// MTProtoSession — длительность завершённой сессии.
func (s *Server) MTProtoSession(d time.Duration) { s.mtp.session.Observe(d.Seconds()) }

// SetMTProtoDC выставляет dc_up и dc_rtt_seconds агента; вызывается wiring по
// событию реестра (статус агента). При up=false RTT сбрасывается в 0.
func (s *Server) SetMTProtoDC(agent string, dc int, up bool, rtt time.Duration) {
	d := dcLabel(dc)
	if up {
		s.mtp.dcUp.WithLabelValues(agent, d).Set(1)
		s.mtp.dcRTT.WithLabelValues(agent, d).Set(rtt.Seconds())
		return
	}
	s.mtp.dcUp.WithLabelValues(agent, d).Set(0)
	s.mtp.dcRTT.WithLabelValues(agent, d).Set(0)
}

// SetMTProtoDCs заменяет весь набор DC агента (dc → up/rtt): исчезнувшие DC
// удаляются. Удобно звать целиком из статуса агента.
func (s *Server) SetMTProtoDCs(agent string, dcs map[int]DCState) {
	l := prometheus.Labels{"agent": agent}
	s.mtp.dcUp.DeletePartialMatch(l)
	s.mtp.dcRTT.DeletePartialMatch(l)
	for dc, st := range dcs {
		s.SetMTProtoDC(agent, dc, st.Up, st.RTT)
	}
}

// DCState — доступность DC с агента.
type DCState struct {
	Up  bool
	RTT time.Duration
}

// ForgetMTProtoAgent удаляет все MTProto-серии агента.
func (s *Server) ForgetMTProtoAgent(agent string) {
	l := prometheus.Labels{"agent": agent}
	s.mtp.streams.DeletePartialMatch(l)
	s.mtp.dcRTT.DeletePartialMatch(l)
	s.mtp.dcUp.DeletePartialMatch(l)
	s.mtp.upErrors.DeletePartialMatch(l)
	s.mtp.bytes.DeletePartialMatch(l)
}
