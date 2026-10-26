package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Agent — рекордеры метрик агента.
type Agent struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration prometheus.Histogram
	inflight prometheus.Gauge
	bytes    *prometheus.CounterVec
	dialErr  *prometheus.CounterVec
}

// NewAgentRegistry создаёт отдельный реестр агента.
func NewAgentRegistry() (*prometheus.Registry, *Agent) {
	reg := prometheus.NewRegistry()
	registerCommon(reg)
	a := &Agent{
		reg: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "agent_requests_total",
			Help: "Requests handled by the agent."}, []string{"code_class", "error_phase"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: namespace, Name: "agent_upstream_duration_seconds",
			Help: "Upstream (Telegram) request duration.", Buckets: durationBuckets}),
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "agent_inflight",
			Help: "In-flight upstream requests."}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "agent_upstream_bytes_total",
			Help: "Bytes proxied to/from upstream."}, []string{"direction"}),
		dialErr: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "agent_dial_errors_total",
			Help: "Upstream dial errors."}, []string{"kind"}),
	}
	reg.MustRegister(a.requests, a.duration, a.inflight, a.bytes, a.dialErr)
	return reg, a
}

// Request учитывает запрос (codeClass: 2xx|4xx|5xx|..., phase: none|dial|tls|...).
func (a *Agent) Request(codeClass, phase string) { a.requests.WithLabelValues(codeClass, phase).Inc() }

// UpstreamDuration — длительность запроса к Telegram.
func (a *Agent) UpstreamDuration(d time.Duration) { a.duration.Observe(d.Seconds()) }

// SetInflight — число запросов в полёте.
func (a *Agent) SetInflight(n int) { a.inflight.Set(float64(n)) }

// UpstreamBytes — объём трафика; direction: in|out. Отрицательные n игнорируются.
func (a *Agent) UpstreamBytes(direction string, n int) {
	if n > 0 {
		a.bytes.WithLabelValues(direction).Add(float64(n))
	}
}

// DialError — ошибка соединения с upstream (kind: dns|connect|tls|timeout|...).
func (a *Agent) DialError(kind string) { a.dialErr.WithLabelValues(kind).Inc() }

// WatchReverseConns регистрирует gauge tgp_agent_reverse_conns, читающий
// число reverse-соединений агента из conns при каждом скрейпе. Повторный вызов
// игнорируется.
func (a *Agent) WatchReverseConns(conns func() int) {
	g := prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: namespace, Name: "agent_reverse_conns",
		Help: "Active reverse connections of the agent to the server."}, func() float64 { return float64(conns()) })
	_ = a.reg.Register(g)
}
