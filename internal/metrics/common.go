// Package metrics содержит Prometheus-реестры сервера и агента (префикс tgp_),
// типизированные рекордеры, защищённый bearer-ом /metrics-handler и in-memory
// top-K ботов. bot_id в метки метрик не попадает никогда.
package metrics

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
)

const namespace = "tgp"

// registerCommon регистрирует build_info и go/process-коллекторы.
func registerCommon(reg *prometheus.Registry) {
	bi := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "build_info",
		Help:      "Build information; value is always 1.",
	}, []string{"version", "commit", "go"})
	bi.WithLabelValues(buildinfo.Version, buildinfo.Commit, runtime.Version()).Set(1)

	reg.MustRegister(
		bi,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
}

// durationBuckets покрывают от 5ms до 60s (дедлайн getUpdates ≤ 65s в гистограмму не пишется).
var durationBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}
