package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Server — рекордеры метрик сервера (§10 architecture.md).
type Server struct {
	requests         *prometheus.CounterVec
	duration         *prometheus.HistogramVec
	upstream         *prometheus.CounterVec
	retries          *prometheus.CounterVec
	tg429            *prometheus.CounterVec
	denied           *prometheus.CounterVec
	agentUp          *prometheus.GaugeVec
	agentInflight    *prometheus.GaugeVec
	agentReverse     *prometheus.GaugeVec
	enroll           *prometheus.CounterVec
	noHealthy        prometheus.Counter
	buffered         prometheus.Gauge
	longPoll         prometheus.Gauge
	webhookBlocked   prometheus.Counter
	installJobs      *prometheus.CounterVec
	adminLogins      *prometheus.CounterVec
	undeliverable    prometheus.Counter
	ingressCertAfter prometheus.Gauge
}

// NewServerRegistry создаёт отдельный (не глобальный) реестр сервера.
func NewServerRegistry() (*prometheus.Registry, *Server) {
	reg := prometheus.NewRegistry()
	registerCommon(reg)

	c := func(name, help string, labels ...string) *prometheus.CounterVec {
		return prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: name, Help: help}, labels)
	}
	g := func(name, help string, labels ...string) *prometheus.GaugeVec {
		return prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help}, labels)
	}

	s := &Server{
		requests: c("requests_total", "Proxied Bot API requests.", "rule", "method", "code"),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "request_duration_seconds",
			Help: "Request duration excluding long-poll getUpdates.", Buckets: durationBuckets,
		}, []string{"method_class", "agent"}),
		upstream:      c("upstream_attempts_total", "Upstream attempts via agents.", "agent", "result"),
		retries:       c("retries_total", "Retried requests.", "class", "reason"),
		tg429:         c("telegram_429_total", "Telegram 429 responses.", "rule"),
		denied:        c("denied_total", "Requests denied by access control (reason: no_rule|key_required|bad_key|rate_limited|banned|mtproto_replay|mtproto_conn_limit|mtproto_bad_secret).", "reason"),
		agentUp:       g("agent_up", "1 if the agent is up.", "agent", "mode"),
		agentInflight: g("agent_inflight", "In-flight requests per agent.", "agent"),
		agentReverse:  g("agent_reverse_conns", "Active reverse connections per agent.", "agent"),
		enroll:        c("enroll_attempts_total", "Agent enrollment attempts.", "result"),
		noHealthy:     prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: "no_healthy_agents_total", Help: "Requests with no healthy agent."}),
		buffered:      prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "inflight_buffered_bytes", Help: "Bytes buffered for in-flight requests."}),
		longPoll:      prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: "longpoll_active", Help: "Active long-poll requests."}),
		webhookBlocked: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "webhook_blocked_total", Help: "Blocked setWebhook requests."}),
		installJobs: c("install_jobs_total", "Agent install jobs.", "result"),
		adminLogins: c("admin_logins_total", "Admin login attempts.", "result"),
		undeliverable: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "alerts_undeliverable_total", Help: "Alerts that could not be delivered (no agents)."}),
		ingressCertAfter: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "ingress_cert_not_after_seconds", Help: "Ingress certificate NotAfter, unix seconds."}),
	}
	reg.MustRegister(s.requests, s.duration, s.upstream, s.retries, s.tg429, s.denied, s.agentUp,
		s.agentInflight, s.agentReverse, s.enroll, s.noHealthy, s.buffered, s.longPoll,
		s.webhookBlocked, s.installJobs, s.adminLogins, s.undeliverable, s.ingressCertAfter)
	return reg, s
}

// RequestDone учитывает завершённый запрос. method нормализуется через tgapi.MethodLabel.
func (s *Server) RequestDone(rule, method string, code int) {
	s.requests.WithLabelValues(rule, tgapi.MethodLabel(method), CodeLabel(code)).Inc()
}

// RequestDuration пишет длительность; long-poll в гистограмму не попадает.
func (s *Server) RequestDuration(methodClass, agent string, d time.Duration, longPoll bool) {
	if longPoll {
		return
	}
	s.duration.WithLabelValues(methodClass, agent).Observe(d.Seconds())
}

// UpstreamAttempt — попытка к агенту (result: ok|error|timeout|...).
func (s *Server) UpstreamAttempt(agent, result string) {
	s.upstream.WithLabelValues(agent, result).Inc()
}

// Retry — повторная отправка запроса.
func (s *Server) Retry(class, reason string) { s.retries.WithLabelValues(class, reason).Inc() }

// Telegram429 — ответ 429 от Telegram для правила rule.
func (s *Server) Telegram429(rule string) { s.tg429.WithLabelValues(rule).Inc() }

// Denied — отказ доступа. Причина вне известного набора схлопывается в "other" (ограничивает кардинальность).
func (s *Server) Denied(reason string) {
	switch reason {
	case "no_rule", "key_required", "bad_key", "rate_limited", "banned":
	default:
		reason = "other"
	}
	s.denied.WithLabelValues(reason).Inc()
}

// SetAgentUp выставляет agent_up; при смене mode старая серия удаляется.
func (s *Server) SetAgentUp(agent, mode string, up bool) {
	s.agentUp.DeletePartialMatch(prometheus.Labels{"agent": agent})
	v := 0.0
	if up {
		v = 1
	}
	s.agentUp.WithLabelValues(agent, mode).Set(v)
}

// SetAgentInflight — текущее число запросов в полёте на агенте.
func (s *Server) SetAgentInflight(agent string, n int) {
	s.agentInflight.WithLabelValues(agent).Set(float64(n))
}

// SetAgentReverseConns — число reverse-соединений агента.
func (s *Server) SetAgentReverseConns(agent string, n int) {
	s.agentReverse.WithLabelValues(agent).Set(float64(n))
}

// ForgetAgent удаляет все серии удалённого агента (ограничивает кардинальность).
func (s *Server) ForgetAgent(agent string) {
	l := prometheus.Labels{"agent": agent}
	s.agentUp.DeletePartialMatch(l)
	s.agentInflight.DeletePartialMatch(l)
	s.agentReverse.DeletePartialMatch(l)
}

// NoHealthyAgents — запрос отклонён из-за отсутствия живых агентов.
func (s *Server) NoHealthyAgents() { s.noHealthy.Inc() }

// BufferedBytes возвращает gauge с Add(float64) для router.WithBufferGauge.
func (s *Server) BufferedBytes() prometheus.Gauge { return s.buffered }

// LongPollActive изменяет число активных long-poll на delta (+1/-1).
func (s *Server) LongPollActive(delta int) { s.longPoll.Add(float64(delta)) }

// WebhookBlocked — заблокирован setWebhook.
func (s *Server) WebhookBlocked() { s.webhookBlocked.Inc() }

// InstallJob — итог задачи установки агента.
func (s *Server) InstallJob(result string) { s.installJobs.WithLabelValues(result).Inc() }

// AdminLogin — попытка входа в админку (ok|bad_password|bad_totp|locked...).
func (s *Server) AdminLogin(result string) { s.adminLogins.WithLabelValues(result).Inc() }

// AlertUndeliverable — алерт некому доставить.
func (s *Server) AlertUndeliverable() { s.undeliverable.Inc() }

// SetIngressCertNotAfter — срок действия сертификата входа.
func (s *Server) SetIngressCertNotAfter(t time.Time) { s.ingressCertAfter.Set(float64(t.Unix())) }

// EnrollAttempt — попытка enrollment агента.
func (s *Server) EnrollAttempt(result string) { s.enroll.WithLabelValues(result).Inc() }
