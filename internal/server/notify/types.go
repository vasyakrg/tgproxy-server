// Package notify — алерты администраторам в Telegram (architecture §9):
// правила (Evaluator) → дедуп и лимиты (Notifier) → outbox → доставка через
// собственный пул агентов (Deliverer).
package notify

import (
	"context"
	"time"
)

// AlertType — тип алерта (§9).
type AlertType string

// Типы алертов.
const (
	AgentDown           AlertType = "agent_down"
	AgentDegraded       AlertType = "agent_degraded"
	Overload            AlertType = "overload"
	CertExpiring        AlertType = "cert_expiring"
	IngressCertExpiring AlertType = "ingress_cert_expiring"
	IngressCertInvalid  AlertType = "ingress_cert_invalid"
	VersionMismatch     AlertType = "version_mismatch"
	LoginLockout        AlertType = "login_lockout"
	HostKeyMismatch     AlertType = "hostkey_mismatch"
	AgentEnrolled       AlertType = "agent_enrolled"
	AllAgentsDown       AlertType = "all_agents_down"
	RolloutFailed       AlertType = "rollout_failed"
	IPAutoBan           AlertType = "ip_autoban"
)

// Severity — важность алерта.
type Severity string

// Уровни важности.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// AlertKey строит ключ дедупликации "<type>:<agent_id>" (agent_id может быть пустым).
func AlertKey(t AlertType, agentID string) string {
	if agentID == "" {
		return string(t)
	}
	return string(t) + ":" + agentID
}

// Alert — сообщение администраторам. Text не должен содержать секретов;
// Notifier дополнительно пропускает его через redact.
type Alert struct {
	Type     AlertType
	Key      string // ключ дедупа; пусто → AlertKey(Type, AgentID)
	AgentID  string
	Severity Severity
	Title    string
	Text     string
	At       time.Time
}

func (a Alert) key() string {
	if a.Key != "" {
		return a.Key
	}
	return AlertKey(a.Type, a.AgentID)
}

// Metrics — счётчики notify (реализует пакет метрик).
type Metrics interface {
	AlertUndeliverable() // tgp_alerts_undeliverable
}

type noopMetrics struct{}

func (noopMetrics) AlertUndeliverable() {}

// Clock — источник времени (подменяется в тестах).
type Clock func() time.Time

type internalKey struct{}

// InternalContext помечает контекст запроса как внутренний (уведомления
// сервера): метрики и журналы ботов такие запросы не учитывают.
func InternalContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, internalKey{}, true)
}

// IsInternal сообщает, что запрос служебный (см. InternalContext).
func IsInternal(ctx context.Context) bool {
	v, _ := ctx.Value(internalKey{}).(bool)
	return v
}
