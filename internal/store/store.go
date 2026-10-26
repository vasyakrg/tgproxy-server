// Package store — хранилище tgproxy-server (architecture §7).
//
// SQLite хранит всё; Redis (опционально) подменяет только Sessions и RateState
// (см. WithEphemeral). Контракт репозиториев проверяется общим набором storetest.
package store

import (
	"context"
	"time"
)

// Store — фасад над репозиториями.
type Store interface {
	Agents() AgentRepo
	AccessRules() AccessRuleRepo
	Sessions() SessionRepo
	Outbox() OutboxRepo
	RateState() RateStateRepo
	History() HistoryRepo
	Audit() AuditRepo
	HostKeys() HostKeyRepo
	Certs() CertRepo
	Enrollments() EnrollmentRepo
	Errors() ErrorEventRepo
	Close() error
}

// AgentRepo — реестр агентов. Version монотонно растёт при любом изменении
// (в том числе из другого процесса, например CLI) — для инвалидации кэшей.
type AgentRepo interface {
	Create(ctx context.Context, a Agent) (Agent, error)
	Get(ctx context.Context, id string) (Agent, error)
	List(ctx context.Context) ([]Agent, error)
	Update(ctx context.Context, a Agent) (Agent, error)
	SetWeight(ctx context.Context, id string, weight int) error
	SetDraining(ctx context.Context, id string, draining bool) error
	Delete(ctx context.Context, id string) error
	Version(ctx context.Context) (int64, error)
}

// AccessRuleRepo — правила доступа. Update не меняет ключ (KeyHash/KeyPrefix).
type AccessRuleRepo interface {
	Create(ctx context.Context, r AccessRule) (AccessRule, error)
	Get(ctx context.Context, id int64) (AccessRule, error)
	GetByName(ctx context.Context, name string) (AccessRule, error)
	List(ctx context.Context) ([]AccessRule, error)
	Update(ctx context.Context, r AccessRule) (AccessRule, error)
	// Revoke выставляет revoked_at и enabled=false; ключ остаётся в БД, чтобы отозванный ключ давал 403.
	Revoke(ctx context.Context, id int64) error
	Delete(ctx context.Context, id int64) error
	Version(ctx context.Context) (int64, error)
}

// SessionRepo — веб-сессии. Get не возвращает истёкшие (idle или абсолютно).
type SessionRepo interface {
	Create(ctx context.Context, s Session) error
	Get(ctx context.Context, id string) (Session, error)
	// Touch продлевает idle-дедлайн (не дальше ExpiresAt) и обновляет LastSeenAt.
	Touch(ctx context.Context, id string, idleExpiresAt time.Time) error
	Delete(ctx context.Context, id string) error
	DeleteByUser(ctx context.Context, user string) (int, error)
	DeleteExpired(ctx context.Context) (int, error)
}

// RateStateRepo — эфемерные ключ-значение с TTL (окна 429, rate-limit, lockout, anti-replay).
// Истёкшие ключи невидимы для Get/Incr/SetNX.
type RateStateRepo interface {
	Get(ctx context.Context, key string) (RateWindow, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// SetNX записывает значение, только если ключа нет; true — записано.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// Incr атомарно увеличивает счётчик; TTL выставляется при создании окна (фиксированное окно).
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Delete(ctx context.Context, key string) error
	DeleteExpired(ctx context.Context) (int, error)
}

// OutboxRepo — очередь алертов.
type OutboxRepo interface {
	Enqueue(ctx context.Context, it OutboxItem) (OutboxItem, error)
	// Pending — неотправленные, старые первыми.
	Pending(ctx context.Context, limit int) ([]OutboxItem, error)
	CountPending(ctx context.Context) (int, error)
	// LastByKey — последний элемент с этим dedup-ключом (ErrNotFound, если нет).
	LastByKey(ctx context.Context, dedupKey string) (OutboxItem, error)
	MarkSent(ctx context.Context, id int64, at time.Time) error
	RecordAttempt(ctx context.Context, id int64, lastError string) error
	DeleteSentBefore(ctx context.Context, t time.Time) (int, error)
	// Recent — последние limit элементов (отправленных и нет), новые первыми.
	Recent(ctx context.Context, limit int) ([]OutboxItem, error)
}

// HistoryRepo — временные ряды метрик (10s/24h, 5m/30d).
type HistoryRepo interface {
	// Append — upsert по (agent_id, at).
	Append(ctx context.Context, res Resolution, samples []Sample) error
	// Range — [from, to), по возрастанию времени; agentID "" — все агенты.
	Range(ctx context.Context, res Resolution, agentID string, from, to time.Time) ([]Sample, error)
	Prune(ctx context.Context, res Resolution, before time.Time) (int64, error)
}

// AuditRepo — аудит-лог админов.
type AuditRepo interface {
	Append(ctx context.Context, e AuditEntry) (AuditEntry, error)
	List(ctx context.Context, q AuditQuery) ([]AuditEntry, error)
}

// HostKeyRepo — пины SSH host key.
type HostKeyRepo interface {
	Get(ctx context.Context, host string) (HostKey, error)
	Put(ctx context.Context, k HostKey) error
	Delete(ctx context.Context, host string) error
}

// CertRepo — сертификаты, denylist серийников, CA.
type CertRepo interface {
	Put(ctx context.Context, c CertRecord) error
	Get(ctx context.Context, serial string) (CertRecord, error)
	ListByAgent(ctx context.Context, agentID string) ([]CertRecord, error)
	// ListExpiring — сертификаты с NotAfter < before, по возрастанию NotAfter.
	ListExpiring(ctx context.Context, before time.Time) ([]CertRecord, error)
	Deny(ctx context.Context, d DeniedCert) error
	IsDenied(ctx context.Context, serial string) (bool, error)
	ListDenied(ctx context.Context) ([]DeniedCert, error)
	PruneDenied(ctx context.Context, now time.Time) (int, error)
	SaveCA(ctx context.Context, ca CARecord) error
	LoadCA(ctx context.Context) (CARecord, error)
}

// EnrollmentRepo — одноразовые токены подключения агентов за NAT.
type EnrollmentRepo interface {
	Create(ctx context.Context, e Enrollment) error
	// Consume атомарно гасит токен: ErrNotFound, если токена нет, он истёк или уже использован
	// (причина намеренно не различается).
	Consume(ctx context.Context, tokenHash []byte, now time.Time) (Enrollment, error)
	ListPending(ctx context.Context, now time.Time) ([]Enrollment, error)
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// ErrorEventRepo — кольцевой журнал ошибок.
type ErrorEventRepo interface {
	Append(ctx context.Context, e ErrorEvent) (ErrorEvent, error)
	List(ctx context.Context, q ErrorQuery) ([]ErrorEvent, error)
	// Trim оставляет последние keep записей и удаляет всё старше before (zero — не ограничивать по времени).
	Trim(ctx context.Context, keep int, before time.Time) (int64, error)
}
