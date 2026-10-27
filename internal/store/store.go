// Package store — хранилище tgproxy-server (architecture §7).
//
// SQLite хранит всё; Redis (опционально) подменяет только Sessions и RateState
// (см. WithEphemeral). Контракт репозиториев проверяется общим набором storetest.
package store

import (
	"context"
	"net/netip"
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
	InstallJobs() InstallJobRepo
	Settings() SettingsRepo
	Rollouts() RolloutRepo
	Bans() BanRepo
	MTProtoSecrets() MTProtoSecretRepo
	MTProtoSessions() MTProtoSessionRepo
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
	// SetSSHTarget задаёт SSH-цель для аварийного обновления; пустой host с портом 0 очищает её.
	SetSSHTarget(ctx context.Context, id, host string, port int) error
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
	// List — все пины, по host (для CLI `tgproxy hostkeys list`).
	List(ctx context.Context) ([]HostKey, error)
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
	// SaveCA — insert-only: если CA уже есть, ErrConflict (CA не перезаписывается никогда).
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
	// Get возвращает токен по ID (в том числе использованный и просроченный, пока его не убрала
	// очистка): ErrNotFound, если записи нет (отозван или удалён как просроченный).
	Get(ctx context.Context, id string) (Enrollment, error)
	// Delete отзывает неиспользованный токен по ID: ErrNotFound, если записи нет или токен уже использован.
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// ErrorEventRepo — кольцевой журнал ошибок.
type ErrorEventRepo interface {
	Append(ctx context.Context, e ErrorEvent) (ErrorEvent, error)
	List(ctx context.Context, q ErrorQuery) ([]ErrorEvent, error)
	// Trim оставляет последние keep записей и удаляет всё старше before (zero — не ограничивать по времени).
	Trim(ctx context.Context, keep int, before time.Time) (int64, error)
}

// InstallJobRepo — задачи SSH-установки и их события.
type InstallJobRepo interface {
	Create(ctx context.Context, j InstallJob) error
	Get(ctx context.Context, id string) (InstallJob, error)
	// SetState обновляет состояние; для финальных (не running) выставляется finished_at.
	SetState(ctx context.Context, id, state, errMsg string) error
	// SetAgent привязывает задачу к агенту.
	SetAgent(ctx context.Context, id, agentID string) error
	// AppendEvent добавляет событие и возвращает его с присвоенным монотонным ID.
	AppendEvent(ctx context.Context, e InstallJobEvent) (InstallJobEvent, error)
	// Events — события с ID > afterID по возрастанию.
	Events(ctx context.Context, jobID string, afterID int64) ([]InstallJobEvent, error)
}

// SettingsRepo — настройки, меняемые из UI (ключ → значение), например переключатели уведомлений.
type SettingsRepo interface {
	// Get — ErrNotFound, если ключа нет.
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
	// List — все пары ключ-значение.
	List(ctx context.Context) (map[string]string, error)
}

// BanRepo — баны IP. Version растёт при выдаче/изменении/снятии бана (в том числе из другого
// процесса, например CLI) — для инвалидации кэша; счётчики попаданий версию не меняют.
type BanRepo interface {
	// Upsert создаёт бан или перезапускает существующий для этого префикса (hits обнуляется).
	Upsert(ctx context.Context, b Ban) (Ban, error)
	Get(ctx context.Context, id int64) (Ban, error)
	// GetByPrefix — запись по префиксу, в том числе истёкшая (ErrNotFound, если нет).
	GetByPrefix(ctx context.Context, p netip.Prefix) (Ban, error)
	// ListActive — действующие на now баны, новые первыми.
	ListActive(ctx context.Context, now time.Time) ([]Ban, error)
	Delete(ctx context.Context, id int64) error
	// AddHits прибавляет попадания и двигает last_hit_at (нет записи — тихо игнорируется).
	AddHits(ctx context.Context, id, n int64, at time.Time) error
	// Prune удаляет истёкшие баны, по которым не было активности с before.
	Prune(ctx context.Context, before time.Time) (int, error)
	Version(ctx context.Context) (int64, error)
}

// MTProtoSecretRepo — секреты MTProto-прокси. Version растёт на любой insert/update/revoke/rotate
// (в том числе из другого процесса, например CLI) — для инвалидации кэша. Store не шифрует SecretEnc.
type MTProtoSecretRepo interface {
	// Create создаёт включённый секрет; имя уникально (ErrConflict).
	Create(ctx context.Context, name string, sealed []byte, prefix string, cidrs []netip.Prefix, maxConns int) (MTProtoSecret, error)
	Get(ctx context.Context, id int64) (MTProtoSecret, error)
	// List — все секреты, включая отозванные, по id.
	List(ctx context.Context) ([]MTProtoSecret, error)
	// ListActive — секреты, принимаемые на now (см. MTProtoSecret.Active), и версию, согласованную со снимком.
	ListActive(ctx context.Context, now time.Time) ([]MTProtoSecret, int64, error)
	// Update меняет Name, CIDRs, MaxConns и Enabled; ключ и жизненный цикл не трогает.
	Update(ctx context.Context, s MTProtoSecret) (MTProtoSecret, error)
	// Revoke отзывает секрет немедленно: revoked_at=at, enabled=false, grace_until сбрасывается.
	Revoke(ctx context.Context, id int64, at time.Time) error
	// Rotate атомарно создаёт новый секрет с тем же именем и настройками (rotated_from=id), а старый
	// переименовывает в "<имя>~<id>" и помечает отозванным с grace_until. Нулевой graceUntil — старый
	// перестаёт приниматься сразу. Возвращает новый секрет.
	Rotate(ctx context.Context, id int64, sealed []byte, prefix string, graceUntil time.Time) (MTProtoSecret, error)
	Version(ctx context.Context) (int64, error)
}

// MTProtoSessionRepo — журнал соединений MTProto. Пишется батчами (горячий путь в БД не пишет).
type MTProtoSessionRepo interface {
	// InsertBatch записывает пачку атомарно.
	InsertBatch(ctx context.Context, batch []MTProtoSession) error
	// List — записи от новых к старым с фильтрами.
	List(ctx context.Context, q MTProtoSessionQuery) ([]MTProtoSession, error)
	// Prune удаляет записи, завершённые раньше before; возвращает число удалённых.
	Prune(ctx context.Context, before time.Time) (int, error)
}
