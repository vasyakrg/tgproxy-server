package store

import (
	"net/netip"
	"time"
)

// AgentMode — режим связи server ↔ agent (architecture §4.1).
type AgentMode string

// Режимы связи агента.
const (
	ModeDial    AgentMode = "dial"
	ModeReverse AgentMode = "reverse"
)

// Agent — запись реестра агентов. Рантайм-состояние (up/down, EWMA) в БД не хранится.
type Agent struct {
	ID        string // slug, входит в SAN spiffe://tgproxy/agent/<id>
	Name      string
	URL       string // https://host:port; пусто для reverse
	Mode      AgentMode
	Weight    int
	Draining  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AccessRule — правило доступа: сети и/или скрытый ключ (architecture §3).
// Ключ в открытом виде не хранится: KeyHash = SHA-256(ключ).
type AccessRule struct {
	ID        int64
	Name      string
	CIDRs     []netip.Prefix
	KeyHash   []byte // nil — правило только-сеть
	KeyPrefix string // первые символы ключа для отображения в UI
	RPS       float64
	Enabled   bool
	CreatedAt time.Time
	RevokedAt *time.Time
}

// Session — серверная веб-сессия. ID — уже SHA-256 от cookie-токена (токен в БД не хранится).
type Session struct {
	ID            string
	User          string
	Kind          string // "pending" (после пароля, до TOTP) | "full"
	IP            string
	CreatedAt     time.Time
	LastSeenAt    time.Time
	IdleExpiresAt time.Time // скользящий idle-дедлайн (30m)
	ExpiresAt     time.Time // абсолютный дедлайн (12h)
}

// RateWindow — эфемерное значение с TTL: окно 429, счётчик rate-limit, lockout, anti-replay TOTP.
type RateWindow struct {
	Key       string
	Value     []byte
	ExpiresAt time.Time
}

// OutboxState — состояние алерта.
type OutboxState string

// Состояния алерта.
const (
	OutboxFiring   OutboxState = "firing"
	OutboxResolved OutboxState = "resolved"
)

// OutboxItem — алерт в очереди доставки.
type OutboxItem struct {
	ID        int64
	DedupKey  string // "<agent_id>|<type>"
	AgentID   string
	Type      string
	State     OutboxState
	Text      string
	CreatedAt time.Time
	SentAt    *time.Time
	Attempts  int
	LastError string
}

// Resolution — разрешение временного ряда.
type Resolution string

// Поддерживаемые разрешения рядов.
const (
	Res10s Resolution = "10s"
	Res5m  Resolution = "5m"
)

// Sample — точка временного ряда по агенту. AgentID "" — агрегат по всем.
type Sample struct {
	At          time.Time
	AgentID     string
	OK          int64
	Err         int64
	RateLimited int64   // ответы 429
	P95Ms       float64 // p95 по окну
	Inflight    int
	Buckets     []int64 // гистограмма латентности (для корректного rollup p95)
}

// AuditEntry — запись аудит-лога админов. Секреты не пишутся.
type AuditEntry struct {
	ID     int64
	At     time.Time
	Actor  string
	Action string
	Target string
	IP     string
	Detail string
}

// HostKey — пин SSH host key (TOFU, затем FixedHostKey). Ключ — host:port.
type HostKey struct {
	Host        string
	AgentID     string // пусто до создания агента
	Algo        string
	Fingerprint string // SHA256:...
	PublicKey   []byte // wire-формат ssh.PublicKey.Marshal()
	CreatedAt   time.Time
}

// CertRecord — выданный агентский сертификат.
type CertRecord struct {
	Serial    string // hex
	AgentID   string
	Subject   string
	NotBefore time.Time
	NotAfter  time.Time
	CertPEM   []byte
	CreatedAt time.Time
}

// DeniedCert — отозванный серийник (denylist).
type DeniedCert struct {
	Serial   string
	AgentID  string
	Reason   string
	NotAfter time.Time // после этой даты запись можно удалить
	DeniedAt time.Time
}

// CARecord — CA проекта: сертификат открыто, ключ зашифрован KEK.
type CARecord struct {
	CertPEM   []byte
	SealedKey []byte
	CreatedAt time.Time
}

// Enrollment — одноразовый токен подключения агента за NAT (§4.1). В БД только SHA-256.
type Enrollment struct {
	ID        string
	TokenHash []byte
	Name      string
	Weight    int
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// ErrorOutcome — чем закончился запрос с ошибкой.
type ErrorOutcome string

// Исходы запроса с ошибкой.
const (
	OutcomeRetried     ErrorOutcome = "retried"
	OutcomeFailedToBot ErrorOutcome = "failed_to_bot"
	OutcomePassedToBot ErrorOutcome = "passed_to_bot" //nolint:gosec // G101: имя исхода, не секрет
)

// ErrorEvent — запись кольцевого журнала ошибок. Description уже очищен через redact.
type ErrorEvent struct {
	ID          int64
	At          time.Time
	RequestID   string
	BotID       string
	AgentID     string
	Method      string
	Phase       string
	Code        int
	Outcome     ErrorOutcome
	Description string
}

// ErrorQuery — фильтр и курсор журнала ошибок (новые первыми).
type ErrorQuery struct {
	BeforeID  int64 // курсор: только записи с id < BeforeID (0 — с начала)
	Limit     int   // 0 → 100
	AgentID   string
	BotID     string
	Method    string
	Outcome   ErrorOutcome
	Phase     string
	Code      int // 0 — любой
	RequestID string
}

// AuditQuery — фильтр и курсор аудит-лога (новые первыми).
type AuditQuery struct {
	BeforeID int64
	Limit    int
	Actor    string
}
