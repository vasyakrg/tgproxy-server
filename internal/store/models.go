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
	// ModeBoth — сервер ходит к агенту сам (url обязателен) и принимает его reverse-соединения.
	ModeBoth AgentMode = "both"
)

// Agent — запись реестра агентов. Рантайм-состояние (up/down, EWMA) в БД не хранится.
type Agent struct {
	ID       string // slug, входит в SAN spiffe://tgproxy/agent/<id>
	Name     string
	URL      string // https://host:port; пусто для reverse
	Mode     AgentMode
	Weight   int
	Draining bool
	// SSHHost/SSHPort — SSH-цель агента, с которой он был установлен установщиком (для
	// аварийного обновления, когда mTLS-путь недоступен). Пусто/0 — цель неизвестна
	// (reverse/enrollment-агент или установка до миграции без истории). Update их не меняет.
	SSHHost   string
	SSHPort   int
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
	// Denied — отказы доступа по причинам (только у строки-агрегата: отказ никуда не маршрутизируется).
	Denied map[string]int64
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
	OutcomePassedToBot ErrorOutcome = "passed_to_bot" // #nosec G101 -- G101: имя исхода, не секрет
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
	// ClientIP / Reason заполняются для отказов доступа (Phase "access"): реальный адрес
	// клиента и причина (no_rule | key_required | bad_key | rate_limited).
	ClientIP string
	Reason   string
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
	Reason    string
	ClientIP  string
}

// AuditQuery — фильтр и курсор аудит-лога (новые первыми).
type AuditQuery struct {
	BeforeID int64
	Limit    int
	Actor    string
}

// Состояния задачи установки.
const (
	InstallRunning    = "running"
	InstallDone       = "done"
	InstallFailed     = "failed"
	InstallRolledBack = "rolled_back"
)

// InstallJob — задача SSH-установки агента (M5-T3). Креды админа в БД не хранятся.
type InstallJob struct {
	ID         string
	AgentID    string
	Host       string // host:port
	Kind       string // "install"
	State      string // Install*
	Error      string
	CreatedAt  time.Time
	FinishedAt *time.Time
}

// InstallJobEvent — событие задачи (журнал мастера). ID монотонно растёт (используется как seq / Last-Event-ID).
// Message уже очищено от секретов.
type InstallJobEvent struct {
	ID      int64
	JobID   string
	At      time.Time
	Kind    string // step | log | done | error
	Step    string // ключ шага
	Level   string // info | warn | error
	Message string
}

// BanSource — кто создал бан.
type BanSource string

// Источники бана.
const (
	BanAuto   BanSource = "auto"
	BanManual BanSource = "manual"
)

// Ban — бан сетевого префикса клиента (IPv4 /32, IPv6 /64). Одна запись на префикс:
// повторный бан обновляет её, сохраняя Level (эскалация) до сброса.
type Ban struct {
	ID        int64
	Prefix    netip.Prefix
	Source    BanSource
	Actor     string // логин админа или "auto"
	Comment   string
	CreatedAt time.Time
	ExpiresAt *time.Time // nil — бессрочно
	Hits      int64      // отклонённые запросы с момента бана
	Level     int        // уровень эскалации (0 — первый бан)
	LastHitAt time.Time  // последняя активность (создание или попадание) — для сброса эскалации
}

// Active сообщает, что бан действует в момент now.
func (b Ban) Active(now time.Time) bool { return b.ExpiresAt == nil || b.ExpiresAt.After(now) }

// MTProtoSecret — клиентский секрет MTProto-прокси. SecretEnc — непрозрачные байты: store их
// не шифрует и не интерпретирует (шифрует сервисный слой, KEK с aad "mtproto/<id>").
type MTProtoSecret struct {
	ID          int64
	Name        string
	SecretEnc   []byte
	Prefix      string // первые 4 байта ключа в hex — для UI/логов
	CIDRs       []netip.Prefix
	MaxConns    int // 0 — без лимита
	Enabled     bool
	CreatedAt   time.Time
	RevokedAt   *time.Time
	GraceUntil  *time.Time // до этого момента ротированный/отозванный секрет ещё принимается
	RotatedFrom *int64     // id секрета, который этот заменил
}

// Active сообщает, что секрет принимается в момент now: включён, не отозван (либо отозван,
// но grace_until ещё не истёк) и grace_until не истёк.
func (s MTProtoSecret) Active(now time.Time) bool {
	if !s.Enabled {
		return false
	}
	if s.GraceUntil != nil && !s.GraceUntil.After(now) {
		return false
	}
	return s.RevokedAt == nil || s.GraceUntil != nil
}

// MTProtoSession — запись журнала соединения MTProto.
type MTProtoSession struct {
	ID          int64
	StartedAt   time.Time
	EndedAt     time.Time
	ClientIP    string
	SecretID    int64
	DC          int
	AgentID     string
	BytesIn     int64
	BytesOut    int64
	CloseReason string
}

// MTProtoSessionQuery — фильтры журнала; выдача от новых к старым, курсор BeforeID.
type MTProtoSessionQuery struct {
	BeforeID int64
	SecretID int64
	AgentID  string
	ClientIP string
	DC       int
	Limit    int // 0 — 100
}
