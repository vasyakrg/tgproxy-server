// Package config содержит типы конфигурации server и agent, загрузку
// (YAML со строгим разбором -> env-override -> *_file секреты) и валидацию.
//
// Порядок приоритета: значения по умолчанию < YAML < переменные окружения
// TGPROXY_<SECTION>__<FIELD> < секреты из *_file (секреты задаются только файлом).
package config

import (
	"log/slog"
	"net/netip"
	"time"
)

// Secret — значение секрета, прочитанное из *_file. Не печатается ни в логах,
// ни в fmt/JSON/YAML-выводе; получить значение можно только через Reveal.
type Secret string

// Reveal возвращает открытое значение секрета.
func (s Secret) Reveal() string { return string(s) }

// String маскирует значение.
func (Secret) String() string { return "***" }

// GoString маскирует значение в %#v.
func (Secret) GoString() string { return `"***"` }

// LogValue маскирует значение в slog.
func (Secret) LogValue() slog.Value { return slog.StringValue("***") }

// MarshalText маскирует значение при сериализации.
func (Secret) MarshalText() ([]byte, error) { return []byte("***"), nil }

// Режимы и перечисления.
type (
	// TLSMode — режим TLS на входе сервера (docs/architecture.md §3.1).
	TLSMode string
	// AgentMode — способ связи server <-> agent (§4.1).
	AgentMode string
	// WebhookPolicy — политика для setWebhook.
	WebhookPolicy string
	// StoreDriver — драйвер хранилища эфемерных данных (§7).
	StoreDriver string
)

// Допустимые значения перечислений.
const (
	TLSModeOff   TLSMode = "off"
	TLSModeFiles TLSMode = "files"
	TLSModeACME  TLSMode = "acme"

	AgentModeDial    AgentMode = "dial"
	AgentModeReverse AgentMode = "reverse"

	WebhookDeny        WebhookPolicy = "deny"
	WebhookPassthrough WebhookPolicy = "passthrough"

	StoreSQLite StoreDriver = "sqlite"
	StoreRedis  StoreDriver = "redis"
)

// DefaultTelegramAPIURL — единственный upstream агента.
const DefaultTelegramAPIURL = "https://api.telegram.org"

// ---------------------------------------------------------------- server

// ServerConfig — конфигурация процесса `tgproxy server`.
type ServerConfig struct {
	Server         ServerSection  `yaml:"server"`
	Listen         ServerListen   `yaml:"listen"`
	TLS            IngressTLS     `yaml:"tls"`
	TrustedProxies []netip.Prefix `yaml:"trusted_proxies"`
	// AgentTLS — статические mTLS-материалы сервера для связи с агентами (M1).
	// Полная PKI (pki.dir) появляется в M5; одно из двух обязательно, если есть агенты.
	AgentTLS      TLSFiles        `yaml:"agent_tls"`
	PKI           PKIConfig       `yaml:"pki"`
	Auth          AuthConfig      `yaml:"auth"`
	Agents        []AgentEndpoint `yaml:"agents"`
	AccessRules   []AccessRule    `yaml:"access_rules"`
	WebhookPolicy WebhookPolicy   `yaml:"webhook_policy"`
	Router        RouterConfig    `yaml:"router"`
	Buffer        BufferConfig    `yaml:"buffer"`
	Store         StoreConfig     `yaml:"store"`
	Update        UpdateConfig    `yaml:"update"`
	Notify        NotifyConfig    `yaml:"notify"`
	Metrics       MetricsConfig   `yaml:"metrics"`
	Logging       LoggingConfig   `yaml:"logging"`
}

// ServerSection — общие параметры сервера.
type ServerSection struct {
	// PublicBaseURL — публичный base URL прокси для ботов (https://tg.example.com; http — только loopback).
	// Показывается в UI «Доступ». Пусто — берётся из Host запроса.
	PublicBaseURL string `yaml:"public_base_url"`
}

// ServerListen — адреса листенеров сервера (host:port).
type ServerListen struct {
	Proxy        string `yaml:"proxy"`         // прокси для ботов
	Admin        string `yaml:"admin"`         // Web-UI + /api/v1
	Metrics      string `yaml:"metrics"`       // /metrics (bearer)
	AgentGateway string `yaml:"agent_gateway"` // reverse-соединения агентов (mTLS)
}

// IngressTLS — TLS на входе сервера (прокси ботов и админка).
type IngressTLS struct {
	Mode     TLSMode    `yaml:"mode"`
	CertFile string     `yaml:"cert_file"`
	KeyFile  string     `yaml:"key_file"`
	Domains  []string   `yaml:"domains"`
	CacheDir string     `yaml:"cache_dir"` // кеш autocert, только для mode=acme
	ACME     ACMEConfig `yaml:"acme"`
}

// ACMEConfig — параметры mode=acme.
type ACMEConfig struct {
	Email          string `yaml:"email"`
	DirectoryURL   string `yaml:"directory_url"`
	ViaAgentEgress bool   `yaml:"via_agent_egress"`
	// HTTP01Listen — адрес листенера HTTP-01 (обычно ":80"); пусто — только TLS-ALPN-01.
	HTTP01Listen string `yaml:"http01_listen"`
}

// TLSFiles — набор файлов TLS (сертификат, ключ, CA).
type TLSFiles struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

// PKIConfig — каталог встроенного CA и файл KEK (полная PKI — M5).
type PKIConfig struct {
	Dir     string `yaml:"dir"`
	KEKFile string `yaml:"kek_file"`
}

// AuthConfig — аутентификация админов.
type AuthConfig struct {
	UsersFile string `yaml:"users_file"` // users_database.yml (формат Authelia)
	// AllowPasswordOnly — DEV ONLY (M4-T2): пускать пользователей без TOTP-секрета только по паролю.
	// По умолчанию false: TOTP обязателен.
	AllowPasswordOnly bool `yaml:"allow_password_only"`
}

// AgentEndpoint — статически заданный агент (M1).
type AgentEndpoint struct {
	ID     string    `yaml:"id"`
	URL    string    `yaml:"url"` // https://host:8443, только для mode=dial
	Mode   AgentMode `yaml:"mode"`
	Weight int       `yaml:"weight"` // 0 в YAML = «не задан» -> 1
}

// AccessRule — правило доступа: имя + сети и/или скрытый ключ + лимит rps.
type AccessRule struct {
	Name      string         `yaml:"name"`
	CIDRs     []netip.Prefix `yaml:"cidrs"`
	KeySHA256 string         `yaml:"key_sha256"` // hex SHA-256 ключа
	KeyFile   string         `yaml:"key_file"`   // файл с открытым ключом (хешируется при загрузке)
	RPS       float64        `yaml:"rps"`        // 0 = без лимита

	// KeyHash — SHA-256 ключа, заполняется при загрузке из KeySHA256/KeyFile.
	KeyHash []byte `yaml:"-"`
}

// HasKey сообщает, задан ли у правила скрытый ключ.
func (r AccessRule) HasKey() bool { return r.KeySHA256 != "" || r.KeyFile != "" }

// RouterConfig — ретраи и таймауты маршрутизации (§6).
type RouterConfig struct {
	MaxAttempts   int           `yaml:"max_attempts"`
	Budget        time.Duration `yaml:"budget"`
	LongPollExtra time.Duration `yaml:"long_poll_extra"`
	MaxLongPoll   time.Duration `yaml:"max_long_poll"`
	NoAgentWait   time.Duration `yaml:"no_agent_wait"`
}

// BufferConfig — буфер тела запроса на время ретраев (§6).
type BufferConfig struct {
	RAMMax  int64  `yaml:"ram_max"`  // байт
	DiskMax int64  `yaml:"disk_max"` // байт
	BodyMax int64  `yaml:"body_max"` // байт, больше -> 413
	TmpDir  string `yaml:"tmp_dir"`  // пусто = os.TempDir()
}

// StoreConfig — хранилище (§7). SQLite нужен всегда; redis — для эфемерных данных.
type StoreConfig struct {
	Driver            StoreDriver `yaml:"driver"`
	SQLitePath        string      `yaml:"sqlite_path"`
	RedisURL          string      `yaml:"redis_url"` // только rediss://
	RedisPasswordFile string      `yaml:"redis_password_file"`
	RedisCAFile       string      `yaml:"redis_ca_file"` // PEM CA для rediss://; пусто — системные корни

	RedisPassword Secret `yaml:"-"`
}

// UpdateConfig — самообновление (§12).
type UpdateConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Repo          string        `yaml:"repo"` // owner/name на GitHub
	HTTPProxy     string        `yaml:"http_proxy"`
	CheckInterval time.Duration `yaml:"check_interval"`
	MinVersion    string        `yaml:"min_version"`
	StagingDir    string        `yaml:"staging_dir"`
}

// NotifyConfig — алерты в Telegram (§9). Включены, если задан bot_token_file.
type NotifyConfig struct {
	BotTokenFile    string        `yaml:"bot_token_file"`
	RepeatInterval  time.Duration `yaml:"repeat_interval"`  // повтор firing
	MaxPerMinute    int           `yaml:"max_per_minute"`   // глобальный лимит
	CertExpiryWarn  time.Duration `yaml:"cert_expiry_warn"` // за сколько предупреждать
	DeliveryTimeout time.Duration `yaml:"delivery_timeout"`

	BotToken Secret `yaml:"-"`
}

// Enabled сообщает, настроен ли notifier.
func (n NotifyConfig) Enabled() bool { return n.BotTokenFile != "" }

// MetricsConfig — защита /metrics.
type MetricsConfig struct {
	BearerFile string `yaml:"bearer_file"`

	Bearer Secret `yaml:"-"`
}

// LoggingConfig — slog.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug|info|warn|error
	Format string `yaml:"format"` // json|text
}

// ----------------------------------------------------------------- agent

// AgentConfig — конфигурация процесса `tgproxy agent`.
//
// Upstream (api.telegram.org) в YAML не настраивается: поле telegramAPIURL
// неэкспортируемое. Подмена возможна только через OverrideTelegramAPIURL
// (тесты и скрытый флаг wiring-слоя).
type AgentConfig struct {
	Listen           AgentListen   `yaml:"listen"`
	Mode             AgentMode     `yaml:"mode"`
	ServerURL        string        `yaml:"server_url"` // https://host:8444, для mode=reverse
	TLS              TLSFiles      `yaml:"tls"`
	AllowedClientSAN string        `yaml:"allowed_client_san"`
	DataDir          string        `yaml:"data_dir"`
	Metrics          MetricsConfig `yaml:"metrics"`
	Logging          LoggingConfig `yaml:"logging"`

	telegramAPIURL string
}

// AgentListen — адреса листенеров агента.
type AgentListen struct {
	API     string `yaml:"api"`     // mTLS: /tg/*, /_agent/*
	Metrics string `yaml:"metrics"` // /metrics (bearer)
}
