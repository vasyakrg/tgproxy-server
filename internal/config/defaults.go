package config

import (
	"fmt"
	"net/url"
	"time"
)

// DefaultServer возвращает серверную конфигурацию со значениями по умолчанию
// (раскладка портов — docs/plan.md §0.2). YAML накладывается поверх этих значений,
// поэтому явный нулевой таймаут в файле попадёт в валидацию и будет отвергнут.
func DefaultServer() *ServerConfig {
	return &ServerConfig{
		Listen: ServerListen{
			Proxy:        ":8080",
			Admin:        "127.0.0.1:8090",
			Metrics:      ":9090",
			AgentGateway: ":8444",
		},
		TLS: IngressTLS{
			Mode:     TLSModeOff,
			CacheDir: "/var/lib/tgproxy/acme",
		},
		PKI: PKIConfig{
			Dir:     "/var/lib/tgproxy/pki",
			KEKFile: "/etc/tgproxy/kek",
		},
		Auth:          AuthConfig{UsersFile: "/etc/tgproxy/users_database.yml"},
		WebhookPolicy: WebhookDeny,
		Router: RouterConfig{
			MaxAttempts:   3,
			Budget:        25 * time.Second,
			LongPollExtra: 15 * time.Second,
			MaxLongPoll:   65 * time.Second,
			NoAgentWait:   30 * time.Second,
		},
		Buffer: BufferConfig{
			RAMMax:  1 << 20,
			DiskMax: 10 << 20,
			BodyMax: 51 << 20,
		},
		Store: StoreConfig{
			Driver:     StoreSQLite,
			SQLitePath: "/var/lib/tgproxy/tgproxy.db",
		},
		Update: UpdateConfig{
			Enabled:       true,
			Repo:          "vasyakrg/tgproxy-server",
			CheckInterval: 6 * time.Hour,
			StagingDir:    "/var/lib/tgproxy/updates",
		},
		Notify: NotifyConfig{
			RepeatInterval:  time.Hour,
			MaxPerMinute:    20,
			CertExpiryWarn:  14 * 24 * time.Hour,
			DeliveryTimeout: 30 * time.Second,
		},
		Logging: LoggingConfig{Level: "info", Format: "json"},
	}
}

// DefaultAgent возвращает конфигурацию агента со значениями по умолчанию.
func DefaultAgent() *AgentConfig {
	return &AgentConfig{
		Listen: AgentListen{
			API:     ":8443",
			Metrics: ":9443",
		},
		Mode:             AgentModeDial,
		AllowedClientSAN: "tgproxy-server",
		DataDir:          "/var/lib/tgproxy",
		Logging:          LoggingConfig{Level: "info", Format: "json"},
		telegramAPIURL:   DefaultTelegramAPIURL,
	}
}

// normalize приводит значения, которые нельзя выразить префиллом (элементы слайсов).
func (c *ServerConfig) normalize() {
	for i := range c.Agents {
		if c.Agents[i].Mode == "" {
			c.Agents[i].Mode = AgentModeDial
		}
		if c.Agents[i].Weight == 0 {
			c.Agents[i].Weight = 1
		}
	}
}

func (c *AgentConfig) normalize() {
	if c.telegramAPIURL == "" {
		c.telegramAPIURL = DefaultTelegramAPIURL
	}
}

// TelegramAPIURL возвращает upstream агента (по умолчанию https://api.telegram.org).
func (c *AgentConfig) TelegramAPIURL() string {
	if c.telegramAPIURL == "" {
		return DefaultTelegramAPIURL
	}
	return c.telegramAPIURL
}

// OverrideTelegramAPIURL подменяет upstream агента. Предназначено только для
// тестов и скрытого (не документируемого) флага wiring-слоя: в YAML и env
// такой настройки нет намеренно — иначе агент становится открытым relay.
// Допускается только https:// (mTLS-канал и TLS до upstream не ослабляются).
func (c *AgentConfig) OverrideTelegramAPIURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("telegram api url %q: want https://host[:port]", raw)
	}
	c.telegramAPIURL = raw
	return nil
}
