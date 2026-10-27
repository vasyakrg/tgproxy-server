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
			Source:        UpdateSourceGitHub,
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
		Ban: BanConfig{
			Enabled:    true,
			Threshold:  20,
			Window:     10 * time.Minute,
			Duration:   time.Hour,
			Escalation: []time.Duration{24 * time.Hour, 7 * 24 * time.Hour},
			ResetAfter: 30 * 24 * time.Hour,
			MaxTracked: 10000,
		},
		GeoIP: GeoIPConfig{File: "/usr/share/tgproxy/geoip/dbip-country-lite.mmdb"},
		MTProto: MTProtoConfig{
			Listen:               MTProtoListenShared,
			MaxConns:             20000,
			MaxConnsPerIP:        64,
			MaxPendingHandshakes: 1024,
			HandshakeTimeout:     5 * time.Second,
			IdleTimeout:          5 * time.Minute,
			TimeSkew:             2 * time.Minute,
			ReplayCache:          4 << 20,
			DCProbeInterval:      30 * time.Second,
			AgentPool: MTProtoAgentPool{
				ReverseConns:      2,
				MaxStreamsPerConn: 500,
				DialTimeout:       5 * time.Second,
			},
		},
		Logging: LoggingConfig{Level: "info", Format: "json"},
	}
}

// DefaultAgentAPIListen — адрес mTLS-листенера агента dial/both, если listen.api не задан.
const DefaultAgentAPIListen = ":8443"

// DefaultAgent возвращает конфигурацию агента со значениями по умолчанию.
func DefaultAgent() *AgentConfig {
	return &AgentConfig{
		Listen: AgentListen{
			// API по умолчанию пуст: reverse-агент входящих не принимает. Для dial/both пустой
			// адрес заменяется на DefaultAgentAPIListen после разбора env (AgentConfig.resolve).
			API:     "",
			Metrics: ":9443",
		},
		Mode:             AgentModeDial,
		AllowedClientSAN: "tgproxy-server",
		DataDir:          "/var/lib/tgproxy",
		MTProto: AgentMTProtoConfig{
			Enabled:     true,
			MaxStreams:  10000,
			DialTimeout: 5 * time.Second,
			IdleTimeout: 5 * time.Minute,
			MaxDuration: 24 * time.Hour,

			DCProbeInterval: 30 * time.Second,
		},
		Logging:        LoggingConfig{Level: "info", Format: "json"},
		telegramAPIURL: DefaultTelegramAPIURL,
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
