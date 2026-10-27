package config

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// ByteSize — размер в байтах. В YAML и env: целое число байт либо число с
// суффиксом (B, KiB, MiB, GiB; KB, MB, GB — десятичные), например "4MiB".
type ByteSize int64

var byteSizeType = typeOf[ByteSize]()

var byteSizeUnits = map[string]int64{
	"": 1, "b": 1,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30,
	"kb": 1000, "mb": 1000 * 1000, "gb": 1000 * 1000 * 1000,
}

// ParseByteSize разбирает размер: "4MiB", "1 GiB", "2097152".
func ParseByteSize(s string) (ByteSize, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool { return !unicode.IsDigit(r) })
	num, unit := s, ""
	if i >= 0 {
		num, unit = s[:i], strings.ToLower(strings.TrimSpace(s[i:]))
	}
	mult, ok := byteSizeUnits[unit]
	if !ok {
		return 0, fmt.Errorf("invalid size %q: unknown unit (want B|KiB|MiB|GiB|KB|MB|GB)", s)
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q: want non-negative integer with optional unit, e.g. 4MiB", s)
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return ByteSize(n * mult), nil
}

// UnmarshalYAML принимает и число, и строку с единицей.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: size must be a scalar", n.Line)
	}
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = v
	return nil
}

// String печатает точное значение в наибольшей целой единице.
func (b ByteSize) String() string {
	switch {
	case b > 0 && b%(1<<30) == 0:
		return fmt.Sprintf("%dGiB", b>>30)
	case b > 0 && b%(1<<20) == 0:
		return fmt.Sprintf("%dMiB", b>>20)
	case b > 0 && b%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", b>>10)
	}
	return fmt.Sprintf("%dB", int64(b))
}

// MTProtoListenShared — значение mtproto.listen: MTProto на листенере listen.proxy.
const MTProtoListenShared = "shared"

// MTProtoConfig — MTProto-прокси на сервере (docs/mtproto.md §10).
type MTProtoConfig struct {
	Enabled bool `yaml:"enabled"`
	// Listen — "shared" (общий листенер listen.proxy) или host:port (выделенный).
	Listen string `yaml:"listen"`
	// PublicHost — хост в ссылке; пусто — хост server.public_base_url.
	PublicHost string `yaml:"public_host"`
	// PublicPort — порт в ссылке; 0 — порт листенера.
	PublicPort int `yaml:"public_port"`
	// FrontingDomain — домен FakeTLS; обязан совпадать с доменом входного сертификата.
	FrontingDomain       string        `yaml:"fronting_domain"`
	MaxConns             int           `yaml:"max_conns"`
	MaxConnsPerIP        int           `yaml:"max_conns_per_ip"`
	MaxPendingHandshakes int           `yaml:"max_pending_handshakes"`
	HandshakeTimeout     time.Duration `yaml:"handshake_timeout"`
	IdleTimeout          time.Duration `yaml:"idle_timeout"`
	TimeSkew             time.Duration `yaml:"time_skew"`
	ReplayCache          ByteSize      `yaml:"replay_cache"`
	// DCProbeInterval пробрасывается агентам через /_agent/config.
	DCProbeInterval time.Duration    `yaml:"dc_probe_interval"`
	AgentPool       MTProtoAgentPool `yaml:"agent_pool"`
}

// MTProtoAgentPool — пул потоков сервер -> агент.
type MTProtoAgentPool struct {
	ReverseConns int `yaml:"reverse_conns"`
	// MaxReverseConns — потолок MTProto-соединений reverse-агента на сервере
	// (согласуйте с агентским mtproto.reverse_conns_max, по умолчанию 16).
	MaxReverseConns   int           `yaml:"max_reverse_conns"`
	MaxStreamsPerConn int           `yaml:"max_streams_per_conn"`
	DialTimeout       time.Duration `yaml:"dial_timeout"`
}

// AgentMTProtoConfig — релей MTProto на агенте (docs/mtproto.md §10).
type AgentMTProtoConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MaxStreams  int           `yaml:"max_streams"`
	DialTimeout time.Duration `yaml:"dial_timeout"`
	IdleTimeout time.Duration `yaml:"idle_timeout"`
	MaxDuration time.Duration `yaml:"max_duration"`
	IPv6        bool          `yaml:"ipv6"`
	// ReverseConnsMin/Max — границы пула MTProto-соединений reverse/both
	// (сервер просит размер через PUT /_agent/mtproto/pool, clamp в [min, max]).
	ReverseConnsMin int `yaml:"reverse_conns_min"`
	ReverseConnsMax int `yaml:"reverse_conns_max"`
	// DCProbeInterval — период TCP-проб DC; сервер может менять его через PUT /_agent/config.
	DCProbeInterval time.Duration `yaml:"dc_probe_interval"`
}

// Умолчания пула MTProto-соединений агента.
const (
	DefaultReverseConnsMin = 2
	DefaultReverseConnsMax = 16
)

// Границы dc_probe_interval агента (YAML и PUT /_agent/config).
const (
	MinDCProbeInterval = time.Second
	MaxDCProbeInterval = time.Hour
)

// Shared сообщает, что MTProto делит листенер с прокси ботов.
func (m MTProtoConfig) Shared() bool { return m.Listen == MTProtoListenShared }

// NeedsRestart сообщает, требует ли смена m -> next перезапуска сервера: enabled,
// listen и fronting_domain применяются только при старте; остальное — по SIGHUP.
func (m MTProtoConfig) NeedsRestart(next MTProtoConfig) bool {
	return m.Enabled != next.Enabled || m.Listen != next.Listen || m.FrontingDomain != next.FrontingDomain
}

// OverrideMTProtoDCs подменяет таблицу DC агента (DC -> адреса; отрицательный
// номер — media). Только для тестов и скрытого флага wiring-слоя: в YAML и env
// такой настройки нет намеренно — иначе агент становится открытым TCP-релеем.
// nil возвращает встроенную таблицу.
func (c *AgentConfig) OverrideMTProtoDCs(table map[int][]netip.AddrPort) {
	if table == nil {
		c.mtprotoDCs = nil
		return
	}
	c.mtprotoDCs = cloneDCTable(table)
}

// MTProtoDCOverride возвращает копию подменённой таблицы DC (nil — не подменена).
func (c *AgentConfig) MTProtoDCOverride() map[int][]netip.AddrPort {
	if c.mtprotoDCs == nil {
		return nil
	}
	return cloneDCTable(c.mtprotoDCs)
}

func cloneDCTable(t map[int][]netip.AddrPort) map[int][]netip.AddrPort {
	out := make(map[int][]netip.AddrPort, len(t))
	for dc, addrs := range t {
		out[dc] = append([]netip.AddrPort(nil), addrs...)
	}
	return out
}

// Границы настроек MTProto.
const (
	minMTProtoSkew   = 30 * time.Second
	maxMTProtoSkew   = 10 * time.Minute
	minReplayCache   = 1 << 20
	maxReplayCache   = 256 << 20
	maxFQDNLen       = 253
	maxDomainLabelLn = 63
)

func (v *validator) mtproto(c *ServerConfig) {
	m := c.MTProto
	positiveInt := func(path string, n int) {
		if n <= 0 {
			v.add(path, "must be positive, got %d", n)
		}
	}
	positiveInt("mtproto.max_conns", m.MaxConns)
	positiveInt("mtproto.max_conns_per_ip", m.MaxConnsPerIP)
	positiveInt("mtproto.max_pending_handshakes", m.MaxPendingHandshakes)
	v.positive("mtproto.handshake_timeout", m.HandshakeTimeout)
	v.positive("mtproto.idle_timeout", m.IdleTimeout)
	v.positive("mtproto.dc_probe_interval", m.DCProbeInterval)
	if m.TimeSkew < minMTProtoSkew || m.TimeSkew > maxMTProtoSkew {
		v.add("mtproto.time_skew", "must be in %s..%s, got %s", minMTProtoSkew, maxMTProtoSkew, m.TimeSkew)
	}
	if m.ReplayCache < minReplayCache || m.ReplayCache > maxReplayCache {
		v.add("mtproto.replay_cache", "must be in %s..%s, got %s", ByteSize(minReplayCache), ByteSize(maxReplayCache), m.ReplayCache)
	}
	positiveInt("mtproto.agent_pool.reverse_conns", m.AgentPool.ReverseConns)
	positiveInt("mtproto.agent_pool.max_reverse_conns", m.AgentPool.MaxReverseConns)
	if m.AgentPool.MaxReverseConns > 0 && m.AgentPool.MaxReverseConns < m.AgentPool.ReverseConns {
		v.add("mtproto.agent_pool.max_reverse_conns", "must be >= reverse_conns (%d), got %d", m.AgentPool.ReverseConns, m.AgentPool.MaxReverseConns)
	}
	positiveInt("mtproto.agent_pool.max_streams_per_conn", m.AgentPool.MaxStreamsPerConn)
	v.positive("mtproto.agent_pool.dial_timeout", m.AgentPool.DialTimeout)
	if m.PublicPort < 0 || m.PublicPort > 65535 {
		v.add("mtproto.public_port", "must be in 0..65535, got %d", m.PublicPort)
	}
	if m.PublicHost != "" && !validPublicHost(m.PublicHost) {
		v.add("mtproto.public_host", "want hostname or IP without port, got %q", m.PublicHost)
	}
	if m.FrontingDomain != "" && !validFQDN(m.FrontingDomain) {
		v.add("mtproto.fronting_domain", "want FQDN without port, e.g. tg.example.com, got %q", m.FrontingDomain)
	}
	if !m.Enabled {
		return
	}
	if m.FrontingDomain == "" {
		v.add("mtproto.fronting_domain", "required when mtproto.enabled (must match the ingress certificate domain)")
	}
	if c.PKI.KEKFile == "" {
		v.add("pki.kek_file", "required when mtproto.enabled (MTProto secrets are encrypted with the KEK)")
	}
	switch {
	case m.Shared():
		if c.TLS.Mode == TLSModeOff {
			v.add("mtproto.listen", "shared requires tls.mode files|acme (FakeTLS falls through to the real TLS handler); got tls.mode=off")
		}
	case m.Listen == "":
		v.add("mtproto.listen", "required: %q or host:port", MTProtoListenShared)
	default:
		v.dedicatedListen(c)
	}
}

func (v *validator) dedicatedListen(c *ServerConfig) {
	const path = "mtproto.listen"
	l := c.MTProto.Listen
	n := len(v.errs)
	v.addr(path, l)
	if len(v.errs) != n {
		return
	}
	for _, o := range []struct{ name, addr string }{
		{"listen.proxy", c.Listen.Proxy}, {"listen.admin", c.Listen.Admin},
		{"listen.metrics", c.Listen.Metrics}, {"listen.agent_gateway", c.Listen.AgentGateway},
	} {
		if listenConflict(l, o.addr) {
			v.add(path, "%q conflicts with %s (%q)", l, o.name, o.addr)
		}
	}
}

// listenConflict: один порт и совпадающий host либо wildcard (пустой/0.0.0.0/::) с любой стороны.
func listenConflict(a, b string) bool {
	ha, pa, errA := net.SplitHostPort(a)
	hb, pb, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || pa != pb {
		return false
	}
	return ha == hb || isWildcardHost(ha) || isWildcardHost(hb)
}

func isWildcardHost(h string) bool {
	if h == "" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsUnspecified()
}

// validFQDN: имя из >=2 меток [A-Za-z0-9-], без порта, wildcard, завершающей точки и IP.
func validFQDN(s string) bool {
	if len(s) > maxFQDNLen {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 || !validLabels(labels) {
		return false
	}
	last := labels[len(labels)-1]
	return strings.IndexFunc(last, func(r rune) bool { return r < '0' || r > '9' }) >= 0 // не IPv4
}

func validPublicHost(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return len(s) <= maxFQDNLen && validLabels(strings.Split(s, "."))
}

func validLabels(labels []string) bool {
	for _, l := range labels {
		if l == "" || len(l) > maxDomainLabelLn || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func (v *validator) agentMTProto(m AgentMTProtoConfig) {
	if m.MaxStreams <= 0 {
		v.add("mtproto.max_streams", "must be positive, got %d", m.MaxStreams)
	}
	v.positive("mtproto.dial_timeout", m.DialTimeout)
	v.positive("mtproto.idle_timeout", m.IdleTimeout)
	v.positive("mtproto.max_duration", m.MaxDuration)
	if m.DCProbeInterval < MinDCProbeInterval || m.DCProbeInterval > MaxDCProbeInterval {
		v.add("mtproto.dc_probe_interval", "must be in %s..%s, got %s", MinDCProbeInterval, MaxDCProbeInterval, m.DCProbeInterval)
	}
	if m.ReverseConnsMin < 1 {
		v.add("mtproto.reverse_conns_min", "must be >= 1, got %d", m.ReverseConnsMin)
	}
	if m.ReverseConnsMax < m.ReverseConnsMin {
		v.add("mtproto.reverse_conns_max", "must be >= reverse_conns_min (%d), got %d", m.ReverseConnsMin, m.ReverseConnsMax)
	}
	if m.IdleTimeout > 0 && m.MaxDuration > 0 && m.IdleTimeout > m.MaxDuration {
		v.add("mtproto.idle_timeout", "must not exceed mtproto.max_duration (%s), got %s", m.MaxDuration, m.IdleTimeout)
	}
}
