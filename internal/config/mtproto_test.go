package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// mtServerYAML — базовый серверный конфиг с TLS files и включённым MTProto.
const mtServerYAML = `
listen:
  proxy: "127.0.0.1:8080"
  metrics: "127.0.0.1:9090"
tls:
  mode: files
  cert_file: c.crt
  key_file: c.key
`

func mtServer(t *testing.T, mt string, env ...string) (*ServerConfig, error) {
	t.Helper()
	return parseServer(t, mtServerYAML+mt, env...)
}

// Пример из docs/mtproto.md §10.
const docExampleServer = `
mtproto:
  enabled: true
  listen: shared
  public_host: ""
  public_port: 0
  fronting_domain: tg.example.com
  max_conns: 20000
  max_conns_per_ip: 64
  max_pending_handshakes: 1024
  handshake_timeout: 5s
  idle_timeout: 5m
  time_skew: 2m
  replay_cache: 4MiB
  dc_probe_interval: 30s
  agent_pool:
    reverse_conns: 2
    max_reverse_conns: 16
    max_streams_per_conn: 500
    dial_timeout: 5s
`

const docExampleAgent = `
mtproto:
  enabled: true
  max_streams: 10000
  dial_timeout: 5s
  idle_timeout: 5m
  max_duration: 24h
  ipv6: false
`

func TestMTProtoServerDefaults(t *testing.T) {
	d := DefaultServer().MTProto
	want := MTProtoConfig{
		Enabled: false, Listen: "shared", MaxConns: 20000, MaxConnsPerIP: 64, MaxPendingHandshakes: 1024,
		HandshakeTimeout: 5 * time.Second, IdleTimeout: 5 * time.Minute, TimeSkew: 2 * time.Minute,
		ReplayCache: 4 << 20, DCProbeInterval: 30 * time.Second,
		AgentPool: MTProtoAgentPool{ReverseConns: 2, MaxReverseConns: 16, MaxStreamsPerConn: 500, DialTimeout: 5 * time.Second},
	}
	if d != want {
		t.Fatalf("defaults = %+v, want %+v", d, want)
	}
	// Выключенный MTProto не требует ничего: дефолтный конфиг валиден.
	if _, err := parseServer(t, baseServer); err != nil {
		t.Fatal(err)
	}
}

func TestMTProtoAgentDefaults(t *testing.T) {
	d := DefaultAgent().MTProto
	want := AgentMTProtoConfig{Enabled: true, MaxStreams: 10000, DialTimeout: 5 * time.Second,
		IdleTimeout: 5 * time.Minute, MaxDuration: 24 * time.Hour, DCProbeInterval: 30 * time.Second,
		ReverseConnsMin: 2, ReverseConnsMax: 16}
	if d != want {
		t.Fatalf("defaults = %+v, want %+v", d, want)
	}
}

func TestMTProtoDocExampleValid(t *testing.T) {
	c, err := mtServer(t, docExampleServer)
	if err != nil {
		t.Fatalf("doc example server: %v", err)
	}
	if c.MTProto != func() MTProtoConfig {
		m := DefaultServer().MTProto
		m.Enabled = true
		m.FrontingDomain = "tg.example.com"
		return m
	}() {
		t.Fatalf("unexpected parsed config: %+v", c.MTProto)
	}
	a, err := parseAgent(t, baseAgent+docExampleAgent)
	if err != nil {
		t.Fatalf("doc example agent: %v", err)
	}
	if a.MTProto != DefaultAgent().MTProto {
		t.Fatalf("agent = %+v", a.MTProto)
	}
}

func TestMTProtoServerValidation(t *testing.T) {
	const on = "mtproto:\n  enabled: true\n  fronting_domain: tg.example.com\n"
	tests := []struct {
		name string
		yaml string
		want string // "" — ошибки быть не должно
	}{
		{"enabled ok", on, ""},
		{"disabled needs nothing", "mtproto:\n  enabled: false\n", ""},
		{"fronting required", "mtproto:\n  enabled: true\n", "mtproto.fronting_domain"},
		{"fronting with port", "mtproto:\n  enabled: true\n  fronting_domain: tg.example.com:443\n", "mtproto.fronting_domain"},
		{"fronting single label", "mtproto:\n  enabled: true\n  fronting_domain: localhost\n", "mtproto.fronting_domain"},
		{"fronting ip", "mtproto:\n  enabled: true\n  fronting_domain: 1.2.3.4\n", "mtproto.fronting_domain"},
		{"fronting wildcard", "mtproto:\n  enabled: true\n  fronting_domain: '*.example.com'\n", "mtproto.fronting_domain"},
		{"fronting bad label", "mtproto:\n  enabled: true\n  fronting_domain: -a.example.com\n", "mtproto.fronting_domain"},
		{"fronting long label", "mtproto:\n  enabled: true\n  fronting_domain: " + strings.Repeat("a", 64) + ".example.com\n", "mtproto.fronting_domain"},
		{"fronting too long", "mtproto:\n  enabled: true\n  fronting_domain: " + strings.Repeat("a.", 130) + "com\n", "mtproto.fronting_domain"},
		{"fronting trailing dot", "mtproto:\n  enabled: true\n  fronting_domain: tg.example.com.\n", "mtproto.fronting_domain"},
		{"fronting bad even if disabled", "mtproto:\n  fronting_domain: a b.example.com\n", "mtproto.fronting_domain"},
		{"dedicated ok", on + "  listen: '0.0.0.0:8443'\n", ""},
		{"dedicated bad addr", on + "  listen: nonsense\n", "mtproto.listen"},
		{"dedicated eq proxy", on + "  listen: '127.0.0.1:8080'\n", "mtproto.listen"},
		{"dedicated eq admin", on + "  listen: '127.0.0.1:8090'\n", "mtproto.listen"},
		{"dedicated eq metrics", on + "  listen: '127.0.0.1:9090'\n", "mtproto.listen"},
		{"dedicated eq gateway", on + "  listen: ':8444'\n", "mtproto.listen"},
		{"dedicated wildcard vs proxy port", on + "  listen: ':8080'\n", "mtproto.listen"},
		{"dedicated same port other host ok", on + "  listen: '10.0.0.1:8080'\n", ""},
		{"public_port range", on + "  public_port: 70000\n", "mtproto.public_port"},
		{"public_host with port", on + "  public_host: 'a.example.com:443'\n", "mtproto.public_host"},
		{"public_host ok", on + "  public_host: a.example.com\n  public_port: 443\n", ""},
		{"skew low", on + "  time_skew: 10s\n", "mtproto.time_skew"},
		{"skew high", on + "  time_skew: 11m\n", "mtproto.time_skew"},
		{"skew bounds", on + "  time_skew: 30s\n", ""},
		{"skew upper bound", on + "  time_skew: 10m\n", ""},
		{"replay low", on + "  replay_cache: 512KiB\n", "mtproto.replay_cache"},
		{"replay high", on + "  replay_cache: 257MiB\n", "mtproto.replay_cache"},
		{"replay bounds", on + "  replay_cache: 256MiB\n", ""},
		{"replay int bytes", on + "  replay_cache: 2097152\n", ""},
		{"replay garbage", on + "  replay_cache: lots\n", "invalid size"},
		{"max_conns zero", on + "  max_conns: 0\n", "mtproto.max_conns"},
		{"per_ip negative", on + "  max_conns_per_ip: -1\n", "mtproto.max_conns_per_ip"},
		{"pending zero", on + "  max_pending_handshakes: 0\n", "mtproto.max_pending_handshakes"},
		{"handshake zero", on + "  handshake_timeout: 0s\n", "mtproto.handshake_timeout"},
		{"idle zero", on + "  idle_timeout: 0s\n", "mtproto.idle_timeout"},
		{"probe zero", on + "  dc_probe_interval: 0s\n", "mtproto.dc_probe_interval"},
		{"reverse_conns zero", on + "  agent_pool:\n    reverse_conns: 0\n", "mtproto.agent_pool.reverse_conns"},
		{"max_reverse_conns below reverse_conns", on + "  agent_pool:\n    reverse_conns: 4\n    max_reverse_conns: 3\n", "mtproto.agent_pool.max_reverse_conns"},
		{"max_reverse_conns zero", on + "  agent_pool:\n    max_reverse_conns: 0\n", "mtproto.agent_pool.max_reverse_conns"},
		{"streams per conn zero", on + "  agent_pool:\n    max_streams_per_conn: 0\n", "mtproto.agent_pool.max_streams_per_conn"},
		{"pool dial zero", on + "  agent_pool:\n    dial_timeout: 0s\n", "mtproto.agent_pool.dial_timeout"},
		{"limits checked when disabled", "mtproto:\n  max_conns: 0\n", "mtproto.max_conns"},
		{"unknown field", on + "  bogus: 1\n", "mtproto.bogus: unknown field"},
		{"unknown pool field", on + "  agent_pool:\n    bogus: 1\n", "mtproto.agent_pool.bogus: unknown field"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mtServer(t, tc.yaml)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			wantErr(t, err, tc.want)
		})
	}
}

func TestMTProtoRequiresKEK(t *testing.T) {
	c := DefaultServer()
	c.Listen.Proxy, c.Listen.Metrics = "127.0.0.1:8080", "127.0.0.1:9090"
	c.TLS = IngressTLS{Mode: TLSModeFiles, CertFile: "c", KeyFile: "k"}
	c.MTProto.Enabled, c.MTProto.FrontingDomain = true, "tg.example.com"
	if err := ValidateServer(c); err != nil {
		t.Fatal(err)
	}
	c.PKI.KEKFile = ""
	wantErr(t, ValidateServer(c), "pki.kek_file")
	c.MTProto.Enabled = false
	if err := ValidateServer(c); err != nil {
		t.Fatalf("disabled must not require kek: %v", err)
	}
}

func TestMTProtoSharedRequiresTLS(t *testing.T) {
	c := DefaultServer()
	c.Listen.Proxy, c.Listen.Metrics = "127.0.0.1:8080", "127.0.0.1:9090"
	c.MTProto.Enabled, c.MTProto.FrontingDomain = true, "tg.example.com"
	wantErr(t, ValidateServer(c), "mtproto.listen", "tls.mode")
	// dedicated при tls.mode=off — допустим по этому правилу.
	c.MTProto.Listen = "0.0.0.0:8443"
	if err := ValidateServer(c); err != nil {
		t.Fatalf("dedicated with tls off: %v", err)
	}
	c.MTProto.Listen = ""
	wantErr(t, ValidateServer(c), "mtproto.listen")
}

func TestMTProtoEnv(t *testing.T) {
	c, err := mtServer(t, "", "TGPROXY_MTPROTO__REPLAY_CACHE=8MiB", "TGPROXY_MTPROTO__TIME_SKEW=1m",
		"TGPROXY_MTPROTO__AGENT_POOL__REVERSE_CONNS=4", "TGPROXY_MTPROTO__ENABLED=false")
	if err != nil {
		t.Fatal(err)
	}
	if c.MTProto.ReplayCache != 8<<20 || c.MTProto.TimeSkew != time.Minute || c.MTProto.AgentPool.ReverseConns != 4 {
		t.Fatalf("%+v", c.MTProto)
	}
	_, err = mtServer(t, "", "TGPROXY_MTPROTO__REPLAY_CACHE=junk")
	wantErr(t, err, "REPLAY_CACHE")
}

func TestByteSizeParse(t *testing.T) {
	ok := map[string]ByteSize{
		"4MiB": 4 << 20, "1 MiB": 1 << 20, "2GiB": 2 << 30, "3KiB": 3 << 10, "10B": 10, "7": 7,
		"1MB": 1000 * 1000, "1kb": 1000, "1GB": 1000 * 1000 * 1000, "1mib": 1 << 20,
	}
	for in, want := range ok {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("ParseByteSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "MiB", "-1MiB", "1.5MiB", "1XiB", "99999999999999GiB", "1 2 MiB"} {
		if _, err := ParseByteSize(in); err == nil {
			t.Errorf("ParseByteSize(%q): want error", in)
		}
	}
	if s := ByteSize(4 << 20).String(); s != "4MiB" {
		t.Errorf("String = %q", s)
	}
	if s := ByteSize(1500).String(); s != "1500B" {
		t.Errorf("String = %q", s)
	}
	if s := ByteSize(0).String(); s != "0B" {
		t.Errorf("String = %q", s)
	}
}

func TestMTProtoAgentValidation(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"ok", "mtproto:\n  enabled: false\n", ""},
		{"streams zero", "mtproto:\n  max_streams: 0\n", "mtproto.max_streams"},
		{"dial zero", "mtproto:\n  dial_timeout: 0s\n", "mtproto.dial_timeout"},
		{"idle zero", "mtproto:\n  idle_timeout: -1s\n", "mtproto.idle_timeout"},
		{"max_duration zero", "mtproto:\n  max_duration: 0s\n", "mtproto.max_duration"},
		{"idle > max_duration", "mtproto:\n  idle_timeout: 2h\n  max_duration: 1h\n", "mtproto.idle_timeout"},
		{"probe zero", "mtproto:\n  dc_probe_interval: 0s\n", "mtproto.dc_probe_interval"},
		{"probe too small", "mtproto:\n  dc_probe_interval: 500ms\n", "mtproto.dc_probe_interval"},
		{"probe too large", "mtproto:\n  dc_probe_interval: 2h\n", "mtproto.dc_probe_interval"},
		{"probe ok", "mtproto:\n  dc_probe_interval: 10s\n", ""},
		{"unknown", "mtproto:\n  bogus: 1\n", "mtproto.bogus: unknown field"},
		{"ipv6", "mtproto:\n  ipv6: true\n", ""},
		{"reverse min zero", "mtproto:\n  reverse_conns_min: 0\n", "mtproto.reverse_conns_min"},
		{"reverse max < min", "mtproto:\n  reverse_conns_min: 4\n  reverse_conns_max: 3\n", "mtproto.reverse_conns_max"},
		{"reverse ok", "mtproto:\n  reverse_conns_min: 1\n  reverse_conns_max: 1\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAgent(t, baseAgent+tc.yaml)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantErr(t, err, tc.want)
		})
	}
}

func TestMTProtoNeedsRestart(t *testing.T) {
	base := DefaultServer().MTProto
	base.FrontingDomain = "tg.example.com"
	mut := map[string]func(*MTProtoConfig){
		"enabled":         func(m *MTProtoConfig) { m.Enabled = !m.Enabled },
		"listen":          func(m *MTProtoConfig) { m.Listen = "0.0.0.0:8443" },
		"fronting_domain": func(m *MTProtoConfig) { m.FrontingDomain = "other.example.com" },
	}
	for name, f := range mut {
		next := base
		f(&next)
		if !base.NeedsRestart(next) {
			t.Errorf("%s: want restart", name)
		}
	}
	live := map[string]func(*MTProtoConfig){
		"max_conns":         func(m *MTProtoConfig) { m.MaxConns++ },
		"idle":              func(m *MTProtoConfig) { m.IdleTimeout++ },
		"time_skew":         func(m *MTProtoConfig) { m.TimeSkew++ },
		"pool":              func(m *MTProtoConfig) { m.AgentPool.ReverseConns++ },
		"public_host":       func(m *MTProtoConfig) { m.PublicHost = "x.example.com" },
		"dc_probe_interval": func(m *MTProtoConfig) { m.DCProbeInterval++ },
	}
	for name, f := range live {
		next := base
		f(&next)
		if base.NeedsRestart(next) {
			t.Errorf("%s: must be applied on SIGHUP", name)
		}
	}
	if base.NeedsRestart(base) {
		t.Error("same config must not need restart")
	}
}

func TestOverrideMTProtoDCs(t *testing.T) {
	a := DefaultAgent()
	if a.MTProtoDCOverride() != nil {
		t.Fatal("no override by default")
	}
	ap := netip.MustParseAddrPort("127.0.0.1:4430")
	src := map[int][]netip.AddrPort{2: {ap}, -2: {ap}}
	a.OverrideMTProtoDCs(src)
	src[2][0] = netip.MustParseAddrPort("10.0.0.1:1")
	delete(src, -2)
	got := a.MTProtoDCOverride()
	if len(got) != 2 || got[2][0] != ap || got[-2][0] != ap {
		t.Fatalf("override must be a deep copy: %v", got)
	}
	got[2][0] = netip.MustParseAddrPort("10.0.0.2:1")
	if a.MTProtoDCOverride()[2][0] != ap {
		t.Fatal("accessor must return a copy")
	}
	a.OverrideMTProtoDCs(nil)
	if a.MTProtoDCOverride() != nil {
		t.Fatal("nil clears override")
	}
	// В YAML подменить нельзя.
	_, err := parseAgent(t, baseAgent+"mtproto:\n  dc_table: {}\n")
	wantErr(t, err, "mtproto.dc_table: unknown field")
}
