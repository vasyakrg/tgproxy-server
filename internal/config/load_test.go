package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsServer(t *testing.T) {
	c := mustServer(t, baseServer)
	if c.Router.MaxAttempts != 3 || c.Router.Budget != 25*time.Second ||
		c.Router.LongPollExtra != 15*time.Second || c.Router.MaxLongPoll != 65*time.Second ||
		c.Router.NoAgentWait != 30*time.Second {
		t.Errorf("router defaults: %+v", c.Router)
	}
	if c.Buffer.RAMMax != 1<<20 || c.Buffer.DiskMax != 10<<20 || c.Buffer.BodyMax != 51<<20 {
		t.Errorf("buffer defaults: %+v", c.Buffer)
	}
	if c.WebhookPolicy != WebhookDeny || c.Store.Driver != StoreSQLite {
		t.Errorf("policy/store defaults: %v %v", c.WebhookPolicy, c.Store.Driver)
	}
	if c.Listen.AgentGateway != ":8444" || c.Listen.Admin != "127.0.0.1:8090" {
		t.Errorf("listen defaults: %+v", c.Listen)
	}
	if c.Logging.Level != "info" || c.Logging.Format != "json" {
		t.Errorf("logging defaults: %+v", c.Logging)
	}
}

func TestDefaultsAgent(t *testing.T) {
	c, err := parseAgent(t, baseAgent)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.API != ":8443" || c.Mode != AgentModeDial || c.AllowedClientSAN != "tgproxy-server" {
		t.Errorf("defaults: %+v", c)
	}
	if c.TelegramAPIURL() != "https://api.telegram.org" {
		t.Errorf("upstream = %q", c.TelegramAPIURL())
	}
}

func TestEmptyFileIsDefaults(t *testing.T) {
	_, err := parseServer(t, "")
	// пустой файл -> дефолты, которые невалидны только из-за metrics bearer / tls off на ":8080"
	wantErr(t, err, "tls.mode", "metrics.bearer_file")
}

func TestUnknownFieldHasPath(t *testing.T) {
	_, err := parseServer(t, baseServer+"router:\n  max_attemps: 5\n")
	wantErr(t, err, "router.max_attemps", "unknown field", "test.yaml")

	_, err = parseServer(t, baseServer+"agents:\n  - id: a\n    url: https://x:1\n    bogus: 1\n")
	wantErr(t, err, "agents[0].bogus")

	_, err = parseServer(t, baseServer+"nonsense: 1\n")
	wantErr(t, err, "nonsense")

	_, err = parseAgent(t, baseAgent+"telegram:\n  api_url: https://evil.example\n")
	wantErr(t, err, "telegram", "unknown field") // upstream в YAML не настраивается
}

func TestYAMLSyntaxAndTypeErrors(t *testing.T) {
	_, err := parseServer(t, "listen: [")
	wantErr(t, err, "test.yaml")
	_, err = parseServer(t, baseServer+"router:\n  budget: notaduration\n")
	wantErr(t, err, "test.yaml")
}

func TestPrefixAndDurationParsing(t *testing.T) {
	c := mustServer(t, baseServer+"router:\n  budget: 40s\ntrusted_proxies: [10.0.0.0/8, \"fd00::/8\"]\n")
	if c.Router.Budget != 40*time.Second {
		t.Errorf("budget = %v", c.Router.Budget)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("trusted_proxies = %v", c.TrustedProxies)
	}
	_, err := parseServer(t, baseServer+"trusted_proxies: [not-a-cidr]\n")
	wantErr(t, err, "test.yaml")
}

func TestEnvOverridesYAML(t *testing.T) {
	c := mustServer(t, baseServer+"router:\n  max_attempts: 2\n",
		"TGPROXY_LISTEN__PROXY=127.0.0.1:9999",
		"TGPROXY_ROUTER__MAX_ATTEMPTS=5",
		"TGPROXY_ROUTER__BUDGET=10s",
		"TGPROXY_WEBHOOK_POLICY=passthrough",
		"TGPROXY_UPDATE__ENABLED=false",
		"TGPROXY_TRUSTED_PROXIES=10.1.0.0/16, 10.2.0.0/16",
		"TGPROXY_TLS__DOMAINS=a.example, b.example",
		"TGPROXY_TLS__ACME__VIA_AGENT_EGRESS=true",
		"TGPROXY_BUFFER__RAM_MAX=2048",
		"TGPROXY_ROUTER__LONG_POLL_EXTRA=20s",
		"TGPROXY_OTHER_TOOL=ignored",
		"TGPROXY_CONFIG=/etc/x.yaml", // без "__" — не наш override
		"UNRELATED=1",
	)
	if c.Listen.Proxy != "127.0.0.1:9999" || c.Router.MaxAttempts != 5 || c.Router.Budget != 10*time.Second ||
		c.WebhookPolicy != WebhookPassthrough || c.Update.Enabled || c.Buffer.RAMMax != 2048 ||
		c.Router.LongPollExtra != 20*time.Second {
		t.Errorf("env not applied: %+v", c)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[1] != netip.MustParsePrefix("10.2.0.0/16") {
		t.Errorf("trusted_proxies = %v", c.TrustedProxies)
	}
	if len(c.TLS.Domains) != 2 || !c.TLS.ACME.ViaAgentEgress {
		t.Errorf("tls = %+v", c.TLS)
	}
}

func TestEnvAgent(t *testing.T) {
	c, err := parseAgent(t, baseAgent, "TGPROXY_LISTEN__API=127.0.0.1:1234", "TGPROXY_MODE=reverse",
		"TGPROXY_SERVER_URL=https://s.example:8444")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.API != "127.0.0.1:1234" || c.Mode != AgentModeReverse {
		t.Errorf("%+v", c)
	}
}

func TestEnvErrors(t *testing.T) {
	_, err := parseServer(t, baseServer, "TGPROXY_ROUTER__BUDGET=forever")
	wantErr(t, err, "TGPROXY_ROUTER__BUDGET")
	_, err = parseServer(t, baseServer, "TGPROXY_ROUTER__MAX_ATTEMPTS=x")
	wantErr(t, err, "TGPROXY_ROUTER__MAX_ATTEMPTS")
	_, err = parseServer(t, baseServer, "TGPROXY_UPDATE__ENABLED=maybe")
	wantErr(t, err, "TGPROXY_UPDATE__ENABLED")
	_, err = parseServer(t, baseServer, "TGPROXY_TRUSTED_PROXIES=bad")
	wantErr(t, err, "TGPROXY_TRUSTED_PROXIES")
	_, err = parseServer(t, baseServer, "TGPROXY_LISTEN__PROXI=:1") // опечатка
	wantErr(t, err, "TGPROXY_LISTEN__PROXI", "unknown override")
	// секреты и списки структур через env не задаются
	_, err = parseServer(t, baseServer, "TGPROXY_NOTIFY__BOT_TOKEN=123")
	wantErr(t, err, "unknown override")
	_, err = parseServer(t, baseServer, "TGPROXY_AGENTS=x")
	if err != nil {
		t.Errorf("single-segment unknown names are ignored, got %v", err)
	}
}

func TestSetScalarFloatAndUnsupported(t *testing.T) {
	var s struct {
		F float64           `yaml:"f"`
		M map[string]string `yaml:"m"`
	}
	err := applyEnv(&s, []string{"TGPROXY_F=1.5", "TGPROXY_M=x"})
	wantErr(t, err, "TGPROXY_M", "unsupported type")
	if s.F != 1.5 {
		t.Errorf("F = %v", s.F)
	}
	err = applyEnv(&s, []string{"TGPROXY_F=abc"})
	wantErr(t, err, "TGPROXY_F")
}

func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	tok := writeFile(t, dir, "tok", "123456:AAAA\n", 0o600)
	pw := writeFile(t, dir, "pw", "s3cret", 0o640)
	bearer := writeFile(t, dir, "bearer", " b-token \n", 0o600)
	y := baseServer + fmt.Sprintf("notify:\n  bot_token_file: %s\nstore:\n  redis_password_file: %s\nmetrics:\n  bearer_file: %s\n", tok, pw, bearer)
	c := mustServer(t, y)
	if c.Notify.BotToken.Reveal() != "123456:AAAA" || c.Store.RedisPassword.Reveal() != "s3cret" ||
		c.Metrics.Bearer.Reveal() != "b-token" {
		t.Errorf("secrets not resolved: %v %v %v", c.Notify.BotToken, c.Store.RedisPassword, c.Metrics.Bearer)
	}
	if !c.Notify.Enabled() {
		t.Error("notify should be enabled")
	}
	if got := fmt.Sprintf("%v %+v %#v", c.Notify.BotToken, c.Notify, c.Metrics.Bearer); strings.Contains(got, "123456:AAAA") || strings.Contains(got, "b-token") {
		t.Errorf("secret leaked in fmt output: %s", got)
	}
}

func TestSecretFilePermissions(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o600, true}, {0o640, true}, {0o400, true}, {0o644, false}, {0o660, false}, {0o604, false}, {0o777, false}} {
		p := writeFile(t, dir, fmt.Sprintf("tok-%o", tc.mode), "123456:AAAA", tc.mode)
		_, err := parseServer(t, baseServer+"notify:\n  bot_token_file: "+p+"\n")
		if tc.ok && err != nil {
			t.Errorf("mode %o: unexpected error %v", tc.mode, err)
		}
		if !tc.ok {
			wantErr(t, err, "notify.bot_token_file", "too open")
		}
	}
}

func TestSecretFileProblems(t *testing.T) {
	dir := t.TempDir()
	_, err := parseServer(t, baseServer+"notify:\n  bot_token_file: "+filepath.Join(dir, "missing")+"\n")
	wantErr(t, err, "notify.bot_token_file")
	empty := writeFile(t, dir, "empty", " \n", 0o600)
	_, err = parseServer(t, baseServer+"notify:\n  bot_token_file: "+empty+"\n")
	wantErr(t, err, "empty")
	big := writeFile(t, dir, "big", strings.Repeat("a", maxSecretSize+1), 0o600)
	_, err = parseServer(t, baseServer+"notify:\n  bot_token_file: "+big+"\n")
	wantErr(t, err, "larger than")
	_, err = parseServer(t, baseServer+"notify:\n  bot_token_file: "+dir+"\n")
	wantErr(t, err, "not a regular file")
}

func TestTLSKeyAndKEKPermsCheckedWhenPresent(t *testing.T) {
	dir := t.TempDir()
	key := writeFile(t, dir, "k.key", "x", 0o644)
	_, err := parseServer(t, "listen:\n  proxy: \"127.0.0.1:8080\"\n  metrics: \"127.0.0.1:9090\"\ntls:\n  mode: files\n  cert_file: c.crt\n  key_file: "+key+"\n")
	wantErr(t, err, "tls.key_file", "too open")
	kek := writeFile(t, dir, "kek", "x", 0o644)
	_, err = parseServer(t, baseServer+"pki:\n  kek_file: "+kek+"\n")
	wantErr(t, err, "pki.kek_file", "too open")
	_, err = parseServer(t, baseServer+"agent_tls:\n  ca_file: a\n  cert_file: b\n  key_file: "+key+"\n")
	wantErr(t, err, "agent_tls.key_file")
	// отсутствующие файлы — не ошибка конфигурации
	mustServer(t, baseServer+"pki:\n  kek_file: "+filepath.Join(dir, "nokek")+"\n")
	// и для агента
	_, err = parseAgent(t, strings.Replace(baseAgent, "key_file: a.key", "key_file: "+key, 1))
	wantErr(t, err, "tls.key_file", "too open")
	bearer := writeFile(t, dir, "b", "tok", 0o644)
	_, err = parseAgent(t, baseAgent+"metrics:\n  bearer_file: "+bearer+"\n")
	wantErr(t, err, "metrics.bearer_file")
	ok := writeFile(t, dir, "b2", "tok", 0o600)
	a, err := parseAgent(t, baseAgent+"metrics:\n  bearer_file: "+ok+"\n")
	if err != nil || a.Metrics.Bearer.Reveal() != "tok" {
		t.Errorf("agent bearer: %v %v", a, err)
	}
}

func TestAccessKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeFile(t, dir, "key", "tgp_devkey_local_only\n", 0o600)
	c := mustServer(t, baseServer+"access_rules:\n  - name: k\n    key_file: "+keyPath+"\n")
	sum := sha256.Sum256([]byte("tgp_devkey_local_only"))
	if hex.EncodeToString(c.AccessRules[0].KeyHash) != hex.EncodeToString(sum[:]) {
		t.Errorf("hash = %x", c.AccessRules[0].KeyHash)
	}

	short := writeFile(t, dir, "short", "abc", 0o600)
	_, err := parseServer(t, baseServer+"access_rules:\n  - name: k\n    key_file: "+short+"\n")
	wantErr(t, err, "access_rules[0].key_file", "shorter")
	open := writeFile(t, dir, "open", "tgp_devkey_local_only", 0o644)
	_, err = parseServer(t, baseServer+"access_rules:\n  - name: k\n    key_file: "+open+"\n")
	wantErr(t, err, "access_rules[0].key_file", "too open")
}

func TestKeySHA256Resolved(t *testing.T) {
	h := "5d920d4d62626d92a41b29c61d704f31857190681e0f521e08d22ce671082be7"
	c := mustServer(t, baseServer+"access_rules:\n  - name: k\n    key_sha256: "+h+"\n")
	if hex.EncodeToString(c.AccessRules[0].KeyHash) != h {
		t.Errorf("KeyHash = %x", c.AccessRules[0].KeyHash)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "s.yaml", baseServer, 0o644)
	c, err := LoadServer(p)
	if err != nil || c.Listen.Proxy != "127.0.0.1:8080" {
		t.Fatalf("LoadServer: %v %v", c, err)
	}
	a := writeFile(t, dir, "a.yaml", baseAgent, 0o644)
	if _, err := LoadAgent(a); err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	t.Setenv("TGPROXY_ROUTER__BUDGET", "7s")
	c, err = LoadServer(p)
	if err != nil || c.Router.Budget != 7*time.Second {
		t.Errorf("env via os.Environ: %v %v", c, err)
	}
	_, err = LoadServer(filepath.Join(dir, "nope.yaml"))
	wantErr(t, err, "config:")
}

func TestOverrideTelegramAPIURL(t *testing.T) {
	a := DefaultAgent()
	if err := a.OverrideTelegramAPIURL("https://127.0.0.1:4443"); err != nil || a.TelegramAPIURL() != "https://127.0.0.1:4443" {
		t.Fatalf("override: %v %q", err, a.TelegramAPIURL())
	}
	for _, bad := range []string{"http://127.0.0.1:1", "ftp://x", "://", "https://"} {
		if err := a.OverrideTelegramAPIURL(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	var zero AgentConfig
	if zero.TelegramAPIURL() != DefaultTelegramAPIURL {
		t.Error("zero value must fall back to the default upstream")
	}
	zero.normalize()
	if zero.telegramAPIURL != DefaultTelegramAPIURL {
		t.Error("normalize must set upstream")
	}
}

func TestSecretMasks(t *testing.T) {
	s := Secret("topsecret")
	b, _ := s.MarshalText()
	if s.String() != "***" || s.GoString() != `"***"` || string(b) != "***" || s.LogValue().String() != "***" {
		t.Error("secret not masked")
	}
}

func TestDevConfigsAreValid(t *testing.T) {
	root := filepath.Join("..", "..", "dev")
	if _, err := LoadServer(filepath.Join(root, "server.yaml")); err != nil {
		t.Errorf("dev/server.yaml: %v", err)
	}
	if _, err := LoadAgent(filepath.Join(root, "agent.yaml")); err != nil {
		t.Errorf("dev/agent.yaml: %v", err)
	}
	c, _ := LoadServer(filepath.Join(root, "server.yaml"))
	sum := sha256.Sum256([]byte("tgp_devkey_local_only"))
	if c == nil || len(c.AccessRules) != 2 || hex.EncodeToString(c.AccessRules[1].KeyHash) != hex.EncodeToString(sum[:]) {
		t.Errorf("dev-key rule hash mismatch: %+v", c)
	}
}
