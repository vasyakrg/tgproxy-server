package config

import (
	"strings"
	"testing"
)

func TestServerValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string // пусто = валидно
	}{
		{"base ok", baseServer, nil},
		{"rule without nets and key", baseServer + "access_rules:\n  - name: open\n", []string{"access_rules[0]", "open relay"}},
		{"rule v4 any without key", baseServer + "access_rules:\n  - name: any\n    cidrs: [0.0.0.0/0]\n", []string{"access_rules[0].cidrs[0]", "open relay"}},
		{"rule v6 any without key", baseServer + "access_rules:\n  - name: any\n    cidrs: ['::/0']\n", []string{"access_rules[0].cidrs[0]"}},
		{"rule any with key ok", baseServer + "access_rules:\n  - name: any\n    cidrs: [0.0.0.0/0]\n    key_sha256: " + strings.Repeat("ab", 32) + "\n", nil},
		{"rule key only ok", baseServer + "access_rules:\n  - name: k\n    key_sha256: " + strings.Repeat("AB", 32) + "\n", nil},
		{"rule net only ok", baseServer + "access_rules:\n  - name: n\n    cidrs: [10.0.0.0/8]\n    rps: 50\n", nil},
		{"rule bad hash", baseServer + "access_rules:\n  - name: k\n    key_sha256: zz\n", []string{"access_rules[0].key_sha256"}},
		{"rule both key forms", baseServer + "access_rules:\n  - name: k\n    key_sha256: " + strings.Repeat("ab", 32) + "\n    key_file: /x\n", []string{"mutually exclusive"}},
		{"rule host bits", baseServer + "access_rules:\n  - name: n\n    cidrs: [10.0.0.1/8]\n", []string{"host bits"}},
		{"rule negative rps", baseServer + "access_rules:\n  - name: n\n    cidrs: [10.0.0.0/8]\n    rps: -1\n", []string{"access_rules[0].rps"}},
		{"rule bad name", baseServer + "access_rules:\n  - name: 'a b'\n    cidrs: [10.0.0.0/8]\n", []string{"access_rules[0].name"}},
		{"rule dup name", baseServer + "access_rules:\n  - name: a\n    cidrs: [10.0.0.0/8]\n  - name: a\n    cidrs: [10.0.0.0/8]\n", []string{"access_rules[1].name", "duplicate"}},

		{"tls off public proxy no trusted", "listen:\n  proxy: ':8080'\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: 'off'\n", []string{"tls.mode", "trusted_proxies"}},
		{"tls off 0.0.0.0 no trusted", "listen:\n  proxy: '0.0.0.0:8080'\n  metrics: '127.0.0.1:9090'\n", []string{"tls.mode"}},
		{"tls off public with trusted ok", "listen:\n  proxy: ':8080'\n  metrics: '127.0.0.1:9090'\ntrusted_proxies: [10.0.0.0/8]\n", nil},
		{"tls off localhost ok", "listen:\n  proxy: 'localhost:8080'\n  metrics: '127.0.0.1:9090'\n", nil},
		{"tls off ipv6 loopback ok", "listen:\n  proxy: '[::1]:8080'\n  metrics: '127.0.0.1:9090'\n", nil},
		{"trusted everything", baseServer + "trusted_proxies: [0.0.0.0/0]\n", []string{"trusted_proxies[0]", "trusts every address"}},
		{"trusted host bits", baseServer + "trusted_proxies: [10.0.0.1/8]\n", []string{"trusted_proxies[0]", "host bits"}},
		{"tls bad mode", "tls:\n  mode: tls13\n", []string{"tls.mode", "off|files|acme"}},
		{"tls files missing", "listen:\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: files\n", []string{"tls.cert_file", "tls.key_file"}},
		{"tls files ok", "listen:\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: files\n  cert_file: c\n  key_file: k\n", nil},
		{"acme missing domains", "listen:\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: acme\n", []string{"tls.domains"}},
		{"acme ok", "listen:\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: acme\n  domains: [tg.example.com]\n  acme:\n    email: a@example.com\n    directory_url: https://acme.example/dir\n", nil},
		{"acme wildcard", "listen:\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: acme\n  domains: ['*.example.com']\n", []string{"tls.domains[0]"}},
		{"acme bad email", "listen:\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: acme\n  domains: [a.example]\n  acme:\n    email: nope\n", []string{"tls.acme.email"}},
		{"acme http directory", "listen:\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: acme\n  domains: [a.example]\n  acme:\n    directory_url: http://x\n", []string{"tls.acme.directory_url"}},
		{"acme no cache", "listen:\n  metrics: '127.0.0.1:9090'\ntls:\n  mode: acme\n  domains: [a.example]\n  cache_dir: ''\n", []string{"tls.cache_dir"}},

		{"redis plain", baseServer + "store:\n  driver: redis\n  redis_url: redis://127.0.0.1:6379/0\n", []string{"store.redis_url", "rediss://"}},
		{"redis url with sqlite driver still checked", baseServer + "store:\n  redis_url: redis://h:1\n", []string{"store.redis_url"}},
		{"redis missing url", baseServer + "store:\n  driver: redis\n", []string{"store.redis_url", "required"}},
		{"redis tls ok", baseServer + "store:\n  driver: redis\n  redis_url: rediss://u@127.0.0.1:6380/0\n", nil},
		{"store bad driver", baseServer + "store:\n  driver: postgres\n", []string{"store.driver"}},
		{"store no sqlite path", baseServer + "store:\n  sqlite_path: ''\n", []string{"store.sqlite_path"}},

		{"webhook bad", baseServer + "webhook_policy: allow\n", []string{"webhook_policy", "deny|passthrough"}},
		{"webhook passthrough ok", baseServer + "webhook_policy: passthrough\n", nil},

		{"router negative budget", baseServer + "router:\n  budget: -1s\n", []string{"router.budget"}},
		{"router zero long poll", baseServer + "router:\n  max_long_poll: 0s\n", []string{"router.max_long_poll"}},
		{"router zero extra", baseServer + "router:\n  long_poll_extra: 0s\n", []string{"router.long_poll_extra"}},
		{"router neg no agent wait", baseServer + "router:\n  no_agent_wait: -5s\n", []string{"router.no_agent_wait"}},
		{"router attempts zero", baseServer + "router:\n  max_attempts: 0\n", []string{"router.max_attempts"}},
		{"router attempts huge", baseServer + "router:\n  max_attempts: 11\n", []string{"router.max_attempts"}},

		{"buffer bad", baseServer + "buffer:\n  ram_max: 0\n  disk_max: -1\n  body_max: 0\n", []string{"buffer.ram_max", "buffer.disk_max", "buffer.body_max"}},
		{"buffer disk < ram", baseServer + "buffer:\n  ram_max: 100\n  disk_max: 10\n", []string{"buffer.disk_max"}},

		{"agent dial ok", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a1\n    url: https://10.0.0.5:8443\n", nil},
		{"agent dial default mode and weight", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a1\n    url: https://10.0.0.5:8443\n", nil},
		{"agent dial no url", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a1\n", []string{"agents[0].url", "mode=dial"}},
		{"agent http url", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a1\n    url: http://10.0.0.5:8443\n", []string{"agents[0].url", "https"}},
		{"agent url with path", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a1\n    url: https://h:1/x\n", []string{"agents[0].url"}},
		{"agent reverse ok", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a1\n    mode: reverse\n", nil},
		{"agent reverse with url", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a1\n    mode: reverse\n    url: https://h:1\n", []string{"agents[0].url", "reverse"}},
		{"agent bad mode", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a1\n    mode: push\n", []string{"agents[0].mode"}},
		{"agent bad id", baseServer + "pki:\n  dir: /p\nagents:\n  - id: 'A B'\n    url: https://h:1\n", []string{"agents[0].id"}},
		{"agent dup id", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a\n    url: https://h:1\n  - id: a\n    url: https://h:2\n", []string{"agents[1].id", "duplicate"}},
		{"agent negative weight", baseServer + "pki:\n  dir: /p\nagents:\n  - id: a\n    url: https://h:1\n    weight: -2\n", []string{"agents[0].weight"}},
		{"agents without any tls material", baseServer + "pki:\n  dir: ''\nagents:\n  - id: a\n    url: https://h:1\n", []string{"agent_tls"}},
		{"agents with agent_tls ok", baseServer + "pki:\n  dir: ''\nagent_tls:\n  ca_file: a\n  cert_file: b\n  key_file: c\nagents:\n  - id: a\n    url: https://h:1\n", nil},
		{"agent_tls partial", baseServer + "agent_tls:\n  ca_file: a\n", []string{"agent_tls", "together"}},

		{"listen bad addr", "listen:\n  proxy: 'nope'\n  metrics: '127.0.0.1:9090'\n", []string{"listen.proxy"}},
		{"listen bad port", "listen:\n  proxy: '127.0.0.1:99999'\n  metrics: '127.0.0.1:9090'\n", []string{"listen.proxy", "port"}},
		{"listen empty", "listen:\n  admin: ''\n", []string{"listen.admin", "required"}},
		{"auth no users", baseServer + "auth:\n  users_file: ''\n", []string{"auth.users_file"}},

		{"metrics public needs bearer", "listen:\n  proxy: '127.0.0.1:8080'\n  metrics: ':9090'\n", []string{"metrics.bearer_file"}},

		{"logging bad", baseServer + "logging:\n  level: loud\n  format: xml\n", []string{"logging.level", "logging.format"}},

		{"update bad", baseServer + "update:\n  repo: nope\n  check_interval: 0s\n  staging_dir: ''\n  http_proxy: ftp://x\n  min_version: abc\n",
			[]string{"update.repo", "update.check_interval", "update.staging_dir", "update.http_proxy", "update.min_version"}},
		{"update disabled skips repo", baseServer + "update:\n  enabled: false\n  repo: ''\n", nil},
		{"update ok", baseServer + "update:\n  http_proxy: http://proxy:3128\n  min_version: v1.2.3\n", nil},
		{"notify bad", baseServer + "notify:\n  repeat_interval: 0s\n  max_per_minute: 0\n  cert_expiry_warn: -1h\n  delivery_timeout: 0s\n",
			[]string{"notify.repeat_interval", "notify.max_per_minute", "notify.cert_expiry_warn", "notify.delivery_timeout"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseServer(t, tc.yaml)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			wantErr(t, err, tc.want...)
			_ = c
		})
	}
}

func TestServerNormalizeAgentDefaults(t *testing.T) {
	c := mustServer(t, baseServer+"pki:\n  dir: /p\nagents:\n  - id: a1\n    url: https://h:1\n")
	if c.Agents[0].Mode != AgentModeDial || c.Agents[0].Weight != 1 {
		t.Errorf("agent defaults: %+v", c.Agents[0])
	}
}

func TestValidateAggregates(t *testing.T) {
	c := DefaultServer()
	c.WebhookPolicy = "x"
	c.Router.Budget = -1
	c.Logging.Level = "x"
	err := ValidateServer(c)
	wantErr(t, err, "webhook_policy", "router.budget", "logging.level")
	if n := strings.Count(err.Error(), "\n"); n < 3 {
		t.Errorf("expected joined multi-line error, got %q", err)
	}
}

func TestAgentValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"ok", baseAgent, nil},
		{"reverse ok", baseAgent + "mode: reverse\nserver_url: https://s.example:8444\n", nil},
		{"reverse no server url", baseAgent + "mode: reverse\n", []string{"server_url", "mode=reverse"}},
		{"reverse http server url", baseAgent + "mode: reverse\nserver_url: http://s:8444\n", []string{"server_url"}},
		{"bad mode", baseAgent + "mode: pull\n", []string{"mode"}},
		{"dial no san", baseAgent + "allowed_client_san: ''\n", []string{"allowed_client_san"}},
		{"no tls", "listen:\n  metrics: '127.0.0.1:9443'\n", []string{"tls.cert_file", "tls.key_file", "tls.ca_file"}},
		{"no data dir", baseAgent + "data_dir: ''\n", []string{"data_dir"}},
		{"bad listen", strings.Replace(baseAgent, "listen:", "listen:\n  api: x", 1), []string{"listen.api"}},
		{"metrics public needs bearer", strings.Replace(baseAgent, "127.0.0.1:9443", ":9443", 1), []string{"metrics.bearer_file"}},
		{"bad logging", baseAgent + "logging:\n  format: yaml\n", []string{"logging.format"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAgent(t, tc.yaml)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			wantErr(t, err, tc.want...)
		})
	}
}
