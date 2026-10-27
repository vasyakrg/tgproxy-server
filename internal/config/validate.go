package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	ruleRe    = regexp.MustCompile(`^[\p{L}\p{N} ._-]{1,64}$`)
	repoRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	versionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+].+)?$`)
)

// validator копит ошибки с путями полей.
type validator struct{ errs []error }

func (v *validator) add(path, format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...)))
}

func (v *validator) err() error { return errors.Join(v.errs...) }

func (v *validator) positive(path string, d time.Duration) {
	if d <= 0 {
		v.add(path, "must be positive, got %s", d)
	}
}

func (v *validator) addr(path, addr string) {
	if addr == "" {
		v.add(path, "required (host:port)")
		return
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		v.add(path, "invalid address %q: %v", addr, err)
		return
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		v.add(path, "invalid port in %q", addr)
	}
}

func (v *validator) logging(l LoggingConfig) {
	switch l.Level {
	case "debug", "info", "warn", "error":
	default:
		v.add("logging.level", "must be debug|info|warn|error, got %q", l.Level)
	}
	switch l.Format {
	case "json", "text":
	default:
		v.add("logging.format", "must be json|text, got %q", l.Format)
	}
}

// httpsURL проверяет https://host[:port] без userinfo, query и пути.
func (v *validator) httpsURL(path, raw string) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		v.add(path, "want https://host[:port], got %q", raw)
	}
}

// CheckTLSOff проверяет допустимость tls.mode=off: возвращает описание
// проблемы или "". Единый источник правила для validate и tlsin.
func CheckTLSOff(trusted []netip.Prefix, proxyListen string) string {
	if len(trusted) == 0 && !isLoopbackListen(proxyListen) {
		return fmt.Sprintf("off requires trusted_proxies unless listen.proxy is loopback (got %q): "+
			"terminate TLS on a reverse proxy and list it in trusted_proxies, or use files|acme", proxyListen)
	}
	return ""
}

// isLoopbackListen: слушает ли адрес только loopback. Пустой host (":8080") —
// все интерфейсы, то есть не loopback.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// ValidateServer проверяет серверную конфигурацию и возвращает агрегированную
// ошибку (errors.Join) с путями полей. Не выполняет IO.
func ValidateServer(c *ServerConfig) error {
	v := &validator{}

	v.addr("listen.proxy", c.Listen.Proxy)
	v.addr("listen.admin", c.Listen.Admin)
	v.addr("listen.metrics", c.Listen.Metrics)
	v.addr("listen.agent_gateway", c.Listen.AgentGateway)

	v.publicBaseURL(c.Server.PublicBaseURL)
	v.agentGatewayURL(c.Server.AgentGatewayURL)
	v.serverTLS(c)

	for i, p := range c.TrustedProxies {
		path := fmt.Sprintf("trusted_proxies[%d]", i)
		switch {
		case !p.IsValid():
			v.add(path, "invalid prefix")
		case p.Bits() == 0:
			// доверять X-Forwarded-For от всего интернета = подделка IP для правил доступа
			v.add(path, "%s trusts every address; list real reverse-proxy addresses", p)
		case p != p.Masked():
			v.add(path, "%s has host bits set, want %s", p, p.Masked())
		}
	}

	if c.PKI.Dir == "" && len(c.Agents) > 0 && !c.AgentTLS.complete() {
		v.add("agent_tls", "agents are configured: set agent_tls.{ca_file,cert_file,key_file} or pki.dir")
	}
	if c.AgentTLS.any() && !c.AgentTLS.complete() {
		v.add("agent_tls", "ca_file, cert_file and key_file must be set together")
	}
	if c.Auth.UsersFile == "" {
		v.add("auth.users_file", "required")
	}

	v.agents(c)
	v.accessRules(c.AccessRules)

	switch c.WebhookPolicy {
	case WebhookDeny, WebhookPassthrough:
	default:
		v.add("webhook_policy", "must be deny|passthrough, got %q", c.WebhookPolicy)
	}

	v.router(c.Router)
	v.buffer(c.Buffer)
	v.store(c.Store)
	v.update(c.Update)
	v.notify(c.Notify)
	v.ban(c.Ban)
	v.mtproto(c)

	if c.Metrics.BearerFile == "" && !isLoopbackListen(c.Listen.Metrics) {
		v.add("metrics.bearer_file", "required when listen.metrics (%q) is not loopback", c.Listen.Metrics)
	}
	v.logging(c.Logging)
	return v.err()
}

func (t TLSFiles) any() bool {
	return t.CertFile != "" || t.KeyFile != "" || t.CAFile != ""
}

func (t TLSFiles) complete() bool {
	return t.CertFile != "" && t.KeyFile != "" && t.CAFile != ""
}

func (v *validator) serverTLS(c *ServerConfig) {
	t := c.TLS
	switch t.Mode {
	case TLSModeOff:
		// Решение: TLS на входе выключен. Без trusted_proxies это допустимо только
		// если прокси слушает loopback (локальная разработка / сайдкар): тогда
		// plaintext никуда не уходит и X-Forwarded-For игнорируется. Иначе
		// (":8080", 0.0.0.0, внешний IP) — открытый plaintext-вход без TLS и без
		// объявленного терминатора TLS; это ошибка, а не предупреждение: «мягкие»
		// предупреждения в конфиге systemd-сервиса никто не читает.
		if msg := CheckTLSOff(c.TrustedProxies, c.Listen.Proxy); msg != "" {
			v.add("tls.mode", "%s", msg)
		}
	case TLSModeFiles:
		if t.CertFile == "" {
			v.add("tls.cert_file", "required for tls.mode=files")
		}
		if t.KeyFile == "" {
			v.add("tls.key_file", "required for tls.mode=files")
		}
	case TLSModeACME:
		if len(t.Domains) == 0 {
			v.add("tls.domains", "required for tls.mode=acme")
		}
		for i, d := range t.Domains {
			if d == "" || strings.ContainsAny(d, "* /:") {
				v.add(fmt.Sprintf("tls.domains[%d]", i), "invalid domain %q (wildcards are not supported)", d)
			}
		}
		if t.CacheDir == "" {
			v.add("tls.cache_dir", "required for tls.mode=acme")
		}
		if e := t.ACME.Email; e != "" && !strings.Contains(e, "@") {
			v.add("tls.acme.email", "invalid email %q", e)
		}
		if l := t.ACME.HTTP01Listen; l != "" {
			if _, _, err := net.SplitHostPort(l); err != nil {
				v.add("tls.acme.http01_listen", "want host:port, got %q", l)
			}
		}
		if u := t.ACME.DirectoryURL; u != "" {
			if pu, err := url.Parse(u); err != nil || pu.Scheme != "https" || pu.Host == "" {
				v.add("tls.acme.directory_url", "want https URL, got %q", u)
			}
		}
	default:
		v.add("tls.mode", "must be off|files|acme, got %q", t.Mode)
	}
}

func (v *validator) agents(c *ServerConfig) {
	seen := map[string]bool{}
	for i, a := range c.Agents {
		p := fmt.Sprintf("agents[%d]", i)
		switch {
		case !idRe.MatchString(a.ID):
			v.add(p+".id", "invalid id %q (want [a-z0-9-], up to 63 chars)", a.ID)
		case seen[a.ID]:
			v.add(p+".id", "duplicate id %q", a.ID)
		}
		seen[a.ID] = true
		if a.Weight < 0 {
			v.add(p+".weight", "must not be negative, got %d", a.Weight)
		}
		switch a.Mode {
		case AgentModeDial:
			if a.URL == "" {
				v.add(p+".url", "required for mode=dial")
			} else {
				v.httpsURL(p+".url", a.URL)
			}
		case AgentModeReverse:
			if a.URL != "" {
				v.add(p+".url", "must be empty for mode=reverse (the agent connects to agent_gateway itself)")
			}
		default:
			v.add(p+".mode", "must be dial|reverse, got %q", a.Mode)
		}
	}
}

func (v *validator) accessRules(rules []AccessRule) {
	seen := map[string]bool{}
	for i, r := range rules {
		p := fmt.Sprintf("access_rules[%d]", i)
		for _, is := range CheckAccessRule(r) {
			v.add(p+is.path(), "%s", is.Msg)
		}
		if ValidRuleName(r.Name) && seen[r.Name] {
			v.add(p+".name", "duplicate name %q", r.Name)
		}
		seen[r.Name] = true
	}
}

func (v *validator) router(r RouterConfig) {
	if r.MaxAttempts < 1 || r.MaxAttempts > 10 {
		v.add("router.max_attempts", "must be in 1..10, got %d", r.MaxAttempts)
	}
	v.positive("router.budget", r.Budget)
	v.positive("router.long_poll_extra", r.LongPollExtra)
	v.positive("router.max_long_poll", r.MaxLongPoll)
	v.positive("router.no_agent_wait", r.NoAgentWait)
}

func (v *validator) buffer(b BufferConfig) {
	if b.RAMMax <= 0 {
		v.add("buffer.ram_max", "must be positive, got %d", b.RAMMax)
	}
	if b.DiskMax < b.RAMMax {
		v.add("buffer.disk_max", "must be >= buffer.ram_max, got %d", b.DiskMax)
	}
	if b.BodyMax <= 0 {
		v.add("buffer.body_max", "must be positive, got %d", b.BodyMax)
	}
}

func (v *validator) store(s StoreConfig) {
	if s.SQLitePath == "" {
		v.add("store.sqlite_path", "required (SQLite stores agents, certificates and history in every mode)")
	}
	switch s.Driver {
	case StoreSQLite:
	case StoreRedis:
		if s.RedisURL == "" {
			v.add("store.redis_url", "required for store.driver=redis")
		}
	default:
		v.add("store.driver", "must be sqlite|redis, got %q", s.Driver)
	}
	if s.RedisURL != "" {
		if u, err := url.Parse(s.RedisURL); err != nil || u.Scheme != "rediss" || u.Host == "" {
			// Redis без TLS = токены сессий и rate-limit по открытому каналу.
			v.add("store.redis_url", "must be rediss://host:port/db (TLS is mandatory)")
		}
	}
}

func (v *validator) update(u UpdateConfig) {
	if u.HTTPProxy != "" {
		if pu, err := url.Parse(u.HTTPProxy); err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			v.add("update.http_proxy", "want http(s)://host:port, got %q", u.HTTPProxy)
		}
	}
	if u.MinVersion != "" && !versionRe.MatchString(u.MinVersion) {
		v.add("update.min_version", "want semver (1.2.3), got %q", u.MinVersion)
	}
	if !u.Enabled {
		return
	}
	if !repoRe.MatchString(u.Repo) {
		v.add("update.repo", "want owner/name, got %q", u.Repo)
	}
	v.positive("update.check_interval", u.CheckInterval)
	switch u.Source {
	case UpdateSourceGitHub, UpdateSourceUpload:
	case UpdateSourceProxy:
		if u.HTTPProxy == "" {
			v.add("update.http_proxy", "required when update.source=proxy")
		}
	case UpdateSourceAgent:
		if !idRe.MatchString(u.ViaAgent) {
			v.add("update.via_agent", "required agent id when update.source=agent, got %q", u.ViaAgent)
		}
	default:
		v.add("update.source", "must be github|proxy|agent|upload, got %q", u.Source)
	}
	if len(u.PubKeys) > 2 {
		v.add("update.pubkeys", "at most 2 keys (primary + rotation), got %d", len(u.PubKeys))
	}
	for i, k := range u.PubKeys {
		if _, err := verify.ParsePublicKey(k); err != nil {
			v.add(fmt.Sprintf("update.pubkeys[%d]", i), "invalid minisign public key: %v", err)
		}
	}
	if u.StagingDir == "" {
		v.add("update.staging_dir", "required when update.enabled")
	}
}

func (v *validator) notify(n NotifyConfig) {
	v.positive("notify.repeat_interval", n.RepeatInterval)
	v.positive("notify.cert_expiry_warn", n.CertExpiryWarn)
	v.positive("notify.delivery_timeout", n.DeliveryTimeout)
	if n.MaxPerMinute < 1 {
		v.add("notify.max_per_minute", "must be positive, got %d", n.MaxPerMinute)
	}
}

// Границы настроек автобана.
const (
	maxBanThreshold  = 100000
	maxBanTracked    = 1_000_000
	maxBanDuration   = 5 * 365 * 24 * time.Hour
	maxBanEscalation = 10
)

func (v *validator) ban(b BanConfig) {
	if !b.Enabled {
		return
	}
	if b.Threshold < 1 || b.Threshold > maxBanThreshold {
		v.add("ban.threshold", "must be 1..%d, got %d", maxBanThreshold, b.Threshold)
	}
	v.positive("ban.window", b.Window)
	v.positive("ban.duration", b.Duration)
	v.positive("ban.reset_after", b.ResetAfter)
	if b.Duration > maxBanDuration {
		v.add("ban.duration", "too long, got %s", b.Duration)
	}
	if len(b.Escalation) > maxBanEscalation {
		v.add("ban.escalation", "at most %d steps, got %d", maxBanEscalation, len(b.Escalation))
	}
	for i, d := range b.Escalation {
		path := fmt.Sprintf("ban.escalation[%d]", i)
		v.positive(path, d)
		if d > maxBanDuration {
			v.add(path, "too long, got %s", d)
		}
	}
	if b.MaxTracked < 100 || b.MaxTracked > maxBanTracked {
		v.add("ban.max_tracked", "must be 100..%d, got %d", maxBanTracked, b.MaxTracked)
	}
}

// ValidateAgent проверяет конфигурацию агента; агрегированная ошибка с путями
// полей. Не выполняет IO.
func ValidateAgent(c *AgentConfig) error {
	v := &validator{}

	v.addr("listen.metrics", c.Listen.Metrics)
	// listen.api нужен только режимам, где агент принимает входящие (dial/both);
	// reverse его не использует: пустой допустим, заданный проверяется.
	switch {
	case c.Listen.API != "":
		v.addr("listen.api", c.Listen.API)
	case c.Mode != AgentModeReverse:
		v.add("listen.api", "required for mode=%s (host:port: агент принимает входящие от сервера)", c.Mode)
	}

	switch c.Mode {
	case AgentModeDial:
		if c.AllowedClientSAN == "" {
			v.add("allowed_client_san", "required for mode=dial (SAN of the server client certificate)")
		}
	case AgentModeReverse:
		if c.ServerURL == "" {
			v.add("server_url", "required for mode=reverse")
		} else {
			v.httpsURL("server_url", c.ServerURL)
		}
	case AgentModeBoth:
		if c.AllowedClientSAN == "" {
			v.add("allowed_client_san", "required for mode=both (SAN of the server client certificate)")
		}
		if c.ServerURL == "" {
			v.add("server_url", "required for mode=both")
		} else {
			v.httpsURL("server_url", c.ServerURL)
		}
	default:
		v.add("mode", "must be dial|reverse|both, got %q", c.Mode)
	}

	if c.TLS.CertFile == "" {
		v.add("tls.cert_file", "required")
	}
	if c.TLS.KeyFile == "" {
		v.add("tls.key_file", "required")
	}
	if c.TLS.CAFile == "" {
		v.add("tls.ca_file", "required")
	}
	if c.DataDir == "" {
		v.add("data_dir", "required")
	}
	v.agentMTProto(c.MTProto)
	if c.Metrics.BearerFile == "" && !isLoopbackListen(c.Listen.Metrics) {
		v.add("metrics.bearer_file", "required when listen.metrics (%q) is not loopback", c.Listen.Metrics)
	}
	v.logging(c.Logging)
	return v.err()
}

// publicBaseURL: https://host[:port] или http://<loopback>[:port]; без пути, query и userinfo.
func (v *validator) publicBaseURL(raw string) {
	if raw == "" {
		return
	}
	const path = "server.public_base_url"
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		v.add(path, "invalid URL %q", raw)
		return
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		v.add(path, "must be scheme://host[:port] without path, query or credentials")
		return
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			v.add(path, "http is allowed only for loopback hosts, use https")
		}
	default:
		v.add(path, "scheme must be https (or http on loopback), got %q", u.Scheme)
	}
}

// agentGatewayURL: https://host[:port] без пути, query и userinfo.
func (v *validator) agentGatewayURL(raw string) {
	if raw == "" {
		return
	}
	const path = "server.agent_gateway_url"
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		v.add(path, "want https://host[:port] without path, query or credentials, got %q", raw)
	}
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}
