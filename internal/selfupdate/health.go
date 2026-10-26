package selfupdate

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// HealthURL строит URL /healthz по адресу admin-листенера сервера; пустой или
// «любой» хост заменяется на loopback.
func HealthURL(adminListen string, tlsOff bool) (string, error) {
	host, port, err := net.SplitHostPort(adminListen)
	if err != nil {
		return "", fmt.Errorf("listen.admin %q: %w", adminListen, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "https"
	if tlsOff {
		scheme = "http"
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/healthz", nil
}

// ProbeConfig — источники URL для проверки здоровья.
type ProbeConfig struct {
	// ServerURL — URL /healthz сервера (ленивый: на хосте агента server.yaml нет).
	ServerURL func() (string, error)
	// AgentURL — URL /healthz агента (listen.metrics на loopback); nil или "" — только systemctl is-active.
	AgentURL func() (string, error)
}

// NewProbe — Probe только с серверным URL (см. NewProbeConfig).
func NewProbe(urlFn func() (string, error), ex Executor) func(context.Context, string) error {
	return NewProbeConfig(ProbeConfig{ServerURL: urlFn}, ex)
}

// NewProbeConfig возвращает Probe: server — GET /healthz (200); agent — `systemctl is-active`
// и, если задан AgentURL, GET /healthz агента (200).
// TLS-сертификат листенера не проверяется: запрос идёт на loopback своего же хоста
// и несёт только факт «процесс отвечает».
func NewProbeConfig(pc ProbeConfig, ex Executor) func(context.Context, string) error {
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402 -- loopback health
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	get := func(ctx context.Context, urlFn func() (string, error)) error {
		url, err := urlFn()
		if err != nil {
			return err
		}
		if url == "" {
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("healthz: статус %d", resp.StatusCode)
		}
		return nil
	}
	return func(ctx context.Context, component string) error {
		if component == ComponentAgent {
			if err := ex.Run(ctx, "systemctl", "is-active", "--quiet", "tgproxy-agent"); err != nil {
				return err
			}
			if pc.AgentURL == nil {
				return nil
			}
			return get(ctx, pc.AgentURL)
		}
		if pc.ServerURL == nil {
			return fmt.Errorf("healthz сервера не настроен")
		}
		return get(ctx, pc.ServerURL)
	}
}

// AgentHealthURL строит URL /healthz агента по listen.metrics; не-loopback адрес или пустое
// значение дают "" (проверка пропускается: наружу без bearer не ходим).
func AgentHealthURL(metricsListen string) string {
	host, port, err := net.SplitHostPort(metricsListen)
	if err != nil || port == "" {
		return ""
	}
	if host == "" {
		host = "127.0.0.1"
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		if ip != nil && ip.IsUnspecified() {
			host = "127.0.0.1"
		} else {
			return ""
		}
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}
