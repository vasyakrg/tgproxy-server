// Package tlsin — TLS на входе сервера (docs/architecture.md §3.1): режимы
// files (горячая перезагрузка PEM), acme (autocert) и off (TLS снаружи).
package tlsin

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

// ExpiryWarn — порог события EventExpiring (docs/architecture.md §9).
const ExpiryWarn = 14 * 24 * time.Hour

// EventType — тип события провайдера.
type EventType string

// Типы событий; соответствуют алертам notify.
const (
	EventReloaded EventType = "cert_reloaded" // новый сертификат принят
	EventInvalid  EventType = "cert_invalid"  // новый сертификат отвергнут, остаётся старый
	EventExpiring EventType = "cert_expiring" // до NotAfter меньше ExpiryWarn
)

// Event — событие провайдера. NotAfter — срок действующего сертификата (может
// быть нулевым, если сертификата нет); Err задан для EventInvalid.
type Event struct {
	Type     EventType
	NotAfter time.Time
	Err      error
}

// CertInfo — описание текущего сертификата входа для UI («Система → Сертификат входа»).
type CertInfo struct {
	Mode       string
	Subject    string
	SANs       []string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	LastReload time.Time // последняя успешная загрузка/продление
	LastError  string    // последняя ошибка перезагрузки, пусто — всё хорошо
}

// Provider — источник сертификата входа.
type Provider interface {
	// GetCertificate — для tls.Config.GetCertificate.
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Info — снимок состояния сертификата.
	Info() CertInfo
	// TLSConfig — готовый конфиг для http.Server; nil для mode=off.
	TLSConfig() *tls.Config
	// Run — фоновая работа (наблюдение за файлами, продление) до отмены ctx.
	Run(ctx context.Context) error
	// Reload принудительно перечитывает сертификат (SIGHUP / кнопка UI);
	// для acme и off — no-op.
	Reload() error
}

// HTTP01 реализуют провайдеры, умеющие отвечать на HTTP-01 (mode=acme).
type HTTP01 interface {
	// HTTPHandler обслуживает /.well-known/acme-challenge/; прочие запросы —
	// fallback (nil — редирект на https).
	HTTPHandler(fallback http.Handler) http.Handler
}

type options struct {
	logger       *slog.Logger
	events       func(Event)
	metrics      func(time.Time)
	client       *http.Client
	clock        func() time.Time
	trusted      []netip.Prefix
	proxyListen  string
	pollInterval time.Duration
	debounce     time.Duration
}

// Option настраивает провайдера.
type Option func(*options)

// WithLogger задаёт логгер (по умолчанию slog.Default).
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.logger = l } }

// WithEvents подписывает на события (вызывается синхронно, не блокируйте).
func WithEvents(fn func(Event)) Option { return func(o *options) { o.events = fn } }

// WithMetrics задаёт приёмник NotAfter действующего сертификата.
func WithMetrics(fn func(notAfter time.Time)) Option { return func(o *options) { o.metrics = fn } }

// WithHTTPClient задаёт HTTP-клиент ACME (например, через /_agent/egress).
func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.client = c } }

// WithClock подменяет время (тесты).
func WithClock(fn func() time.Time) Option { return func(o *options) { o.clock = fn } }

// WithOffGuard передаёт контекст проверки mode=off: trusted_proxies и адрес
// листенера прокси (правило config.CheckTLSOff). Без него mode=off отвергается.
func WithOffGuard(trusted []netip.Prefix, proxyListen string) Option {
	return func(o *options) { o.trusted, o.proxyListen = trusted, proxyListen }
}

// New создаёт провайдера по cfg.Mode. Для files сертификат загружается и
// валидируется немедленно (ошибка — отказ старта).
func New(cfg config.IngressTLS, opts ...Option) (Provider, error) {
	o := options{
		logger: slog.Default(), clock: time.Now,
		pollInterval: defaultPollInterval, debounce: defaultDebounce,
	}
	for _, fn := range opts {
		fn(&o)
	}
	switch cfg.Mode {
	case config.TLSModeOff, "":
		return newOff(&o)
	case config.TLSModeFiles:
		return newFiles(cfg, &o)
	case config.TLSModeACME:
		return newACME(cfg, &o)
	default:
		return nil, fmt.Errorf("tlsin: unknown tls.mode %q", cfg.Mode)
	}
}

func (o *options) emit(ev Event) {
	if o.events != nil {
		o.events(ev)
	}
}

func (o *options) setNotAfter(t time.Time) {
	if o.metrics != nil && !t.IsZero() {
		o.metrics(t)
	}
}
