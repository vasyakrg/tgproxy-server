package proxy

import (
	"context"
	"net/netip"

	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Banner — бан-лист и автобан (реализует *ban.Manager). Banned засчитывает попадание,
// Record — отказ доступа клиенту.
type Banner interface {
	Banned(a netip.Addr) bool
	Record(a netip.Addr, reason access.Reason)
}

// ErrorSink — журнал ошибок (реализует *history.ErrorLog).
type ErrorSink interface {
	Record(ctx context.Context, e store.ErrorEvent)
}

// Geo определяет страну по IP (реализует *geoip.DB; nil-база безопасна).
type Geo interface {
	Lookup(a netip.Addr) string
}

// Recorder — приёмник метрик прокси (реализует *metrics.Server).
type Recorder interface {
	RequestDone(rule, method string, code int)
	WebhookBlocked()
	Telegram429(rule string)
}

// BotObserver — приёмник статистики по ботам (реализует *metrics.TopBots).
type BotObserver interface {
	Observe(botID int64, rule string, code int)
}

type noopRecorder struct{}

func (noopRecorder) RequestDone(string, string, int) {}
func (noopRecorder) WebhookBlocked()                 {}
func (noopRecorder) Telegram429(string)              {}

// Option настраивает Handler.
type Option func(*Handler)

// WithRecorder подключает метрики Prometheus.
func WithRecorder(r Recorder) Option {
	return func(h *Handler) {
		if r != nil {
			h.rec = r
		}
	}
}

// WithBots подключает top-K ботов (bot_id только в памяти, не в метках).
func WithBots(b BotObserver) Option { return func(h *Handler) { h.bots = b } }

// observe учитывает завершённый запрос, прошедший проверку доступа.
// Служебные (internal) запросы не учитываются.
func (h *Handler) observe(internal bool, rule, method string, botID int64, code int) {
	if internal || rule == "" {
		return
	}
	h.rec.RequestDone(rule, method, code)
	if h.bots != nil {
		h.bots.Observe(botID, rule, code)
	}
}

// WithBans включает проверку бана до правил доступа и учёт отказов для автобана.
func WithBans(b Banner) Option { return func(h *Handler) { h.bans = b } }

// WithDenied подписывает приёмники отказов доступа (метрика, история): reason — access.Reason.
func WithDenied(f ...func(reason string)) Option {
	return func(h *Handler) { h.denied = append(h.denied, f...) }
}

// WithErrorLog пишет отказы доступа в журнал ошибок (фаза access).
func WithErrorLog(s ErrorSink) Option { return func(h *Handler) { h.errs = s } }

// WithGeo добавляет страну клиента в лог отказов.
func WithGeo(g Geo) Option { return func(h *Handler) { h.geo = g } }
