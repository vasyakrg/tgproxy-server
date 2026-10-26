package proxy

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
