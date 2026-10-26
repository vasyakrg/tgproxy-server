package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

const (
	pendingScan    = 200
	envelopeLimit  = 64 << 10
	defaultPoll    = 5 * time.Second
	defaultBackoff = 5 * time.Second
	maxBackoff     = 10 * time.Minute
	defaultBatch   = 50
	defaultMaxAge  = 24 * time.Hour
	defaultTimeout = 30 * time.Second
)

// Sender — отправка запроса через пул агентов (*router.Router).
type Sender interface {
	Do(ctx context.Context, req *http.Request, route tgapi.Route) (*http.Response, error)
}

// DeliverOptions — параметры Deliverer.
type DeliverOptions struct {
	Outbox  store.OutboxRepo
	Sender  Sender
	Token   string                      // токен notifier-бота (в логи не попадает)
	Load    func() ([]Recipient, error) // источник получателей; по умолчанию пусто
	Metrics Metrics                     // nil → no-op
	Clock   Clock                       // nil → time.Now
	Logger  *slog.Logger                // nil → slog.Default()
	Poll    time.Duration               // период опроса outbox; 0 → 5с
	Timeout time.Duration               // таймаут одной отправки; 0 → 30с
	Backoff time.Duration               // базовая задержка ретрая; 0 → 5с (удваивается, ≤10м)
	Batch   int                         // сообщений за проход; 0 → 50
	MaxAge  time.Duration               // старше — отбрасывается; 0 → 24ч
}

// Deliverer — фоновая доставка outbox в Telegram.
type Deliverer struct {
	o    DeliverOptions
	log  *slog.Logger
	wake chan struct{}

	mu     sync.Mutex
	rcpts  []Recipient
	loaded bool
	next   map[int64]time.Time // id → не раньше (backoff)
}

// NewDeliverer создаёт Deliverer.
func NewDeliverer(o DeliverOptions) *Deliverer {
	if o.Metrics == nil {
		o.Metrics = noopMetrics{}
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Poll <= 0 {
		o.Poll = defaultPoll
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.Backoff <= 0 {
		o.Backoff = defaultBackoff
	}
	if o.Batch <= 0 {
		o.Batch = defaultBatch
	}
	if o.MaxAge <= 0 {
		o.MaxAge = defaultMaxAge
	}
	if o.Load == nil {
		o.Load = func() ([]Recipient, error) { return nil, nil }
	}
	l := o.Logger
	if l == nil {
		l = slog.Default()
	}
	return &Deliverer{o: o, log: l, wake: make(chan struct{}, 1), next: map[int64]time.Time{}}
}

// Reload перечитывает получателей (по SIGHUP/fsnotify из wiring).
func (d *Deliverer) Reload() error {
	r, err := d.o.Load()
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.rcpts, d.loaded = r, true
	d.mu.Unlock()
	return nil
}

// Wake просит выполнить проход немедленно (например, при agent_up).
func (d *Deliverer) Wake() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run крутит цикл доставки до отмены ctx.
func (d *Deliverer) Run(ctx context.Context) {
	t := time.NewTicker(d.o.Poll)
	defer t.Stop()
	for {
		if _, err := d.DeliverOnce(ctx); err != nil && ctx.Err() == nil {
			d.log.Warn("notify: deliver pass", "err", redact.String(err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.wake:
		}
	}
}

func (d *Deliverer) recipients() ([]Recipient, error) {
	d.mu.Lock()
	loaded, r := d.loaded, d.rcpts
	d.mu.Unlock()
	if loaded {
		return r, nil
	}
	if err := d.Reload(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rcpts, nil
}

// DeliverOnce делает один проход по outbox и возвращает число доставленных сообщений.
func (d *Deliverer) DeliverOnce(ctx context.Context) (int, error) {
	items, err := d.o.Outbox.Pending(ctx, pendingScan)
	if err != nil {
		return 0, fmt.Errorf("notify: pending: %w", err)
	}
	rcpts, rerr := d.recipients()
	now := d.o.Clock()
	sent, handled := 0, 0
	for _, it := range items {
		if handled >= d.o.Batch || ctx.Err() != nil {
			break
		}
		if now.Sub(it.CreatedAt) > d.o.MaxAge {
			d.log.Warn("notify: alert dropped as stale", "type", it.Type, "agent", it.AgentID)
			if err := d.o.Outbox.MarkSent(ctx, it.ID, now); err != nil {
				return sent, fmt.Errorf("notify: mark stale: %w", err)
			}
			continue
		}
		if t, ok := d.nextTry(it.ID); ok && now.Before(t) {
			continue
		}
		handled++
		var res outcome
		switch {
		case rerr != nil:
			res = outcome{err: fmt.Errorf("recipients: %w", rerr)}
		case len(rcpts) == 0:
			res = outcome{err: errors.New("no recipients")}
		default:
			res = d.send(ctx, it, rcpts)
		}
		if res.delivered {
			if err := d.o.Outbox.MarkSent(ctx, it.ID, d.o.Clock()); err != nil {
				return sent, fmt.Errorf("notify: mark sent: %w", err)
			}
			d.forget(it.ID)
			sent++
			continue
		}
		d.o.Metrics.AlertUndeliverable()
		msg := redact.String(res.err.Error())
		if err := d.o.Outbox.RecordAttempt(ctx, it.ID, msg); err != nil {
			return sent, fmt.Errorf("notify: record attempt: %w", err)
		}
		d.schedule(it.ID, now, it.Attempts+1)
		d.log.Warn("notify: delivery failed", "type", it.Type, "agent", it.AgentID, "err", msg)
	}
	return sent, nil
}

func (d *Deliverer) nextTry(id int64) (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.next[id]
	return t, ok
}

func (d *Deliverer) forget(id int64) {
	d.mu.Lock()
	delete(d.next, id)
	d.mu.Unlock()
}

func (d *Deliverer) schedule(id int64, now time.Time, attempts int) {
	delay := d.o.Backoff
	for i := 1; i < attempts && delay < maxBackoff; i++ {
		delay *= 2
	}
	delay = min(delay, maxBackoff)
	d.mu.Lock()
	d.next[id] = now.Add(delay)
	d.mu.Unlock()
}

// outcome: delivered — хотя бы одному получателю ушло, либо все отказы постоянные
// (повтор бессмысленен); иначе err — причина для RecordAttempt.
type outcome struct {
	delivered bool
	err       error
}

func (d *Deliverer) send(ctx context.Context, it store.OutboxItem, rcpts []Recipient) outcome {
	var ok int
	var transient, permanent error
	for _, r := range rcpts {
		perm, err := d.sendOne(ctx, r.TelegramID, it.Text)
		switch {
		case err == nil:
			ok++
		case perm:
			permanent = err
			d.log.Warn("notify: recipient rejected", "user", r.User, "err", redact.String(err.Error()))
		default:
			transient = err
		}
	}
	switch {
	case ok > 0:
		if transient != nil {
			d.log.Warn("notify: partial delivery", "type", it.Type, "err", redact.String(transient.Error()))
		}
		return outcome{delivered: true}
	case transient != nil:
		return outcome{err: transient}
	default:
		return outcome{delivered: true, err: permanent}
	}
}

type sendMessage struct {
	ChatID                int64  `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

// sendOne возвращает permanent=true для отказов, которые повтор не исправит
// (400/401/403/404: бот заблокирован, чат не найден).
func (d *Deliverer) sendOne(parent context.Context, chatID int64, text string) (permanent bool, err error) {
	ctx, cancel := context.WithTimeout(InternalContext(parent), d.o.Timeout)
	defer cancel()
	body, err := json.Marshal(sendMessage{ChatID: chatID, Text: text, ParseMode: "HTML", DisableWebPagePreview: true})
	if err != nil {
		return true, err
	}
	path := "/bot" + d.o.Token + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://tgproxy.internal"+path, bytes.NewReader(body))
	if err != nil {
		return true, errors.New("build request")
	}
	req.Header.Set("Content-Type", "application/json")
	route, err := tgapi.ParsePath(req.URL.EscapedPath())
	if err != nil {
		return true, errors.New("notifier bot token is invalid")
	}
	resp, err := d.o.Sender.Do(ctx, req, route)
	if err != nil {
		return false, fmt.Errorf("send: %w", redactErr(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		env, perr := tgapi.ParseEnvelope(resp.Body, envelopeLimit)
		if perr != nil || !env.OK {
			return false, errors.New("telegram: unexpected 200 response")
		}
		return false, nil
	}
	env, _ := tgapi.ParseEnvelope(resp.Body, envelopeLimit)
	desc := ""
	if env != nil {
		desc = env.Description
	}
	e := fmt.Errorf("telegram: status %s: %s", strconv.Itoa(resp.StatusCode), desc)
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true, e
	}
	return false, e
}

func redactErr(err error) error { return errors.New(redact.String(err.Error())) }
