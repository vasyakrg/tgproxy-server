package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// ErrTestTooOften — «Отправить тест» нажали слишком часто.
var ErrTestTooOften = errors.New("api: тестовое сообщение уже отправлялось недавно")

// defaultTestInterval — минимальная пауза между тестовыми сообщениями.
const defaultTestInterval = 10 * time.Second

// TestSender ставит тестовое сообщение в очередь (реализует *notify.Notifier).
type TestSender interface {
	SendTest(ctx context.Context, actor string) error
}

// EventToggles — переключатели типов событий (реализует *notify.Toggles).
type EventToggles interface {
	States(ctx context.Context) (map[notify.AlertType]bool, error)
	Set(ctx context.Context, states map[notify.AlertType]bool) error
}

// AdminDirectory — администраторы из users-файла (реализует *auth.Users).
type AdminDirectory interface {
	Names() []string
	Get(name string) (auth.User, bool)
}

// NotificationsConfig — зависимости NotificationsService.
type NotificationsConfig struct {
	Sender       TestSender // nil — уведомления выключены (нет notify.bot_token_file)
	BotID        string     // часть токена до «:»; сам токен сюда не попадает
	Toggles      EventToggles
	Admins       AdminDirectory
	Audit        store.AuditRepo
	Outbox       store.OutboxRepo // необязательно: число сообщений в очереди
	Wake         func()           // разбудить доставку после теста
	TestInterval time.Duration    // 0 → 10 с
	Logger       *slog.Logger
	Now          func() time.Time
}

// NotificationsService — экран «Уведомления в Telegram».
type NotificationsService struct {
	c   NotificationsConfig
	log *slog.Logger
	now func() time.Time

	mu       sync.Mutex
	lastTest time.Time
}

// NewNotificationsService создаёт сервис.
func NewNotificationsService(c NotificationsConfig) *NotificationsService {
	s := &NotificationsService{c: c, log: c.Logger, now: c.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.c.TestInterval <= 0 {
		s.c.TestInterval = defaultTestInterval
	}
	return s
}

// AdminJSON — администратор в списке получателей.
type AdminJSON struct {
	Name       string `json:"name"`
	TelegramID int64  `json:"telegram_id,omitempty"`
	TOTP       bool   `json:"totp"`
	Disabled   bool   `json:"disabled"`
	LastLogin  string `json:"last_login,omitempty"`
}

// EventJSON — тип события и его переключатель.
type EventJSON struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Hint     string `json:"hint,omitempty"`
	Severity string `json:"severity"`
	Enabled  bool   `json:"enabled"`
}

// NotificationsInfo — GET /api/v1/notifications.
type NotificationsInfo struct {
	Enabled bool        `json:"enabled"`
	BotID   string      `json:"bot_id,omitempty"`
	Pending int         `json:"pending"`
	Admins  []AdminJSON `json:"admins"`
	Events  []EventJSON `json:"events"`
}

const lastLoginScan = 200

func (s *NotificationsService) lastLogin(ctx context.Context, name string) string {
	if s.c.Audit == nil {
		return ""
	}
	items, err := s.c.Audit.List(ctx, store.AuditQuery{Actor: name, Limit: lastLoginScan})
	if err != nil {
		return ""
	}
	for _, e := range items {
		if e.Action == auth.AuditLoginOK {
			return e.At.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// Info собирает состояние экрана.
func (s *NotificationsService) Info(ctx context.Context) (NotificationsInfo, error) {
	info := NotificationsInfo{Enabled: s.c.Sender != nil, BotID: s.c.BotID, Admins: []AdminJSON{}, Events: []EventJSON{}}
	if s.c.Outbox != nil {
		if n, err := s.c.Outbox.CountPending(ctx); err == nil {
			info.Pending = n
		}
	}
	if s.c.Admins != nil {
		for _, n := range s.c.Admins.Names() {
			u, ok := s.c.Admins.Get(n)
			if !ok {
				continue
			}
			info.Admins = append(info.Admins, AdminJSON{
				Name: n, TelegramID: u.TelegramID, TOTP: strings.TrimSpace(u.TOTPSecretEnc) != "",
				Disabled: u.Disabled, LastLogin: s.lastLogin(ctx, n),
			})
		}
	}
	var states map[notify.AlertType]bool
	if s.c.Toggles != nil {
		var err error
		if states, err = s.c.Toggles.States(ctx); err != nil {
			return info, fmt.Errorf("api: notification toggles: %w", err)
		}
	}
	for _, e := range notify.Catalog() {
		on := true
		if states != nil {
			on = states[e.Type]
		}
		info.Events = append(info.Events, EventJSON{
			Type: string(e.Type), Title: e.Title, Hint: e.Hint, Severity: string(e.Severity), Enabled: on,
		})
	}
	return info, nil
}

func (s *NotificationsService) record(ctx context.Context, act Actor, action, target, detail string) {
	if s.c.Audit == nil {
		return
	}
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	if _, err := s.c.Audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: action, Target: target, IP: act.IP, Detail: truncate(detail, 128),
	}); err != nil {
		s.log.ErrorContext(ctx, "notifications audit failed", "action", action, "err", err)
	}
}

// SetEvents включает и выключает типы событий; типы, которых нет в states, не меняются.
func (s *NotificationsService) SetEvents(ctx context.Context, act Actor, states map[string]bool) (NotificationsInfo, error) {
	if s.c.Toggles == nil {
		return NotificationsInfo{}, ErrNotConfigured
	}
	typed := make(map[notify.AlertType]bool, len(states))
	for k, v := range states {
		if !notify.KnownType(notify.AlertType(k)) {
			return NotificationsInfo{}, &ValidationError{Fields: FieldErrors{"events": "неизвестный тип события: " + truncate(k, 40)}}
		}
		typed[notify.AlertType(k)] = v
	}
	if err := s.c.Toggles.Set(ctx, typed); err != nil {
		return NotificationsInfo{}, err
	}
	var off []string
	for _, e := range notify.Catalog() {
		if v, ok := typed[e.Type]; ok && !v {
			off = append(off, string(e.Type))
		}
	}
	s.record(ctx, act, "notifications.update", "", "off="+strings.Join(off, ","))
	return s.Info(ctx)
}

// SendTest ставит тестовое сообщение в очередь доставки администраторам.
func (s *NotificationsService) SendTest(ctx context.Context, act Actor) error {
	if s.c.Sender == nil {
		return ErrNotConfigured
	}
	s.mu.Lock()
	now := s.now()
	if !s.lastTest.IsZero() && now.Sub(s.lastTest) < s.c.TestInterval {
		s.mu.Unlock()
		return ErrTestTooOften
	}
	s.lastTest = now
	s.mu.Unlock()
	if err := s.c.Sender.SendTest(ctx, act.User); err != nil {
		s.mu.Lock()
		s.lastTest = time.Time{}
		s.mu.Unlock()
		return err
	}
	if s.c.Wake != nil {
		s.c.Wake()
	}
	s.record(ctx, act, "notifications.test", "", "")
	return nil
}
