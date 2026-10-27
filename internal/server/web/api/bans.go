package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/ban"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Действия аудита банов.
const (
	AuditBanCreate = "ban.create"
	AuditBanDelete = "ban.delete"
	AuditBanAuto   = "ban.auto"
)

// Поля формы/JSON банов, к которым привязываются ошибки.
const (
	FieldIP       = "ip"
	FieldDuration = "duration"
	FieldComment  = "comment"
)

// Сроки, доступные в UI, и предел для API.
const (
	maxBanDurationDays = 365
	maxCommentRunes    = 200
)

// BanManager — то, что сервису нужно от *ban.Manager.
type BanManager interface {
	Add(ctx context.Context, r ban.AddRequest) (store.Ban, error)
	Remove(ctx context.Context, id int64) (store.Ban, error)
	List(ctx context.Context) ([]store.Ban, error)
}

// BansService — ручное управление банами с валидацией и аудитом. Общий для JSON API, HTML-экрана и CLI.
type BansService struct {
	m     BanManager
	audit store.AuditRepo
	log   *slog.Logger
	now   func() time.Time
}

// NewBansService создаёт сервис; log и now могут быть nil.
func NewBansService(m BanManager, audit store.AuditRepo, log *slog.Logger, now func() time.Time) *BansService {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &BansService{m: m, audit: audit, log: log, now: now}
}

// BanInput — ввод ручного бана. Duration: «30m», «1h», «24h», «7d»; Permanent — бессрочно (Duration пуст).
type BanInput struct {
	IP        string
	Duration  string
	Permanent bool
	Comment   string
}

// ParseBanDuration разбирает срок: стандартные duration плюс суффикс «d» (дни).
func ParseBanDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 || n > maxBanDurationDays {
			return 0, fmt.Errorf("bad days %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return d, nil
}

// ParseBanAddr разбирает IP для бана (без зоны и без маски).
func ParseBanAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, errors.New("bad ip")
	}
	return a.Unmap(), nil
}

// Create валидирует и создаёт бан.
func (s *BansService) Create(ctx context.Context, act Actor, in BanInput) (store.Ban, error) {
	fe := FieldErrors{}
	addr, err := ParseBanAddr(in.IP)
	if err != nil {
		fe[FieldIP] = "Введите IP-адрес, например 203.0.113.7 или 2001:db8::1"
	}
	var dur time.Duration
	switch {
	case in.Permanent:
		if strings.TrimSpace(in.Duration) != "" {
			fe[FieldDuration] = "Укажите либо срок, либо «навсегда»"
		}
	case strings.TrimSpace(in.Duration) == "":
		fe[FieldDuration] = "Выберите срок или «навсегда»"
	default:
		dur, err = ParseBanDuration(in.Duration)
		if err != nil || dur <= 0 || dur > ban.MaxManualDuration {
			fe[FieldDuration] = "Срок от 1 минуты до 365 дней, например 1h, 24h, 7d"
		}
	}
	if len([]rune(in.Comment)) > maxCommentRunes {
		fe[FieldComment] = fmt.Sprintf("Не длиннее %d символов", maxCommentRunes)
	}
	if len(fe) > 0 {
		return store.Ban{}, &ValidationError{Fields: fe}
	}
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	b, err := s.m.Add(ctx, ban.AddRequest{
		Addr: addr, Duration: dur, Permanent: in.Permanent, Comment: strings.TrimSpace(in.Comment), Actor: actor,
	})
	if err != nil {
		var pe *ban.ProtectedError
		if errors.As(err, &pe) {
			return store.Ban{}, &ValidationError{Fields: FieldErrors{FieldIP: "Этот адрес банить нельзя: " + pe.Reason}}
		}
		return store.Ban{}, err
	}
	s.record(ctx, act, AuditBanCreate, b)
	return b, nil
}

// Delete снимает бан (store.ErrNotFound, если уже нет); возвращает снятый.
func (s *BansService) Delete(ctx context.Context, act Actor, id int64) (store.Ban, error) {
	b, err := s.m.Remove(ctx, id)
	if err != nil {
		return store.Ban{}, err
	}
	s.record(ctx, act, AuditBanDelete, b)
	return b, nil
}

// List возвращает действующие баны.
func (s *BansService) List(ctx context.Context) ([]store.Ban, error) { return s.m.List(ctx) }

func (s *BansService) record(ctx context.Context, act Actor, action string, b store.Ban) {
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	until := "permanent"
	if b.ExpiresAt != nil {
		until = b.ExpiresAt.UTC().Format(time.RFC3339)
	}
	detail := fmt.Sprintf("id=%d source=%s until=%s level=%d", b.ID, b.Source, until, b.Level)
	if _, err := s.audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: action, Target: b.Prefix.String(), IP: act.IP, Detail: detail,
	}); err != nil {
		s.log.ErrorContext(ctx, "ban audit failed", "action", action, "prefix", b.Prefix.String(), "err", err)
	}
}

// RecordAutoBan пишет в аудит автобан (actor «auto»).
func RecordAutoBan(ctx context.Context, audit store.AuditRepo, lg *slog.Logger, b store.Ban, count int) {
	until := "permanent"
	if b.ExpiresAt != nil {
		until = b.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if _, err := audit.Append(ctx, store.AuditEntry{
		At: time.Now(), Actor: "auto", Action: AuditBanAuto, Target: b.Prefix.String(),
		Detail: fmt.Sprintf("id=%d denials=%d until=%s level=%d", b.ID, count, until, b.Level),
	}); err != nil && lg != nil {
		lg.ErrorContext(ctx, "autoban audit failed", "prefix", b.Prefix.String(), "err", err)
	}
}

// DisplayAddr — адрес для людей: IPv4 без «/32», IPv6 как префикс /64.
func DisplayAddr(p netip.Prefix) string {
	if p.Addr().Is4() {
		return p.Addr().String()
	}
	return p.String()
}
