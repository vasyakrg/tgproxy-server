package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// AuditErrorsPurge — действие аудита ручной очистки журнала ошибок.
const AuditErrorsPurge = "errors.purge"

// ErrorsKeepDays — допустимые значения keep_days: 0 — удалить всё, иначе удаляются записи старше N дней.
var ErrorsKeepDays = []int{0, 30, 15, 5, 3}

// ValidKeepDays — keep_days входит в разрешённый набор.
func ValidKeepDays(n int) bool {
	for _, k := range ErrorsKeepDays {
		if k == n {
			return true
		}
	}
	return false
}

// ErrorsPurgeService — ручная очистка журнала ошибок (только error_events; агрегаты, история rps
// и журнал сессий не трогаются). Общий для JSON API и UI.
type ErrorsPurgeService struct {
	repo  store.ErrorEventRepo
	audit store.AuditRepo
	log   *slog.Logger
	now   func() time.Time
}

// NewErrorsPurgeService создаёт сервис; log и now могут быть nil.
func NewErrorsPurgeService(repo store.ErrorEventRepo, audit store.AuditRepo, log *slog.Logger, now func() time.Time) *ErrorsPurgeService {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &ErrorsPurgeService{repo: repo, audit: audit, log: log, now: now}
}

// Purge удаляет записи старше keepDays суток (keepDays=0 — все) и возвращает их число.
// Граница строгая: запись ровно N суток назад остаётся. Пишет аудит errors.purge.
func (s *ErrorsPurgeService) Purge(ctx context.Context, act Actor, keepDays int) (int64, error) {
	if !ValidKeepDays(keepDays) {
		return 0, &ValidationError{Fields: FieldErrors{"keep_days": "Допустимо: 0 (всё), 3, 5, 15, 30"}}
	}
	var before time.Time
	if keepDays > 0 {
		before = s.now().Add(-time.Duration(keepDays) * 24 * time.Hour)
	}
	n, err := s.repo.Purge(ctx, before)
	if err != nil {
		return 0, err
	}
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	if _, aerr := s.audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: AuditErrorsPurge, Target: "error_events", IP: act.IP,
		Detail: fmt.Sprintf("keep_days=%d deleted=%d", keepDays, n),
	}); aerr != nil {
		s.log.ErrorContext(ctx, "errors purge audit failed", "err", aerr)
	}
	return n, nil
}
