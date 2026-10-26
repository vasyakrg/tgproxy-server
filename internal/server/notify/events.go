package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// SettingDisabled — ключ настройки: типы алертов через запятую, которые администратор выключил.
// Новый тип по умолчанию включён.
const SettingDisabled = "notify.disabled_types"

// TestType — тип служебного тестового сообщения (вне каталога, не отключается).
const TestType = "test"

// EventInfo — тип алерта для экрана «Какие события отправлять».
type EventInfo struct {
	Type     AlertType
	Title    string
	Hint     string
	Severity Severity
}

// Catalog — все типы алертов §9 в порядке показа.
func Catalog() []EventInfo {
	return []EventInfo{
		{AgentDown, "Агент недоступен", "Агент не отвечает или выпал из балансировки", SeverityCritical},
		{AllAgentsDown, "Все агенты недоступны", "Прокси не может отправить ни одного запроса", SeverityCritical},
		{AgentDegraded, "Рост ошибок на агенте", "Доля ошибок выше 5% за 5 минут", SeverityWarning},
		{Overload, "Перегрузка агента", "Число запросов в полёте выше порога", SeverityWarning},
		{CertExpiring, "Сертификат агента истекает", "Сертификат агента скоро закончится", SeverityWarning},
		{IngressCertExpiring, "Сертификат входа истекает", "Сертификат публичного адреса скоро закончится", SeverityWarning},
		{IngressCertInvalid, "Сертификат входа недействителен", "Файлы сертификата не читаются или не подходят", SeverityCritical},
		{VersionMismatch, "Версия агента отличается", "Агент работает на другой версии, чем сервер", SeverityWarning},
		{LoginLockout, "Блокировка входа", "Много неудачных попыток входа в админку", SeverityWarning},
		{HostKeyMismatch, "Ключ SSH-хоста изменился", "Возможна подмена хоста при установке агента", SeverityCritical},
		{AgentEnrolled, "Агент подключён", "Новый агент за NAT завершил подключение", SeverityInfo},
		{RolloutFailed, "Раскатка обновления остановлена", "Обновление агента не прошло проверку, остальные агенты не тронуты", SeverityCritical},
	}
}

// KnownType сообщает, что тип входит в каталог.
func KnownType(t AlertType) bool {
	return slices.ContainsFunc(Catalog(), func(e EventInfo) bool { return e.Type == t })
}

// Toggles — переключатели «какие события отправлять» поверх store.SettingsRepo.
type Toggles struct {
	repo store.SettingsRepo
	mu   sync.RWMutex
	off  map[AlertType]bool
	ok   bool
}

// NewToggles создаёт Toggles; значения читаются лениво и кэшируются до Set.
func NewToggles(repo store.SettingsRepo) *Toggles { return &Toggles{repo: repo} }

func (t *Toggles) load(ctx context.Context) (map[AlertType]bool, error) {
	t.mu.RLock()
	if t.ok {
		defer t.mu.RUnlock()
		return t.off, nil
	}
	t.mu.RUnlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ok {
		return t.off, nil
	}
	off := map[AlertType]bool{}
	v, err := t.repo.Get(ctx, SettingDisabled)
	switch {
	case err == nil:
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				off[AlertType(p)] = true
			}
		}
	case !errors.Is(err, store.ErrNotFound):
		return nil, fmt.Errorf("notify: settings: %w", err)
	}
	t.off, t.ok = off, true
	return off, nil
}

// Enabled сообщает, что тип включён (при ошибке чтения настроек — включён, чтобы не терять алерты).
func (t *Toggles) Enabled(ctx context.Context, a AlertType) bool {
	off, err := t.load(ctx)
	return err != nil || !off[a]
}

// States возвращает состояние каждого типа каталога.
func (t *Toggles) States(ctx context.Context) (map[AlertType]bool, error) {
	off, err := t.load(ctx)
	if err != nil {
		return nil, err
	}
	out := map[AlertType]bool{}
	for _, e := range Catalog() {
		out[e.Type] = !off[e.Type]
	}
	return out, nil
}

// Set сохраняет состояния; неизвестный тип → store.ErrInvalid. Типы, которых нет в map, не меняются.
func (t *Toggles) Set(ctx context.Context, states map[AlertType]bool) error {
	for k := range states {
		if !KnownType(k) {
			return fmt.Errorf("%w: unknown event type %q", store.ErrInvalid, k)
		}
	}
	cur, err := t.load(ctx)
	if err != nil {
		return err
	}
	next := map[AlertType]bool{}
	for _, e := range Catalog() {
		next[e.Type] = cur[e.Type]
	}
	for k, on := range states {
		next[k] = !on
	}
	var list []string
	for _, e := range Catalog() {
		if next[e.Type] {
			list = append(list, string(e.Type))
		}
	}
	if err := t.repo.Set(ctx, SettingDisabled, strings.Join(list, ",")); err != nil {
		return fmt.Errorf("notify: save settings: %w", err)
	}
	off := map[AlertType]bool{}
	for _, s := range list {
		off[AlertType(s)] = true
	}
	t.mu.Lock()
	t.off, t.ok = off, true
	t.mu.Unlock()
	return nil
}
