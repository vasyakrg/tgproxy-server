package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Действия аудита правил доступа. Ключ и его хеш в аудит не попадают.
const (
	AuditRuleCreate = "access_rule.create"
	AuditRuleUpdate = "access_rule.update"
	AuditRuleDelete = "access_rule.delete"
)

// Лимиты ввода.
const (
	maxCIDRs   = 256
	maxCIDRLen = 64
	maxRPS     = 1_000_000
	echoLen    = 40
)

// FieldGeneral — ключ общей (не полевой) ошибки в FieldErrors.
const FieldGeneral = "_"

// Поля формы/JSON, к которым привязываются ошибки.
const (
	FieldName = "name"
	FieldNets = "cidrs"
	FieldRPS  = "rps"
)

// FieldErrors — ошибки валидации по полям (значения — готовые тексты для UI).
type FieldErrors map[string]string

// ValidationError — ввод не прошёл валидацию (HTTP 422).
type ValidationError struct{ Fields FieldErrors }

func (e *ValidationError) Error() string {
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+e.Fields[k])
	}
	return "validation: " + strings.Join(parts, "; ")
}

// Actor — кто делает изменение (для аудита).
type Actor struct{ User, IP string }

// AccessService — CRUD правил доступа с валидацией и аудитом. Общий для JSON API и HTML-экрана.
type AccessService struct {
	rules store.AccessRuleRepo
	audit store.AuditRepo
	log   *slog.Logger
	now   func() time.Time
}

// NewAccessService создаёт сервис; log и now могут быть nil.
func NewAccessService(rules store.AccessRuleRepo, audit store.AuditRepo, log *slog.Logger, now func() time.Time) *AccessService {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &AccessService{rules: rules, audit: audit, log: log, now: now}
}

// CreateInput — ввод создания правила.
type CreateInput struct {
	Name    string
	CIDRs   []string // сырые записи: "10.0.0.0/8", "10.1.2.3" (= /32)
	WithKey bool     // сгенерировать скрытый ключ
	RPS     float64  // 0 — без лимита
}

// UpdateInput — частичное обновление; nil — «не менять». Ключ не меняется.
type UpdateInput struct {
	Name    *string
	CIDRs   *[]string
	RPS     *float64
	Enabled *bool
}

// Created — результат создания. PlainKey непуст только здесь и больше нигде не доступен.
type Created struct {
	Rule     store.AccessRule
	PlainKey string
}

// ValidateCreate проверяет ввод создания без обращения к хранилищу (для объединения с ошибками формы).
func ValidateCreate(in CreateInput) FieldErrors {
	_, fe := parseAndCheck(in.Name, in.CIDRs, in.WithKey, in.RPS)
	return fe
}

// parseAndCheck разбирает сети и проверяет правило; ошибки разбора сетей заменяют ошибки по сетям.
func parseAndCheck(name string, entries []string, hasKey bool, rps float64) ([]netip.Prefix, FieldErrors) {
	prefixes, parseErr := ParseCIDRs(entries)
	fe := CheckRule(name, prefixes, hasKey, rps)
	if parseErr != nil {
		if fe == nil {
			fe = FieldErrors{}
		}
		fe[FieldNets] = parseErr[FieldNets]
	}
	return prefixes, fe
}

// List возвращает все правила.
func (s *AccessService) List(ctx context.Context) ([]store.AccessRule, error) {
	return s.rules.List(ctx)
}

// Get возвращает правило по id (store.ErrNotFound, если нет).
func (s *AccessService) Get(ctx context.Context, id int64) (store.AccessRule, error) {
	return s.rules.Get(ctx, id)
}

// Create валидирует и создаёт правило.
func (s *AccessService) Create(ctx context.Context, act Actor, in CreateInput) (Created, error) {
	prefixes, fe := parseAndCheck(in.Name, in.CIDRs, in.WithKey, in.RPS)
	if len(fe) > 0 {
		return Created{}, &ValidationError{Fields: fe}
	}
	rule := store.AccessRule{Name: strings.TrimSpace(in.Name), CIDRs: prefixes, RPS: in.RPS, Enabled: true}
	var plain string
	if in.WithKey {
		var err error
		plain, rule.KeyHash, rule.KeyPrefix, err = access.NewKey()
		if err != nil {
			return Created{}, err
		}
	}
	got, err := s.rules.Create(ctx, rule)
	if err != nil {
		return Created{}, s.mapStoreErr(err)
	}
	s.record(ctx, act, AuditRuleCreate, got)
	return Created{Rule: got, PlainKey: plain}, nil
}

// Update применяет изменения и валидирует итоговое правило.
func (s *AccessService) Update(ctx context.Context, act Actor, id int64, in UpdateInput) (store.AccessRule, error) {
	cur, err := s.rules.Get(ctx, id)
	if err != nil {
		return store.AccessRule{}, err
	}
	if in.Name != nil {
		cur.Name = strings.TrimSpace(*in.Name)
	}
	if in.RPS != nil {
		cur.RPS = *in.RPS
	}
	if in.Enabled != nil {
		cur.Enabled = *in.Enabled
	}
	hasKey := len(cur.KeyHash) > 0
	var fe FieldErrors
	if in.CIDRs != nil {
		cur.CIDRs, fe = parseAndCheck(cur.Name, *in.CIDRs, hasKey, cur.RPS)
	} else {
		fe = CheckRule(cur.Name, cur.CIDRs, hasKey, cur.RPS)
	}
	if len(fe) > 0 {
		return store.AccessRule{}, &ValidationError{Fields: fe}
	}
	got, err := s.rules.Update(ctx, cur)
	if err != nil {
		return store.AccessRule{}, s.mapStoreErr(err)
	}
	s.record(ctx, act, AuditRuleUpdate, got)
	return got, nil
}

// Delete удаляет правило; возвращает удалённое (для сообщения).
func (s *AccessService) Delete(ctx context.Context, act Actor, id int64) (store.AccessRule, error) {
	cur, err := s.rules.Get(ctx, id)
	if err != nil {
		return store.AccessRule{}, err
	}
	if err := s.rules.Delete(ctx, id); err != nil {
		return store.AccessRule{}, err
	}
	s.record(ctx, act, AuditRuleDelete, cur)
	return cur, nil
}

func (s *AccessService) mapStoreErr(err error) error {
	switch {
	case errors.Is(err, store.ErrConflict):
		return &ValidationError{Fields: FieldErrors{FieldName: "Правило с таким названием уже существует"}}
	case errors.Is(err, store.ErrInvalid):
		return &ValidationError{Fields: FieldErrors{FieldGeneral: "Правило не прошло проверку"}}
	}
	return err
}

func (s *AccessService) record(ctx context.Context, act Actor, action string, r store.AccessRule) {
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	detail := fmt.Sprintf("id=%d cidrs=%d key=%t rps=%g enabled=%t", r.ID, len(r.CIDRs), len(r.KeyHash) > 0, r.RPS, r.Enabled)
	if _, err := s.audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: action, Target: r.Name, IP: act.IP, Detail: detail,
	}); err != nil {
		s.log.ErrorContext(ctx, "access rule audit failed", "action", action, "rule", r.Name, "err", err)
	}
}

// SplitCIDRs разбивает многострочный ввод (строки, запятые, пробелы) на записи.
func SplitCIDRs(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t'
	})
}

// ParseRPS разбирает лимит из формы; пусто — 0 (без лимита).
func ParseRPS(s string) (float64, string) {
	s = strings.TrimSpace(strings.ReplaceAll(s, ",", "."))
	if s == "" {
		return 0, ""
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || strings.ContainsAny(s, "xXpP_") {
		return 0, "Введите число, например 30"
	}
	return v, ""
}

func echo(s string) string {
	if utf8.RuneCountInString(s) <= echoLen {
		return s
	}
	return string([]rune(s)[:echoLen]) + "…"
}

// ParseCIDRs разбирает записи в префиксы. Голый IP превращается в /32 (/128). Дубликаты схлопываются.
// Ошибки возвращаются в FieldErrors[FieldNets].
func ParseCIDRs(entries []string) ([]netip.Prefix, FieldErrors) {
	if len(entries) > maxCIDRs {
		return nil, FieldErrors{FieldNets: fmt.Sprintf("Слишком много сетей (максимум %d)", maxCIDRs)}
	}
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		var (
			p   netip.Prefix
			err error
		)
		if len(e) > maxCIDRLen {
			err = errors.New("too long")
		} else if strings.Contains(e, "/") {
			p, err = netip.ParsePrefix(e)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(e); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			return nil, FieldErrors{FieldNets: fmt.Sprintf("«%s» — неверная сеть, ожидается CIDR вида 10.0.0.0/24", echo(e))}
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// CheckRule проверяет правило правилами конфига (config.CheckAccessRule — единый источник) и
// переводит нарушения в ошибки по полям. hasKey — у правила есть (или будет) скрытый ключ.
func CheckRule(name string, cidrs []netip.Prefix, hasKey bool, rps float64) FieldErrors {
	fe := FieldErrors{}
	set := func(field, msg string) {
		if _, ok := fe[field]; !ok {
			fe[field] = msg
		}
	}
	rule := config.AccessRule{Name: strings.TrimSpace(name), CIDRs: cidrs, RPS: rps}
	if hasKey {
		rule.KeySHA256 = hex.EncodeToString(make([]byte, 32)) // важно лишь наличие ключа
	}
	if rule.Name == "" {
		set(FieldName, "Укажите название")
	}
	for _, is := range config.CheckAccessRule(rule) {
		switch is.Code {
		case config.IssueName:
			if rule.Name != "" {
				set(FieldName, "Буквы, цифры, пробел, «.», «_», «-»; без пробелов по краям; до 64 символов")
			}
		case config.IssueNoNetNoKey:
			set(FieldNets, "Укажите хотя бы одну сеть или включите скрытый ключ: правило без них — открытый прокси к Bot API")
		case config.IssueOpenRelay:
			set(FieldNets, "0.0.0.0/0 и ::/0 без ключа — открытый прокси к Bot API: включите скрытый ключ или сузьте сеть")
		case config.IssueInvalidCIDR:
			set(FieldNets, "Неверная сеть")
		case config.IssueHostBits:
			p := cidrs[is.Index]
			set(FieldNets, fmt.Sprintf("%s: заданы биты хоста, используйте %s", p, p.Masked()))
		case config.IssueNegativeRate:
			set(FieldRPS, "Лимит не может быть отрицательным")
		case config.IssueKeyForms, config.IssueKeyHash:
			set(FieldGeneral, "Некорректный ключ")
		}
	}
	if rps > maxRPS {
		set(FieldRPS, fmt.Sprintf("Слишком большое значение (максимум %d)", maxRPS))
	}
	if len(fe) == 0 {
		return nil
	}
	return fe
}

// RuleKind — тип правила по составу условий.
type RuleKind string

// Типы правил.
const (
	KindNetwork RuleKind = "network"
	KindKey     RuleKind = "key"
	KindBoth    RuleKind = "network+key"
)

// KindOf определяет тип правила.
func KindOf(r store.AccessRule) RuleKind {
	switch {
	case len(r.KeyHash) > 0 && len(r.CIDRs) > 0:
		return KindBoth
	case len(r.KeyHash) > 0:
		return KindKey
	}
	return KindNetwork
}
