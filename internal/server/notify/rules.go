package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const (
	defaultEvalInterval = 30 * time.Second
	defaultErrThreshold = 0.05
	defaultErrWindow    = 5 * time.Minute
	defaultMinRequests  = 20
	defaultOverload     = 200
	defaultCertWarn     = 14 * 24 * time.Hour
)

// Alerter — то, во что Evaluator отдаёт алерты (*Notifier).
type Alerter interface {
	Fire(ctx context.Context, a Alert) error
	Resolve(ctx context.Context, key string) error
	Flush(ctx context.Context) error
}

// Registry — реестр агентов (*agents.Registry).
type Registry interface {
	List() []agents.State
	Subscribe() (<-chan agents.Event, func())
}

// ErrorRateSource — доля ошибок агента за окно и число запросов в окне.
type ErrorRateSource interface {
	AgentErrorRate(agent string, window time.Duration) (rate float64, requests int64)
}

// EvalOptions — параметры Evaluator. Нулевые значения заменяются умолчаниями.
type EvalOptions struct {
	Registry Registry
	Alerter  Alerter
	Errors   ErrorRateSource // nil → agent_degraded отключён

	Interval         time.Duration // период оценки; 30с
	ErrThreshold     float64       // доля ошибок; 0.05
	ErrWindow        time.Duration // окно ошибок; 5м
	MinRequests      int64         // минимум запросов в окне для agent_degraded; 20
	OverloadInflight int           // порог inflight; 200
	CertWarn         time.Duration // cert_expiring/ingress_cert_expiring; 14д
	Version          string        // ожидаемая версия агентов; buildinfo.Version
	Clock            Clock
	// Tick создаёт канал периодической оценки (тесты подменяют); по умолчанию time.Ticker.
	Tick   func(d time.Duration) (<-chan time.Time, func())
	Logger *slog.Logger
}

// Evaluator превращает состояние реестра и события подсистем в Fire/Resolve.
type Evaluator struct {
	o   EvalOptions
	log *slog.Logger
}

// NewEvaluator создаёт Evaluator.
func NewEvaluator(o EvalOptions) *Evaluator {
	if o.Interval <= 0 {
		o.Interval = defaultEvalInterval
	}
	if o.ErrThreshold <= 0 {
		o.ErrThreshold = defaultErrThreshold
	}
	if o.ErrWindow <= 0 {
		o.ErrWindow = defaultErrWindow
	}
	if o.MinRequests <= 0 {
		o.MinRequests = defaultMinRequests
	}
	if o.OverloadInflight <= 0 {
		o.OverloadInflight = defaultOverload
	}
	if o.CertWarn <= 0 {
		o.CertWarn = defaultCertWarn
	}
	if o.Version == "" {
		o.Version = buildinfo.Version
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Tick == nil {
		o.Tick = func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		}
	}
	l := o.Logger
	if l == nil {
		l = slog.Default()
	}
	return &Evaluator{o: o, log: l}
}

// Run обрабатывает события реестра и периодически вычисляет пороговые правила.
func (e *Evaluator) Run(ctx context.Context) {
	events, cancel := e.o.Registry.Subscribe()
	defer cancel()
	tick, stop := e.o.Tick(e.o.Interval)
	defer stop()
	e.Evaluate(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			e.HandleEvent(ctx, ev)
		case <-tick:
			e.Evaluate(ctx)
		}
	}
}

func (e *Evaluator) fire(ctx context.Context, a Alert) {
	if a.At.IsZero() {
		a.At = e.o.Clock()
	}
	if err := e.o.Alerter.Fire(ctx, a); err != nil {
		e.log.Warn("notify: fire", "type", a.Type, "agent", a.AgentID, "err", redact.String(err.Error()))
	}
}

func (e *Evaluator) resolve(ctx context.Context, key string) {
	if err := e.o.Alerter.Resolve(ctx, key); err != nil {
		e.log.Warn("notify: resolve", "key", key, "err", redact.String(err.Error()))
	}
}

// set вызывает fire при cond и resolve иначе.
func (e *Evaluator) set(ctx context.Context, cond bool, a Alert) {
	if cond {
		e.fire(ctx, a)
		return
	}
	e.resolve(ctx, a.key())
}

// HandleEvent реагирует на событие реестра: agent_down / восстановление.
func (e *Evaluator) HandleEvent(ctx context.Context, ev agents.Event) {
	key := AlertKey(AgentDown, ev.AgentID)
	switch ev.Type {
	case agents.AgentDown:
		e.fire(ctx, Alert{
			Type: AgentDown, AgentID: ev.AgentID, Severity: SeverityCritical, At: ev.At,
			Title: fmt.Sprintf("Агент %s недоступен", ev.AgentID),
			Text:  "Агент не отвечает на опрос статуса, трафик идёт через остальных.",
		})
	case agents.AgentUp, agents.AgentRemoved:
		e.resolve(ctx, key)
	default:
		return
	}
	e.checkAllDown(ctx, e.o.Registry.List())
}

// Evaluate вычисляет пороговые правила по текущему снимку реестра.
func (e *Evaluator) Evaluate(ctx context.Context) {
	states := e.o.Registry.List()
	for _, s := range states {
		if s.Up && s.LastStatus != nil {
			e.evalAgent(ctx, s)
		}
	}
	e.checkAllDown(ctx, states)
	if err := e.o.Alerter.Flush(ctx); err != nil {
		e.log.Warn("notify: flush", "err", redact.String(err.Error()))
	}
}

func (e *Evaluator) evalAgent(ctx context.Context, s agents.State) {
	id, st := s.Agent.ID, s.LastStatus

	e.set(ctx, st.Inflight > e.o.OverloadInflight, Alert{
		Type: Overload, AgentID: id, Severity: SeverityWarning,
		Title: fmt.Sprintf("Агент %s перегружен", id),
		Text:  fmt.Sprintf("In-flight запросов: %d (порог %d).", st.Inflight, e.o.OverloadInflight),
	})

	if !st.CertNotAfter.IsZero() {
		left := st.CertNotAfter.Sub(e.o.Clock())
		e.set(ctx, left < e.o.CertWarn, Alert{
			Type: CertExpiring, AgentID: id, Severity: SeverityWarning,
			Title: fmt.Sprintf("Сертификат агента %s истекает", id),
			Text:  fmt.Sprintf("Действует до %s (осталось %s).", st.CertNotAfter.UTC().Format("2006-01-02 15:04"), humanLeft(left)),
		})
	}

	if st.Version != "" {
		e.set(ctx, st.Version != e.o.Version, Alert{
			Type: VersionMismatch, AgentID: id, Severity: SeverityWarning,
			Title: fmt.Sprintf("Версия агента %s не совпадает с сервером", id),
			Text:  fmt.Sprintf("Агент: %s, сервер: %s.", st.Version, e.o.Version),
		})
	}

	if e.o.Errors != nil {
		rate, n := e.o.Errors.AgentErrorRate(id, e.o.ErrWindow)
		if n >= e.o.MinRequests { // при малом числе запросов состояние не меняем
			e.set(ctx, rate > e.o.ErrThreshold, Alert{
				Type: AgentDegraded, AgentID: id, Severity: SeverityWarning,
				Title: fmt.Sprintf("Агент %s деградирует", id),
				Text:  fmt.Sprintf("Ошибок %.1f%% за %s (запросов: %d, порог %.0f%%).", rate*100, e.o.ErrWindow, n, e.o.ErrThreshold*100),
			})
		}
	}
}

// checkAllDown: все известные агенты down. Агенты, которых ещё ни разу не
// опросили, не считаются упавшими (иначе ложный алерт на старте).
func (e *Evaluator) checkAllDown(ctx context.Context, states []agents.State) {
	all := len(states) > 0
	for _, s := range states {
		if s.Up || (s.LastSeen.IsZero() && s.ConsecutiveFails == 0) {
			all = false
			break
		}
	}
	e.set(ctx, all, Alert{
		Type: AllAgentsDown, Severity: SeverityCritical,
		Title: "Все агенты недоступны",
		Text:  "Нет ни одного здорового агента: прокси не может отправлять запросы в Telegram.",
	})
}

// ReportIngressCert вызывается подсистемой TLS при загрузке/проверке
// сертификата входа: err — отказ валидации (остаётся старый сертификат).
func (e *Evaluator) ReportIngressCert(ctx context.Context, notAfter time.Time, err error) {
	invalid := Alert{
		Type: IngressCertInvalid, Severity: SeverityCritical,
		Title: "Новый сертификат входа не принят",
	}
	if err != nil {
		invalid.Text = "Причина: " + redact.String(err.Error()) + ". Используется предыдущий сертификат."
	}
	e.set(ctx, err != nil, invalid)
	if notAfter.IsZero() {
		return
	}
	left := notAfter.Sub(e.o.Clock())
	e.set(ctx, left < e.o.CertWarn, Alert{
		Type: IngressCertExpiring, Severity: SeverityWarning,
		Title: "Сертификат входа истекает",
		Text:  fmt.Sprintf("Действует до %s (осталось %s).", notAfter.UTC().Format("2006-01-02 15:04"), humanLeft(left)),
	})
}

// LoginLockout — блокировка входа после серии неудач (M4-T2).
func (e *Evaluator) LoginLockout(ctx context.Context, user, ip string) {
	e.fire(ctx, Alert{
		Type: LoginLockout, Key: AlertKey(LoginLockout, user), Severity: SeverityWarning,
		Title: fmt.Sprintf("Блокировка входа: %s", user),
		Text:  fmt.Sprintf("Слишком много неудачных попыток с %s, вход закрыт на 15 минут.", ip),
	})
}

// HostKeyMismatch — SSH host key агента не совпал с закреплённым (M5).
func (e *Evaluator) HostKeyMismatch(ctx context.Context, agentID, host string) {
	e.fire(ctx, Alert{
		Type: HostKeyMismatch, AgentID: agentID, Severity: SeverityCritical,
		Title: fmt.Sprintf("Host key агента %s изменился", agentID),
		Text:  fmt.Sprintf("Ключ хоста %s не совпал с закреплённым. Возможна подмена; установка остановлена.", host),
	})
}

// AgentEnrolled — новый агент подключён по enrollment-токену.
func (e *Evaluator) AgentEnrolled(ctx context.Context, agentID string) {
	e.fire(ctx, Alert{
		Type: AgentEnrolled, AgentID: agentID, Severity: SeverityInfo,
		Title: fmt.Sprintf("Подключён новый агент %s", agentID),
		Text:  "Агент зарегистрирован через enrollment. Если это не вы — отзовите его в разделе «Агенты».",
	})
}

// RolloutFailed — раскатка версии остановлена из-за провала обновления агента (M6-T4).
func (e *Evaluator) RolloutFailed(ctx context.Context, agentID, version, reason string) {
	e.fire(ctx, Alert{
		Type: RolloutFailed, AgentID: agentID, Severity: SeverityCritical,
		Title: fmt.Sprintf("Раскатка %s остановлена на агенте %s", version, agentID),
		Text:  fmt.Sprintf("Обновление агента не прошло: %s. Остальные агенты не тронуты; агент откатывается на прежнюю версию сам.", reason),
	})
}

// autoBanListMax — сколько адресов перечислять в одном сообщении об автобане.
const autoBanListMax = 10

// AutoBans — пачка автобанов за интервал агрегации (internal/server/ban.Digest): одно сообщение
// на пачку, чтобы скан из ботнета не превратился в поток алертов.
func (e *Evaluator) AutoBans(ctx context.Context, bans []store.Ban) {
	if len(bans) == 0 {
		return
	}
	var b strings.Builder
	for i, x := range bans {
		if i == autoBanListMax {
			fmt.Fprintf(&b, "… и ещё %d\n", len(bans)-autoBanListMax)
			break
		}
		until := "бессрочно"
		if x.ExpiresAt != nil {
			until = "до " + x.ExpiresAt.UTC().Format("2006-01-02 15:04") + " UTC"
		}
		fmt.Fprintf(&b, "%s — %s (уровень %d)\n", strings.TrimSuffix(x.Prefix.String(), "/32"), until, x.Level+1)
	}
	title := "Автобан IP: 1 адрес"
	if len(bans) > 1 {
		title = fmt.Sprintf("Автобан IP: %d адресов", len(bans))
	}
	now := e.o.Clock()
	e.fire(ctx, Alert{
		Type: IPAutoBan, Key: AlertKey(IPAutoBan, strconv.FormatInt(now.UnixNano(), 10)), Severity: SeverityWarning,
		Title: title, Text: strings.TrimRight(b.String(), "\n"), At: now,
	})
}

func humanLeft(d time.Duration) string {
	if d <= 0 {
		return "уже истёк"
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%d ч", int(d.Hours()))
	}
	return fmt.Sprintf("%d дн", int(d.Hours()/24))
}
