package router

import (
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Описания финальных ответов политики ретраев.
const (
	// DescDeliveryUnknown — запрос мог дойти до Telegram, повторять нельзя.
	DescDeliveryUnknown = "tgproxy: delivery unknown"
	// DescUpstreamUnavailable — попытки исчерпаны, запрос в Telegram не ушёл
	// или метод идемпотентен.
	DescUpstreamUnavailable = "tgproxy: upstream unavailable"
	// DescCanceled — клиент оборвал запрос.
	DescCanceled = "tgproxy: request canceled"
)

// StatusClientClosed — nginx-style 499: клиент закрыл соединение.
const StatusClientClosed = 499

// backoff5xx — задержки перед повтором после 5xx Telegram по номеру попытки.
var backoff5xx = [...]time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}

// OutcomeKind — укрупнённый вид исхода попытки (не зависит от transport).
type OutcomeKind int

// Виды исхода.
const (
	// OutcomeOK — успешный ответ.
	OutcomeOK OutcomeKind = iota
	// OutcomeTelegram — ответ сформировал Telegram с ошибкой (Status >= 400).
	OutcomeTelegram
	// OutcomeTransport — отказ канала или агента.
	OutcomeTransport
)

// Outcome — вход политики. Строится адаптером FromTransport.
type Outcome struct {
	Kind     OutcomeKind
	Phase    string // tgapi.Phase*; для OutcomeTransport
	NotSent  bool   // запрос точно не ушёл в Telegram
	Canceled bool   // клиент отменил запрос
	Status   int    // HTTP-статус Telegram; для OutcomeTelegram
	Env      *tgapi.Envelope
}

// Final — ответ боту, формируемый самим tgproxy.
type Final struct {
	Status int
	Desc   string
}

// Decision — решение по результату попытки.
//
//   - Retry: повторить после Backoff (на другом агенте);
//   - Passthrough: отдать боту исходный ответ Telegram как есть;
//   - Final: ответить боту собственной ошибкой.
//
// TreatAsSuccess (только вместе с Passthrough) — ошибка Telegram на повторной
// попытке означает, что предыдущая попытка уже сработала («not modified»,
// «message to delete not found»): для метрик и логов это успех; боту уходит
// исходный ответ Telegram.
type Decision struct {
	Retry          bool
	Backoff        time.Duration
	Passthrough    bool
	TreatAsSuccess bool
	Final          *Final
}

// Decide — чистая функция политики ретраев (architecture §6).
// attempt нумеруется с 1; на attempt >= maxAttempts ретраев больше нет.
func Decide(class tgapi.Class, o Outcome, attempt, maxAttempts int) Decision {
	if o.Canceled {
		return final(StatusClientClosed, DescCanceled)
	}
	switch o.Kind {
	case OutcomeOK:
		return Decision{Passthrough: true}
	case OutcomeTelegram:
		return decideTelegram(class, o, attempt, maxAttempts)
	default:
		return decideTransport(class, o, attempt, maxAttempts)
	}
}

func decideTelegram(class tgapi.Class, o Outcome, attempt, maxAttempts int) Decision {
	switch {
	case o.Status >= http.StatusInternalServerError:
		if class == tgapi.Unsafe || attempt >= maxAttempts {
			return Decision{Passthrough: true}
		}
		return Decision{Retry: true, Backoff: backoffFor(attempt)}
	case o.Status == http.StatusBadRequest && attempt > 1 &&
		((class == tgapi.Semi && tgapi.IsNotModified(o.Env)) ||
			(class == tgapi.Safe && tgapi.IsNotFound(o.Env))):
		return Decision{Passthrough: true, TreatAsSuccess: true}
	default: // 429 и прочие 4xx
		return Decision{Passthrough: true}
	}
}

func decideTransport(class tgapi.Class, o Outcome, attempt, maxAttempts int) Decision {
	notSent := o.NotSent || tgapi.PhaseNotSent(o.Phase)
	if !notSent && class == tgapi.Unsafe {
		return final(http.StatusBadGateway, DescDeliveryUnknown)
	}
	if attempt >= maxAttempts {
		if !notSent && class != tgapi.Safe {
			return final(http.StatusBadGateway, DescDeliveryUnknown)
		}
		return final(http.StatusBadGateway, DescUpstreamUnavailable)
	}
	return Decision{Retry: true}
}

func final(status int, desc string) Decision {
	return Decision{Final: &Final{Status: status, Desc: desc}}
}

func backoffFor(attempt int) time.Duration {
	i := min(max(attempt, 1), len(backoff5xx)) - 1
	return backoff5xx[i]
}
