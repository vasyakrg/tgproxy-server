package router

import (
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// FromTransport собирает вход политики из классификации транспорта.
// status и env — статус и разобранный конверт ответа Telegram (для
// transport.KindTelegramError; иначе игнорируются).
func FromTransport(o transport.Outcome, status int, env *tgapi.Envelope) Outcome {
	out := Outcome{Phase: o.Phase, NotSent: o.NotSent, Canceled: o.Canceled}
	switch o.Kind {
	case transport.KindOK:
		out.Kind = OutcomeOK
	case transport.KindTelegramError:
		out.Kind = OutcomeTelegram
		out.Status = status
		out.Env = env
	default:
		out.Kind = OutcomeTransport
	}
	return out
}
