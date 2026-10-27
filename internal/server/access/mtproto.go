package access

import (
	"net/netip"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// MTProtoErrorEvent строит запись журнала «Ошибки» для отказа на входе MTProto: фаза "mtproto",
// IP клиента и причина. Секрета (и его префикса) в записи нет.
func MTProtoErrorEvent(at time.Time, ip netip.Addr, reason Reason) store.ErrorEvent {
	ev := store.ErrorEvent{
		At: at, Phase: tgapi.PhaseMTProto, Outcome: store.OutcomeFailedToBot,
		Description: "mtproto denied: " + string(reason), Reason: string(reason),
	}
	if ip.IsValid() {
		ev.ClientIP = ip.String()
	}
	return ev
}
