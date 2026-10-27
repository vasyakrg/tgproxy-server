package mtproto

import (
	"context"
	"net/netip"
	"sync"

	"github.com/9seconds/mtg/v2/mtglib"
)

// Observer получает события соединений с разметкой по секрету. Методы
// вызываются синхронно из горячего пути relay и не должны блокироваться.
type Observer interface {
	// Start — клиент принят инстансом (ip — адрес клиента).
	Start(secretID int64, streamID string, ip netip.Addr)
	// ConnectedToDC — соединение с DC установлено (DC уже после fallback mtg).
	ConnectedToDC(secretID int64, streamID string, dc int)
	// Traffic — байты на стороне Telegram: fromTelegram=true — от Telegram клиенту.
	Traffic(secretID int64, streamID string, n uint, fromTelegram bool)
	// Finish — соединение завершено (причины закрытия mtg не сообщает).
	Finish(secretID int64, streamID string)
}

// eventSink — mtglib.EventStream одного инстанса: события mtg не несут secret id,
// поэтому на каждый инстанс свой экземпляр с зашитым id. Адрес клиента для
// EventReplayAttack берётся из EventStart того же StreamID.
type eventSink struct {
	secretID int64
	obs      Observer
	onReplay func(netip.Addr)

	mu      sync.Mutex
	clients map[string]netip.Addr
}

func newEventSink(secretID int64, obs Observer, onReplay func(netip.Addr)) *eventSink {
	return &eventSink{secretID: secretID, obs: obs, onReplay: onReplay, clients: make(map[string]netip.Addr)}
}

func (e *eventSink) Send(_ context.Context, ev mtglib.Event) {
	switch v := ev.(type) {
	case mtglib.EventStart:
		ip, _ := netip.AddrFromSlice(v.RemoteIP)
		ip = ip.Unmap()
		e.mu.Lock()
		e.clients[v.StreamID()] = ip
		e.mu.Unlock()
		if e.obs != nil {
			e.obs.Start(e.secretID, v.StreamID(), ip)
		}
	case mtglib.EventConnectedToDC:
		if e.obs != nil {
			e.obs.ConnectedToDC(e.secretID, v.StreamID(), v.DC)
		}
	case mtglib.EventTraffic:
		if e.obs != nil {
			e.obs.Traffic(e.secretID, v.StreamID(), v.Traffic, v.IsRead)
		}
	case mtglib.EventReplayAttack:
		e.mu.Lock()
		ip := e.clients[v.StreamID()]
		e.mu.Unlock()
		if ip.IsValid() && e.onReplay != nil {
			e.onReplay(ip)
		}
	case mtglib.EventFinish:
		e.mu.Lock()
		delete(e.clients, v.StreamID())
		e.mu.Unlock()
		if e.obs != nil {
			e.obs.Finish(e.secretID, v.StreamID())
		}
	}
}
