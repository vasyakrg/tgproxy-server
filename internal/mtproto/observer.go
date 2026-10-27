package mtproto

import (
	"net/netip"
	"sync"
	"time"
)

// MetricsRecorder — приёмник серверных метрик MTProto (реализуется *metrics.Server).
// Байты по агентам считает upstream-conn (там известен агент), не Observer.
type MetricsRecorder interface {
	MTProtoConnection(secret, result string)
	MTProtoSession(d time.Duration)
	MTProtoHandshakeFailure(reason string)
	MTProtoFallthrough()
}

// SecretNamer переводит id секрета в имя для метки secret. Ключи и префиксы в
// метки не попадают.
type SecretNamer interface {
	SecretName(id int64) (string, bool)
}

// SecretNamerFunc — функциональный адаптер SecretNamer.
type SecretNamerFunc func(id int64) (string, bool)

// SecretName реализует SecretNamer.
func (f SecretNamerFunc) SecretName(id int64) (string, bool) { return f(id) }

const unknownSecret = "unknown"

type obsKey struct {
	secretID int64
	streamID string
}

type obsSession struct {
	started   time.Time
	connected bool
}

// MetricsObserver — Observer, обновляющий метрики: connections_total{secret,result}
// (ok — достигнут DC, closed — закрыто до DC) и session_duration_seconds.
type MetricsObserver struct {
	rec   MetricsRecorder
	names SecretNamer
	now   func() time.Time

	mu     sync.Mutex
	live   map[obsKey]*obsSession
	active map[int64]int // активные соединения по id секрета
}

// NewMetricsObserver создаёт Observer метрик. names может быть nil (метка "unknown").
func NewMetricsObserver(rec MetricsRecorder, names SecretNamer) *MetricsObserver {
	return &MetricsObserver{rec: rec, names: names, now: time.Now, live: make(map[obsKey]*obsSession), active: make(map[int64]int)}
}

func (o *MetricsObserver) name(id int64) string {
	if o.names != nil {
		if n, ok := o.names.SecretName(id); ok && n != "" {
			return n
		}
	}
	return unknownSecret
}

// Start — Observer.
func (o *MetricsObserver) Start(secretID int64, streamID string, _ netip.Addr) {
	o.mu.Lock()
	k := obsKey{secretID, streamID}
	if _, dup := o.live[k]; !dup {
		o.active[secretID]++
	}
	o.live[k] = &obsSession{started: o.now()}
	o.mu.Unlock()
}

// ConnectedToDC — Observer: соединение считается успешным.
func (o *MetricsObserver) ConnectedToDC(secretID int64, streamID string, _ int) {
	k := obsKey{secretID, streamID}
	o.mu.Lock()
	s := o.live[k]
	first := s != nil && !s.connected
	if first {
		s.connected = true
	}
	o.mu.Unlock()
	if first {
		o.rec.MTProtoConnection(o.name(secretID), "ok")
	}
}

// Traffic — Observer: байты считает upstream-conn по агентам.
func (o *MetricsObserver) Traffic(int64, string, uint, bool) {}

// Finish — Observer.
func (o *MetricsObserver) Finish(secretID int64, streamID string) {
	k := obsKey{secretID, streamID}
	o.mu.Lock()
	s := o.live[k]
	delete(o.live, k)
	if s != nil {
		if o.active[secretID]--; o.active[secretID] <= 0 {
			delete(o.active, secretID)
		}
	}
	o.mu.Unlock()
	if s == nil {
		return
	}
	if !s.connected {
		o.rec.MTProtoConnection(o.name(secretID), "closed")
	}
	o.rec.MTProtoSession(o.now().Sub(s.started))
}

// Active возвращает число активных соединений секрета с данным id.
func (o *MetricsObserver) Active(secretID int64) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.active[secretID]
}

// Reject учитывает отказ рукопожатия. reason — причина mux (conn_limit,
// handshake_timeout, bad_record); handshake_timeout → timeout.
func (o *MetricsObserver) Reject(reason string) {
	if reason == "handshake_timeout" {
		reason = "timeout"
	}
	o.rec.MTProtoHandshakeFailure(reason)
}

// Fallthrough учитывает соединение, отданное TLS-сайту.
func (o *MetricsObserver) Fallthrough() { o.rec.MTProtoFallthrough() }

// RejectHook адаптирует Reject к mux.Hooks.OnReject: mtproto.RejectHook[mux.Reason](obs).
func RejectHook[R ~string](o *MetricsObserver) func(netip.Addr, R) {
	return func(_ netip.Addr, r R) { o.Reject(string(r)) }
}

// multiObserver вызывает наблюдателей по порядку.
type multiObserver []Observer

// MultiObserver объединяет наблюдателей (например, MetricsObserver и Journal);
// nil-элементы пропускаются.
func MultiObserver(obs ...Observer) Observer {
	var m multiObserver
	for _, o := range obs {
		if o != nil {
			m = append(m, o)
		}
	}
	switch len(m) {
	case 0:
		return nil
	case 1:
		return m[0]
	}
	return m
}

func (m multiObserver) Start(id int64, s string, ip netip.Addr) {
	for _, o := range m {
		o.Start(id, s, ip)
	}
}

func (m multiObserver) ConnectedToDC(id int64, s string, dc int) {
	for _, o := range m {
		o.ConnectedToDC(id, s, dc)
	}
}

func (m multiObserver) Traffic(id int64, s string, n uint, fromTelegram bool) {
	for _, o := range m {
		o.Traffic(id, s, n, fromTelegram)
	}
}

func (m multiObserver) Finish(id int64, s string) {
	for _, o := range m {
		o.Finish(id, s)
	}
}
