// Package upstream реализует mtglib.Network: исходящие соединения mtg к DC
// Telegram идут не напрямую, а стримами через агентов.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/9seconds/mtg/v2/essentials"

	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// ErrUnknownAddress — адрес не принадлежит ни одному DC из таблицы.
var ErrUnknownAddress = errors.New("upstream: unknown telegram address")

// ErrNoAgent — агент выбран, но не резолвится в AgentRef.
var ErrNoAgent = errors.New("upstream: agent not resolvable")

// Lease — захваченный стрим на (agent, dc).
type Lease interface {
	Agent() balancer.AgentID
	Report(balancer.Result)
	Release()
}

// Picker выбирает агента для DC.
type Picker interface {
	Pick(ctx context.Context, dc int, exclude ...balancer.AgentID) (Lease, error)
}

// Streams открывает MTProto-стримы к DC через агента.
type Streams interface {
	OpenMTProto(ctx context.Context, agent transport.AgentRef, dc int) (net.Conn, error)
}

// Resolve превращает ID агента в ссылку для транспорта.
type Resolve func(balancer.AgentID) (transport.AgentRef, bool)

// KeyedPicker адаптирует *balancer.Keyed к Picker.
type KeyedPicker struct{ K *balancer.Keyed }

// Pick реализует Picker.
func (p KeyedPicker) Pick(ctx context.Context, dc int, exclude ...balancer.AgentID) (Lease, error) {
	l, err := p.K.Pick(ctx, dc, exclude...)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// Metrics — необязательный приёмник метрик стримов (реализуется *metrics.Server).
// Вызывается из горячего пути: реализация обязана быть быстрой и потокобезопасной.
type Metrics interface {
	MTProtoStreams(agent string, dc, delta int)
	MTProtoUpstreamError(agent string, dc int, phase string)
	// MTProtoBytes: in — клиент → Telegram, out — Telegram → клиент.
	MTProtoBytes(agent, direction string, n int)
}

// Фазы ошибок для Metrics.MTProtoUpstreamError.
const (
	phaseNoAgent   = "no_agent"
	phaseUnknownDC = "unknown_dc"
	phaseDial      = "dial"
	phaseTimeout   = "timeout"
)

// noAgentLabel — метка agent, когда агента выбрать не удалось.
const noAgentLabel = "none"

// Options — зависимости и параметры Network.
type Options struct {
	Picker      Picker
	Streams     Streams
	Resolve     Resolve
	DialTimeout time.Duration // 0 → 10 с
	// RetryMemory — сколько помнить агента, на котором недавно упало открытие
	// стрима к DC (0 → 5 с).
	RetryMemory time.Duration
	Now         func() time.Time
	Metrics     Metrics // nil — без метрик
}

// Network реализует mtglib.Network.
type Network struct {
	o      Options
	addrs  map[netip.AddrPort]int
	native *net.Dialer

	mu   sync.Mutex
	last map[int]failure
}

type failure struct {
	agent balancer.AgentID
	until time.Time
}

// New создаёт Network.
func New(o Options) (*Network, error) {
	if o.Picker == nil || o.Streams == nil || o.Resolve == nil {
		return nil, errors.New("upstream: Picker, Streams and Resolve are required")
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.RetryMemory <= 0 {
		o.RetryMemory = 5 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Metrics == nil {
		o.Metrics = noMetrics{}
	}
	return &Network{
		o: o, addrs: addrMap(), native: nativeDialer(o.DialTimeout),
		last: make(map[int]failure),
	}, nil
}

// Dial реализует mtglib.Network.
func (n *Network) Dial(network, address string) (essentials.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

// DialContext открывает стрим к DC через выбранного агента.
func (n *Network) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("upstream: unsupported network %q", network)
	}
	ap, err := parseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	dc, ok := n.addrs[ap]
	if !ok {
		n.o.Metrics.MTProtoUpstreamError(noAgentLabel, 0, phaseUnknownDC)
		return nil, fmt.Errorf("%w: %s", ErrUnknownAddress, address)
	}

	ctx, cancel := context.WithTimeout(ctx, n.o.DialTimeout)
	defer cancel()

	lease, err := n.pick(ctx, dc)
	if err != nil {
		n.o.Metrics.MTProtoUpstreamError(noAgentLabel, dc, phaseNoAgent)
		return nil, err
	}
	agent := lease.Agent()
	name := string(agent)
	ref, ok := n.o.Resolve(agent)
	if !ok {
		lease.Report(balancer.Result{TransportError: true})
		lease.Release()
		n.remember(dc, agent)
		n.o.Metrics.MTProtoUpstreamError(name, dc, phaseNoAgent)
		return nil, fmt.Errorf("%w: %s", ErrNoAgent, agent)
	}

	start := n.o.Now()
	conn, err := n.o.Streams.OpenMTProto(ctx, ref, dc)
	if err != nil {
		lease.Report(balancer.Result{
			TransportError: !errors.Is(err, context.Canceled),
			Canceled:       errors.Is(err, context.Canceled),
		})
		lease.Release()
		if !errors.Is(err, context.Canceled) {
			n.remember(dc, agent)
			phase := phaseDial
			if errors.Is(err, context.DeadlineExceeded) {
				phase = phaseTimeout
			}
			n.o.Metrics.MTProtoUpstreamError(name, dc, phase)
		}
		return nil, err
	}
	lease.Report(balancer.Result{Latency: n.o.Now().Sub(start)})
	n.o.Metrics.MTProtoStreams(name, dc, 1)
	return &leaseConn{Conn: conn, lease: lease, m: n.o.Metrics, agent: name, dc: dc}, nil
}

// pick выбирает агента, исключая недавно упавшего для этого DC. Mtg вызывает
// Dial последовательно для адресов DC одного клиента, поэтому «последний
// упавший агент» обычно и есть исключение в пределах соединения; если других
// кандидатов нет — берём любого.
func (n *Network) pick(ctx context.Context, dc int) (Lease, error) {
	n.mu.Lock()
	f, ok := n.last[dc]
	if ok && !n.o.Now().Before(f.until) {
		delete(n.last, dc)
		ok = false
	}
	n.mu.Unlock()
	if ok {
		if l, err := n.o.Picker.Pick(ctx, dc, f.agent); err == nil {
			return l, nil
		}
	}
	return n.o.Picker.Pick(ctx, dc)
}

func (n *Network) remember(dc int, agent balancer.AgentID) {
	n.mu.Lock()
	n.last[dc] = failure{agent: agent, until: n.o.Now().Add(n.o.RetryMemory)}
	n.mu.Unlock()
}

// MakeHTTPClient реализует mtglib.Network (нативный клиент).
func (n *Network) MakeHTTPClient(dial func(ctx context.Context, network, address string) (essentials.Conn, error)) *http.Client {
	return nativeHTTPClient(n.native, n.o.DialTimeout, dial)
}

// NativeDialer реализует mtglib.Network.
func (n *Network) NativeDialer() *net.Dialer { return n.native }

type noMetrics struct{}

func (noMetrics) MTProtoStreams(string, int, int)          {}
func (noMetrics) MTProtoUpstreamError(string, int, string) {}
func (noMetrics) MTProtoBytes(string, string, int)         {}
