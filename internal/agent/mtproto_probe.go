package agent

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// probeJitter — доля интервала, на которую случайно сдвигается следующая проба
// (±), чтобы агенты флота не били в DC синхронно.
const probeJitter = 0.2

// dcProber — периодическая TCP-проба DC (docs/mtproto.md §5): connect к одному
// адресу каждого DC без отправки данных, тем же dialer'ом и dial-control, что и
// релей. Одна неудача -> up=false, одна удача -> up=true.
type dcProber struct {
	a        *Agent
	interval atomic.Int64 // time.Duration; меняется через PUT /_agent/config
	wake     chan struct{}
	jitter   func(d time.Duration) time.Duration // тесты подменяют

	mu      sync.Mutex
	state   map[int]transport.DCStatus
	running bool
}

func newDCProber(a *Agent) *dcProber {
	p := &dcProber{
		a:      a,
		wake:   make(chan struct{}, 1),
		state:  make(map[int]transport.DCStatus),
		jitter: randJitter,
	}
	p.interval.Store(int64(a.cfg.MTProto.DCProbeInterval))
	return p
}

func randJitter(d time.Duration) time.Duration {
	f := rand.Float64() //nolint:gosec // джиттер расписания, не криптография
	return time.Duration((f*2 - 1) * probeJitter * float64(d))
}

// SetDCProbeInterval меняет период проб на лету (PUT /_agent/config);
// значение вне config.MinDCProbeInterval..MaxDCProbeInterval отклоняется.
func (a *Agent) SetDCProbeInterval(d time.Duration) bool {
	if d < config.MinDCProbeInterval || d > config.MaxDCProbeInterval {
		return false
	}
	a.dcp.interval.Store(int64(d))
	select {
	case a.dcp.wake <- struct{}{}:
	default:
	}
	return true
}

// StartMTProtoProbe запускает фоновые пробы DC; no-op при mtproto.enabled=false
// или повторном вызове. Возвращаемая stop отменяет пробу и дожидается горутины;
// пробы также останавливаются по отмене ctx.
func (a *Agent) StartMTProtoProbe(ctx context.Context) (stop func()) {
	p := a.dcp
	p.mu.Lock()
	if !a.MTProtoEnabled() || p.running {
		p.mu.Unlock()
		return func() {}
	}
	p.running = true
	p.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.loop(ctx)
	}()
	return func() {
		cancel()
		<-done
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
	}
}

func (p *dcProber) loop(ctx context.Context) {
	p.probeAll(ctx)
	for {
		d := time.Duration(p.interval.Load())
		d += p.jitter(d)
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-p.wake:
			t.Stop() // интервал сменили — планируем заново
			continue
		case <-t.C:
		}
		p.probeAll(ctx)
	}
}

// dcs возвращает номера DC для проб: таблица-оверрайд либо вшитая.
func (p *dcProber) dcs() []int {
	r := p.a.mtp
	var out []int
	if r.override != nil {
		for dc := range r.override {
			if dc > 0 {
				out = append(out, dc)
			}
		}
		slices.Sort(out)
		return out
	}
	return tgapi.KnownDCs()
}

// probeAll пробует все DC параллельно и дожидается результатов.
func (p *dcProber) probeAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, dc := range p.dcs() {
		addrs := p.a.mtp.addrs(dc)
		if len(addrs) == 0 {
			continue
		}
		wg.Go(func() { p.probeOne(ctx, dc, addrs[:1]) })
	}
	wg.Wait()
}

func (p *dcProber) probeOne(ctx context.Context, dc int, addr []netip.AddrPort) {
	if ctx.Err() != nil {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, p.a.mtp.cfg.DialTimeout)
	defer cancel()
	start := time.Now()
	conn, err := p.a.mtp.dialFn(pctx, addr)
	rtt := time.Since(start)
	if ctx.Err() != nil {
		return // остановка, а не недоступность DC
	}
	st := transport.DCStatus{}
	if err == nil {
		_ = conn.Close()
		st.Up = true
		st.RTTMs = max(float64(rtt)/float64(time.Millisecond), 0.001)
	}
	p.mu.Lock()
	p.state[dc] = st
	p.mu.Unlock()
}

// snapshot возвращает копию состояния DC для /_agent/status.
func (p *dcProber) snapshot() map[string]transport.DCStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]transport.DCStatus, len(p.state))
	for dc, st := range p.state {
		out[strconv.Itoa(dc)] = st
	}
	return out
}
