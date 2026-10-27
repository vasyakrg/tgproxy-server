package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

func dcState(t *testing.T, a *Agent, dc string) transport.DCStatus {
	t.Helper()
	st, ok := a.dcp.snapshot()[dc]
	if !ok {
		t.Fatalf("нет состояния DC %s", dc)
	}
	return st
}

func TestProbeUpAndRTT(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	e.agent.dcp.probeAll(context.Background())
	st := dcState(t, e.agent, "2")
	if !st.Up || st.RTTMs <= 0 {
		t.Fatalf("DC 2: %+v, want up с rtt > 0", st)
	}
}

func TestProbeDownAfterOneFailureAndRecovers(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	p := e.agent.dcp
	var fail atomic.Bool
	realDial := e.agent.mtp.dialFn
	e.agent.mtp.dialFn = func(ctx context.Context, a []netip.AddrPort) (net.Conn, error) {
		if fail.Load() {
			return nil, errors.New("connection refused")
		}
		return realDial(ctx, a)
	}
	p.probeAll(context.Background())
	if !dcState(t, e.agent, "2").Up {
		t.Fatal("ожидали up")
	}
	fail.Store(true)
	p.probeAll(context.Background())
	if st := dcState(t, e.agent, "2"); st.Up || st.RTTMs != 0 {
		t.Fatalf("после одной неудачи: %+v, want down", st)
	}
	fail.Store(false)
	p.probeAll(context.Background())
	if !dcState(t, e.agent, "2").Up {
		t.Fatal("одна удачная проба должна вернуть up")
	}
}

func TestProbeRealUnreachableDC(t *testing.T) {
	addr := netip.MustParseAddrPort(closedAddr(t))
	e := newMTEnv(t, addr)
	e.agent.dcp.probeAll(context.Background())
	if dcState(t, e.agent, "2").Up {
		t.Fatal("закрытый порт не должен быть up")
	}
}

func TestProbeUsesOneAddressPerDC(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	e.cfg.OverrideMTProtoDCs(map[int][]netip.AddrPort{2: {dc.addr, netip.MustParseAddrPort("127.0.0.1:1")}})
	a, err := New(e.cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got atomic.Int32
	a.mtp.dialFn = func(_ context.Context, addrs []netip.AddrPort) (net.Conn, error) {
		got.Store(int32(len(addrs)))
		return nil, errors.New("x")
	}
	a.dcp.probeAll(context.Background())
	if got.Load() != 1 {
		t.Fatalf("проба передала %d адресов, want 1", got.Load())
	}
}

func TestProbeDefaultTableCoversKnownDCs(t *testing.T) {
	e, _ := newEnvNoAgent(t, http.NotFoundHandler())
	a, err := New(e.cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := a.dcp.dcs(), tgapi.KnownDCs(); !slices.Equal(got, want) || len(got) < 5 {
		t.Fatalf("dcs = %v, want %v", got, want)
	}
}

func TestProbeLifecycleNoLeak(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr, func(c *config.AgentConfig) { c.MTProto.DCProbeInterval = time.Second })
	e.agent.dcp.jitter = func(time.Duration) time.Duration { return 0 }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := e.agent.StartMTProtoProbe(ctx)
	waitFor(t, "first probe", func() bool { _, ok := e.agent.dcp.snapshot()["2"]; return ok })
	// повторный Start — no-op
	e.agent.StartMTProtoProbe(ctx)()
	stop()
	stop2 := e.agent.StartMTProtoProbe(ctx) // перезапуск после остановки
	stop2()

	// остановка по отмене ctx
	ctx2, cancel2 := context.WithCancel(context.Background())
	stop3 := e.agent.StartMTProtoProbe(ctx2)
	cancel2()
	stop3()
}

func TestProbePeriodicAndIntervalChange(t *testing.T) {
	var n atomic.Int32
	dc := newFakeDC(t, func(c net.Conn) { n.Add(1); holdDC(c) })
	e := newMTEnv(t, dc.addr)
	e.agent.dcp.jitter = func(time.Duration) time.Duration { return 0 }
	// интервал проверяется границами 1s: SetDCProbeInterval отклоняет мусор
	if e.agent.SetDCProbeInterval(time.Millisecond) || e.agent.SetDCProbeInterval(2*time.Hour) {
		t.Fatal("интервал вне границ принят")
	}
	// обход границ только внутри пакета: пробы должны идти повторно
	e.agent.dcp.interval.Store(int64(20 * time.Millisecond))
	stop := e.agent.StartMTProtoProbe(context.Background())
	defer stop()
	waitFor(t, "повторные пробы", func() bool { return n.Load() >= 3 })
	if !e.agent.SetDCProbeInterval(time.Hour) {
		t.Fatal("валидный интервал отклонён")
	}
	time.Sleep(100 * time.Millisecond)
	cur := n.Load()
	time.Sleep(100 * time.Millisecond)
	if n.Load() > cur+1 {
		t.Fatalf("после увеличения интервала пробы продолжаются: %d -> %d", cur, n.Load())
	}
}

func TestProbeDisabledNoop(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr, func(c *config.AgentConfig) { c.MTProto.Enabled = false })
	e.agent.StartMTProtoProbe(context.Background())()
	if len(e.agent.dcp.snapshot()) != 0 {
		t.Fatal("при enabled=false пробы не запускаются")
	}
}

func TestProbeJitterBounds(t *testing.T) {
	d := 10 * time.Second
	for range 1000 {
		if j := randJitter(d); j < -time.Duration(probeJitter*float64(d)) || j > time.Duration(probeJitter*float64(d)) {
			t.Fatalf("jitter %v вне границ", j)
		}
	}
}

func TestStatusCapabilitiesOnlyWhenEnabled(t *testing.T) {
	dc := newFakeDC(t, holdDC)
	e := newMTEnv(t, dc.addr)
	e.agent.dcp.probeAll(context.Background())
	st := readJSON(t, e.do(t, http.MethodGet, "/_agent/status", nil, nil)) //nolint:bodyclose // закрывается в readJSON
	caps, _ := st["capabilities"].([]any)
	if len(caps) != 1 || caps[0] != "mtproto/1" {
		t.Fatalf("capabilities = %v", st["capabilities"])
	}
	mt, _ := st["mtproto"].(map[string]any)
	dcs, _ := mt["dc"].(map[string]any)
	d2, _ := dcs["2"].(map[string]any)
	if mt == nil || mt["streams"] != float64(0) || d2["up"] != true || d2["rtt_ms"].(float64) <= 0 {
		t.Fatalf("mtproto = %v", st["mtproto"])
	}

	off := newMTEnv(t, dc.addr, func(c *config.AgentConfig) { c.MTProto.Enabled = false })
	st = readJSON(t, off.do(t, http.MethodGet, "/_agent/status", nil, nil)) //nolint:bodyclose // закрывается в readJSON
	if _, ok := st["capabilities"]; ok {
		t.Fatalf("capabilities при enabled=false: %v", st["capabilities"])
	}
	if _, ok := st["mtproto"]; ok {
		t.Fatalf("mtproto при enabled=false: %v", st["mtproto"])
	}
}

func TestConfigDCProbeInterval(t *testing.T) {
	r := newRevEnv(t, config.AgentModeDial, false)
	waitFor(t, "dial listener", func() bool { return portOpen(r.api) })
	put := func(body string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "https://"+r.api+"/_agent/config", strings.NewReader(body))
		resp, err := r.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for _, bad := range []string{`"abc"`, `"0s"`, `"100ms"`, `"2h"`} {
		if code := put(`{"mode":"dial","dc_probe_interval":` + bad + `}`); code != 422 {
			t.Errorf("%s: %d, want 422", bad, code)
		}
	}
	if got := time.Duration(r.agent.dcp.interval.Load()); got != r.cfg.MTProto.DCProbeInterval {
		t.Fatalf("интервал изменился при ошибках: %v", got)
	}
	if code := put(`{"mode":"dial","dc_probe_interval":"7s"}`); code != 200 {
		t.Fatalf("valid: %d", code)
	}
	if got := time.Duration(r.agent.dcp.interval.Load()); got != 7*time.Second {
		t.Fatalf("interval = %v, want 7s", got)
	}
	if code := put(`{"mode":"dial"}`); code != 200 {
		t.Fatalf("без поля: %d", code)
	}
	if got := time.Duration(r.agent.dcp.interval.Load()); got != 7*time.Second {
		t.Fatalf("интервал сброшен: %v", got)
	}
}
