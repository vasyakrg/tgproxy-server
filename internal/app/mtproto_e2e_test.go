package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/probe"
)

const mtDomain = "ing.test" // SAN тестового сертификата входа (writeIngressPair)

// mtOpts — параметры стенда MTProto.
type mtOpts struct {
	agents    int             // число агентов (по умолчанию 1: "local", "a2"…)
	disabled  map[string]bool // агенты с mtproto.enabled=false
	dedicated bool            // отдельный листенер MTProto
	maxPerIP  int             // mtproto.max_conns_per_ip (0 — 1000)
}

type mtEnv struct {
	*e2e
	dcs    map[string]*probe.FakeDC // fake-DC по id агента
	mtAddr string                   // куда ходит MTProto-клиент
	proxy  string                   // адрес листенера Bot API
	httpc  *http.Client
}

func newMTEnv(t *testing.T, o mtOpts) *mtEnv {
	t.Helper()
	n := max(o.agents, 1)
	ids := []string{"local"}
	for i := 2; i <= n; i++ {
		ids = append(ids, "a"+strconv.Itoa(i))
	}
	m := &mtEnv{dcs: map[string]*probe.FakeDC{}}
	dcAddr := map[string]netip.AddrPort{}
	for _, id := range ids {
		d, addr, err := probe.NewFakeDC()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		m.dcs[id] = d
		dcAddr[id] = netip.MustParseAddrPort(addr)
	}
	var dedLn net.Listener
	if o.dedicated {
		dedLn = listen(t)
		m.mtAddr = dedLn.Addr().String()
	}
	perIP := o.maxPerIP
	if perIP == 0 {
		perIP = 1000
	}
	m.e2e = newE2E(t, e2eOpts{
		agents: n,
		mut: func(c *config.ServerConfig) {
			cf, kf := writeIngressPair(t, t.TempDir(), 1)
			c.TLS = config.IngressTLS{Mode: config.TLSModeFiles, CertFile: cf, KeyFile: kf}
			c.MTProto.Enabled = true
			c.MTProto.FrontingDomain = mtDomain
			c.MTProto.MaxConnsPerIP = perIP
			if o.dedicated {
				c.MTProto.Listen = "127.0.0.1:0"
			}
		},
		agentMut: func(id string, c *config.AgentConfig) {
			c.MTProto.Enabled = !o.disabled[id]
			c.MTProto.DCProbeInterval = time.Second
			c.OverrideMTProtoDCs(map[int][]netip.AddrPort{2: {dcAddr[id]}})
		},
		sopt: func(so *ServerOptions) {
			if dedLn != nil {
				so.MTProtoListener = dedLn
			}
		},
	})
	// newE2E строит proxyURL как http://…: листенер теперь TLS.
	m.proxy = strings.TrimPrefix(m.proxyURL, "http://")
	if m.mtAddr == "" {
		m.mtAddr = m.proxy
	}
	m.httpc = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: mtDomain}, //nolint:gosec // тестовый самоподписанный сертификат
			MaxIdleConnsPerHost: 64,
		},
	}
	t.Cleanup(m.httpc.CloseIdleConnections)
	return m
}

// newSecret создаёт секрет в store (ключ запечатывается KEK под id строки).
func (m *mtEnv) newSecret(name string) (id int64, key [16]byte) {
	m.t.Helper()
	if _, err := rand.Read(key[:]); err != nil {
		m.t.Fatal(err)
	}
	kek := m.srv.mt.kek
	s, err := m.srv.st.MTProtoSecrets().Create(context.Background(), name, func(id int64) ([]byte, error) {
		return kek.Seal(key[:], []byte("mtproto/"+strconv.FormatInt(id, 10)))
	}, hex.EncodeToString(key[:4]), nil, 0)
	if err != nil {
		m.t.Fatal(err)
	}
	return s.ID, key
}

// probeOK ждёт (подхват секрета Manager'ом и capability агентов), пока probe
// не пройдёт до fake-DC.
func (m *mtEnv) probeOK(key [16]byte) {
	m.t.Helper()
	var last error
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		res, err := probe.Run(ctx, m.mtAddr, key, mtDomain)
		cancel()
		if err == nil && res.DCResponded {
			return
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	m.t.Fatalf("probe не прошёл: %v", last)
}

func (m *mtEnv) probeOnce(key [16]byte) (probe.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return probe.Run(ctx, m.mtAddr, key, mtDomain)
}

func (m *mtEnv) getMe() (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+m.proxy+"/bot"+testToken+"/getMe", nil)
	if err != nil {
		return 0, err
	}
	resp, err := m.httpc.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func totalAccepted(m *mtEnv) int {
	n := 0
	for _, d := range m.dcs {
		n += d.Accepted()
	}
	return n
}

func TestMTProtoProbeThroughServerAndAgent(t *testing.T) {
	for _, mode := range []string{"shared", "dedicated"} {
		t.Run(mode, func(t *testing.T) {
			m := newMTEnv(t, mtOpts{dedicated: mode == "dedicated"})
			_, key := m.newSecret("main")
			m.probeOK(key)
			if d := m.dcs["local"]; d.Answered() < 1 || d.LastDC() != probe.DefaultDC {
				t.Fatalf("fake-DC: answered=%d dc=%d", d.Answered(), d.LastDC())
			}
			if mode == "shared" {
				if code, err := m.getMe(); err != nil || code != http.StatusOK {
					t.Fatalf("Bot API на shared-листенере: code=%d err=%v", code, err)
				}
			}
		})
	}
}

// rawTLSGet — обычный TLS-клиент: сертификат и ответ прокси Bot API.
func (m *mtEnv) rawTLSGet(addr, path string) (cn string, code int) {
	m.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+path, nil)
	if err != nil {
		m.t.Fatal(err)
	}
	resp, err := m.httpc.Do(req)
	if err != nil {
		m.t.Fatalf("GET %s: %v", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.TLS.PeerCertificates[0].Subject.CommonName, resp.StatusCode
}

func TestMTProtoInvalidHMACGetsRealSite(t *testing.T) {
	for _, mode := range []string{"shared", "dedicated"} {
		t.Run(mode, func(t *testing.T) {
			m := newMTEnv(t, mtOpts{dedicated: mode == "dedicated"})
			_, key := m.newSecret("main")
			m.probeOK(key) // mux активен: секрет подхвачен
			before := totalAccepted(m)

			// Чужой ключ: FakeTLS не принят, а не рукопожатие MTProto.
			var bad [16]byte
			bad[0] = 0xAB
			if _, err := m.probeOnce(bad); err == nil {
				t.Fatal("probe с чужим ключом не должен проходить")
			}
			// Настоящий TLS-клиент (HMAC в random отсутствует) -> настоящий сертификат и ответ сайта.
			path := "/bot" + testToken + "/getMe"
			cn, code := m.rawTLSGet(m.mtAddr, path)
			if cn != mtDomain {
				t.Fatalf("cn = %q", cn)
			}
			if mode == "shared" && code != http.StatusOK {
				t.Fatalf("shared: ответ Bot API %d, want 200", code)
			}
			if mode == "dedicated" && code != http.StatusNotFound {
				t.Fatalf("dedicated: заглушка %d, want 404", code)
			}
			if after := totalAccepted(m); after != before {
				t.Fatalf("невалидные соединения дошли до DC: %d -> %d", before, after)
			}
		})
	}
}

func readFirstRecordType(c net.Conn) (byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var h [5]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return 0, err
	}
	return h[0], nil
}

func TestMTProtoReplayGoesToSite(t *testing.T) {
	m := newMTEnv(t, mtOpts{})
	_, key := m.newSecret("main")
	m.probeOK(key)
	accepted := totalAccepted(m)

	hello := probe.ClientHello(key, mtDomain, time.Now())
	send := func() byte {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", m.mtAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write(hello); err != nil {
			t.Fatal(err)
		}
		typ, err := readFirstRecordType(c)
		if err != nil {
			t.Fatalf("чтение ответа: %v", err)
		}
		return typ
	}
	if typ := send(); typ != 0x16 {
		t.Fatalf("первый ClientHello: тип записи %#x, want 0x16 (ServerHello FakeTLS)", typ)
	}
	// Повтор тех же байт: ServerHello mtg нет, отвечает TLS-сайт (alert на странный ClientHello).
	if typ := send(); typ != 0x15 {
		t.Fatalf("replay: тип записи %#x, want 0x15 (ответ настоящего TLS-сервера)", typ)
	}
	m.waitFor(5*time.Second, "OnReplay в логе", func() bool {
		return strings.Contains(m.logs.String(), "mtproto: replayed ClientHello")
	})
	if got := totalAccepted(m); got != accepted {
		t.Fatalf("replay дошёл до DC: %d -> %d", accepted, got)
	}
	// настоящий клиент по-прежнему обслуживается
	if res, err := m.probeOnce(key); err != nil || !res.DCResponded {
		t.Fatalf("probe после replay: %v", err)
	}
}

func TestMTProtoRevokeDropsConnection(t *testing.T) {
	m := newMTEnv(t, mtOpts{})
	id, key := m.newSecret("main")
	m.probeOK(key)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := probe.Dial(ctx, m.mtAddr, key, mtDomain, probe.DefaultDC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Exchange(5 * time.Second); err != nil {
		t.Fatalf("обмен до отзыва: %v", err)
	}
	dropped := make(chan time.Time, 1)
	go func() {
		for {
			if err := c.Exchange(5 * time.Second); err != nil {
				dropped <- time.Now()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	revokedAt := time.Now()
	if err := m.srv.st.MTProtoSecrets().Revoke(context.Background(), id, revokedAt); err != nil {
		t.Fatal(err)
	}
	select {
	case at := <-dropped:
		// ≤ интервал опроса версии (2 с) + запас на относительные задержки
		if d := at.Sub(revokedAt); d > 2*time.Second+1500*time.Millisecond {
			t.Fatalf("соединение разорвано через %s, want ≤ 2s + poll", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("соединение не разорвано после отзыва секрета")
	}
	// отозванный секрет больше не принимается
	if _, err := m.probeOnce(key); err == nil {
		t.Fatal("отозванный секрет принят")
	}
}

func (m *mtEnv) dcUp(agentID string, dc int) (known, up bool) {
	for _, st := range m.srv.reg.List() {
		if st.Agent.ID != agentID {
			continue
		}
		_, dcs := st.MTProtoView()
		s, ok := dcs[dc]
		return ok, s.Up
	}
	return false, false
}

func TestMTProtoDCDownFailsOverToOtherAgent(t *testing.T) {
	m := newMTEnv(t, mtOpts{agents: 2})
	_, key := m.newSecret("main")
	m.probeOK(key)
	m.waitFor(10*time.Second, "DC обоих агентов up", func() bool {
		k1, u1 := m.dcUp("local", 2)
		k2, u2 := m.dcUp("a2", 2)
		return k1 && u1 && k2 && u2
	})

	_ = m.dcs["local"].Close() // DC агента A недоступен
	m.waitFor(10*time.Second, "DC агента local down", func() bool {
		known, up := m.dcUp("local", 2)
		return known && !up
	})
	if _, up := m.dcUp("a2", 2); !up {
		t.Fatal("DC агента a2 должен остаться up")
	}
	before := m.dcs["a2"].Answered()
	const n = 10
	for i := range n {
		if res, err := m.probeOnce(key); err != nil || !res.DCResponded {
			t.Fatalf("probe #%d при DC down на одном агенте: %v", i, err)
		}
	}
	if got := m.dcs["a2"].Answered() - before; got < n {
		t.Fatalf("через a2 прошло %d из %d проб", got, n)
	}
}

func TestMTProtoAgentWithoutCapabilityUnused(t *testing.T) {
	m := newMTEnv(t, mtOpts{agents: 2, disabled: map[string]bool{"local": true}})
	_, key := m.newSecret("main")
	m.probeOK(key)
	m.waitFor(5*time.Second, "capability видна серверу", func() bool {
		for _, st := range m.srv.reg.List() {
			c, _ := st.MTProtoView()
			if st.Agent.ID == "local" && c {
				return false
			}
			if st.Agent.ID == "a2" && !c {
				return false
			}
		}
		return true
	})
	for i := range 12 {
		if res, err := m.probeOnce(key); err != nil || !res.DCResponded {
			t.Fatalf("probe #%d: %v", i, err)
		}
	}
	if n := m.dcs["local"].Accepted(); n != 0 {
		t.Fatalf("агент без capability получил %d соединений к DC", n)
	}
	if m.dcs["a2"].Answered() < 12 {
		t.Fatalf("a2 ответил %d раз", m.dcs["a2"].Answered())
	}
}

func TestMTProtoNoCapableAgentsFallsThrough(t *testing.T) {
	m := newMTEnv(t, mtOpts{disabled: map[string]bool{"local": true}})
	_, key := m.newSecret("main")
	// ждём подхвата секрета Manager'ом (≤2 с), затем проверяем отказ
	time.Sleep(3 * time.Second)
	if _, err := m.probeOnce(key); err == nil {
		t.Fatal("без capable-агентов probe проходить не должен")
	}
	if cn, code := m.rawTLSGet(m.mtAddr, "/bot"+testToken+"/getMe"); cn != mtDomain || code != http.StatusOK {
		t.Fatalf("fallthrough: cn=%q code=%d", cn, code)
	}
	if n := m.dcs["local"].Accepted(); n != 0 {
		t.Fatalf("DC получил %d соединений", n)
	}
}

func p95(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[len(s)*95/100]
}

// sampleGetMe собирает задержки getMe через Bot API: workers параллельно, n запросов всего.
func (m *mtEnv) sampleGetMe(n, workers int) []time.Duration {
	m.t.Helper()
	var (
		mu   sync.Mutex
		out  []time.Duration
		next atomic.Int64
		wg   sync.WaitGroup
	)
	for range workers {
		wg.Go(func() {
			for next.Add(1) <= int64(n) {
				start := time.Now()
				code, err := m.getMe()
				d := time.Since(start)
				if err != nil || code != http.StatusOK {
					m.t.Errorf("getMe: code=%d err=%v", code, err)
					return
				}
				mu.Lock()
				out = append(out, d)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return out
}

// TestMTProtoBotAPIUnaffectedByMTProtoStreams: p95 getMe с 200 параллельными
// MTProto-стримами не растёт более чем вдвое (с абсолютным полом шума 20 мс:
// на loopback базовый p95 — единицы миллисекунд).
func TestMTProtoBotAPIUnaffectedByMTProtoStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("нагрузочный сценарий пропущен в -short")
	}
	const streams = 200
	m := newMTEnv(t, mtOpts{})
	_, key := m.newSecret("main")
	m.probeOK(key)

	m.sampleGetMe(100, 8) // прогрев
	base := p95(m.sampleGetMe(400, 8))

	ctx, cancel := context.WithCancel(context.Background())
	var (
		wg     sync.WaitGroup
		opened atomic.Int64
		failed atomic.Int64
		sem    = make(chan struct{}, 25)
	)
	for range streams {
		wg.Go(func() {
			sem <- struct{}{}
			dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
			c, err := probe.Dial(dctx, m.mtAddr, key, mtDomain, probe.DefaultDC)
			dcancel()
			<-sem
			if err != nil {
				failed.Add(1)
				return
			}
			defer func() { _ = c.Close() }()
			opened.Add(1)
			for ctx.Err() == nil {
				if err := c.Exchange(10 * time.Second); err != nil {
					if ctx.Err() == nil {
						failed.Add(1)
					}
					return
				}
				time.Sleep(25 * time.Millisecond)
			}
		})
	}
	m.waitFor(30*time.Second, "200 MTProto-стримов", func() bool { return opened.Load()+failed.Load() >= streams })
	if failed.Load() != 0 {
		cancel()
		wg.Wait()
		t.Fatalf("не открылось/оборвалось стримов: %d", failed.Load())
	}
	loaded := p95(m.sampleGetMe(400, 8))
	cancel()
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("оборвалось стримов под нагрузкой: %d", failed.Load())
	}
	limit := max(2*base, base+20*time.Millisecond)
	if m.dcs["local"].Accepted() < streams {
		t.Fatalf("до fake-DC дошло %d стримов из %d", m.dcs["local"].Accepted(), streams)
	}
	t.Logf("p95 getMe: base=%s loaded=%s limit=%s", base, loaded, limit)
	if loaded > limit {
		t.Fatalf("p95 getMe вырос: base=%s loaded=%s (limit %s)", base, loaded, limit)
	}
}
