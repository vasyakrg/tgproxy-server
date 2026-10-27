// Команда bench/mtproto — нагрузочный smoke MTProto (docs/plan-mtproto.md M13-T5).
//
// В одном процессе (127.0.0.1, без сети наружу) поднимаются: фейковый Telegram
// (Bot API), 2 dial-агента, каждый со своим fake-DC в режиме потокового эхо,
// и сервер с MTProto на shared-листенере. Затем:
//  1. базовый p95 getMe (vegeta, без MTProto-нагрузки);
//  2. N одновременных соединений probe (FakeTLS + obfuscated2 + эхо-пакет);
//  3. пропускная способность: часть соединений гонит эхо-трафик конвейером,
//     параллельно идёт getMe — p95 под нагрузкой против базового (порог < 2x);
//  4. закрытие всех соединений и проверка утечек горутин/fd.
//
// Запуск: go run ./scripts/bench/mtproto [-n 5000] (или make bench-mtproto).
// Код возврата 1 — цель не достигнута. Подробности — README.md рядом.
//
// RSS/fd/горутины измеряются у всего процесса (сервер, агенты, DC и клиенты
// вместе) — это верхняя оценка для сервера; число fd на соединение ~4 (клиент,
// вход сервера, выход агента, приём DC).
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/probe"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store/sqlite"
)

const (
	token  = "123456:" + "AAAAAAAAAAAAAAAAAA" + "AAAAAAAAAAAAAAAAA" // склеено: литерал не должен совпадать с шаблоном токена (secret scanning)
	tgBody = `{"ok":true,"result":{"id":123456,"is_bot":true,"username":"fake_bot"}}`
	domain = "ing.bench"

	dialPar = 50 // параллельных dial: backlog listen на macOS 128 (kern.ipc.somaxconn), больше — RST на SYN
)

type options struct {
	n          int
	bulk       int
	payload    int
	window     int
	dur        time.Duration
	rate       int
	targetMbit float64
	maxP95x    float64
	cpuProfile string
	memProfile string
}

func main() {
	var o options
	flag.IntVar(&o.n, "n", 5000, "число одновременных MTProto-соединений")
	flag.IntVar(&o.bulk, "bulk", 16, "сколько из них гонят эхо-трафик")
	flag.IntVar(&o.payload, "payload", 16<<10, "размер пакета эхо, байт (<= 65535)")
	flag.IntVar(&o.window, "window", 8, "пакетов в полёте на соединение")
	flag.DurationVar(&o.dur, "duration", 20*time.Second, "длительность фаз getMe и пропускной способности")
	flag.IntVar(&o.rate, "rate", 200, "getMe, запросов в секунду")
	flag.Float64Var(&o.targetMbit, "target-mbit", 200, "цель: суммарный эхо-трафик, Мбит/с (сумма обоих направлений)")
	flag.Float64Var(&o.maxP95x, "max-p95-ratio", 2, "порог: p95 getMe под нагрузкой / базовый")
	flag.StringVar(&o.cpuProfile, "cpuprofile", "", "файл pprof CPU на время фазы пропускной способности")
	flag.StringVar(&o.memProfile, "memprofile", "", "файл pprof heap (inuse) с N удерживаемыми соединениями")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "bench-mtproto:", err)
		os.Exit(1)
	}
}

// snap — состояние процесса в момент времени.
type snap struct {
	rssMB      float64
	heapMB     float64
	fds        int
	goroutines int
}

func take() snap {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := snap{heapMB: float64(ms.HeapInuse) / (1 << 20), fds: countFDs(), goroutines: runtime.NumGoroutine()}
	out, err := exec.CommandContext(context.Background(), "ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output() // #nosec G204 -- фиксированная команда, аргумент — собственный pid
	if err == nil {
		if kb, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); err == nil {
			s.rssMB = kb / 1024
		}
	}
	return s
}

func countFDs() int {
	for _, d := range []string{"/proc/self/fd", "/dev/fd"} {
		if ents, err := os.ReadDir(d); err == nil {
			return len(ents) - 1 // минус сам дескриптор каталога
		}
	}
	return -1
}

// raiseNOFILE поднимает мягкий лимит fd до максимально возможного и возвращает его.
func raiseNOFILE(want uint64) uint64 {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return 0
	}
	target := want
	if r.Max != 0 && uint64(r.Max) < target { //nolint:unconvert // тип Max зависит от платформы
		target = uint64(r.Max) //nolint:unconvert
	}
	for ; target > uint64(r.Cur); target -= target / 8 { //nolint:unconvert
		nr := syscall.Rlimit{Cur: target, Max: r.Max}
		if syscall.Setrlimit(syscall.RLIMIT_NOFILE, &nr) == nil {
			return target
		}
	}
	return uint64(r.Cur) //nolint:unconvert
}

func run(o options) error {
	if o.payload < 1 || o.payload > 65535 {
		return fmt.Errorf("payload %d вне 1..65535", o.payload)
	}
	if o.n < 1 {
		return fmt.Errorf("n %d < 1", o.n)
	}
	need := uint64(o.n)*4 + 2000
	lim := raiseNOFILE(need)
	if lim < need {
		maxN := int(min((lim-2000)/4, uint64(o.n))) //nolint:gosec // G115: результат не больше o.n (int)
		fmt.Printf("ВНИМАНИЕ: лимит fd %d < нужных %d; N снижен %d -> %d (macOS: sudo sysctl kern.maxfilesperproc=...; ulimit -n)\n", lim, need, o.n, maxN)
		if maxN < 1 {
			return fmt.Errorf("лимит fd %d слишком мал", lim)
		}
		o.n = maxN
	}
	o.bulk = min(o.bulk, o.n)

	st, err := startStand(o)
	if err != nil {
		return err
	}
	defer st.stop()

	// 1. базовый getMe
	_ = st.attack(o.rate, 5*time.Second) // прогрев пула keep-alive
	base := st.attack(o.rate, o.dur)
	st.httpc.CloseIdleConnections()
	settle()
	before := take()
	fmt.Printf("\n[1] базовый getMe: p50=%v p95=%v p99=%v success=%.2f%%\n", rd(base.Latencies.P50), rd(base.Latencies.P95), rd(base.Latencies.P99), base.Success*100)

	// 2. N соединений
	t0 := time.Now()
	conns, derr := st.openConns(o.n)
	fmt.Printf("[2] открыто %d/%d MTProto-соединений за %v (ошибок: %d)\n", len(conns), o.n, time.Since(t0).Round(time.Millisecond), len(derr))
	for i, e := range derr {
		if i >= 3 {
			break
		}
		fmt.Println("    ошибка:", e)
	}
	settle()
	held := take()
	fmt.Printf("    состояние с %d соединениями: RSS=%.0f МБ heap=%.0f МБ fd=%d горутин=%d\n", len(conns), held.rssMB, held.heapMB, held.fds, held.goroutines)

	if o.memProfile != "" {
		if f, err := os.Create(o.memProfile); err == nil {
			_ = pprof.Lookup("heap").WriteTo(f, 0)
			_ = f.Close()
		}
	}

	// 3. пропускная способность + getMe под нагрузкой
	if o.cpuProfile != "" {
		f, err := os.Create(o.cpuProfile)
		if err == nil {
			_ = pprof.StartCPUProfile(f)
		}
	}
	nb := min(o.bulk, len(conns))
	var wg sync.WaitGroup
	var sent, recv atomic.Int64
	var bulkErr atomic.Value
	ctx, cancel := context.WithTimeout(context.Background(), o.dur+5*time.Second)
	stopAt := time.Now().Add(o.dur)
	for _, c := range conns[:nb] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := bulk(ctx, c, o, stopAt, &sent, &recv); err != nil {
				bulkErr.Store(err)
			}
		}()
	}
	startBytes := time.Now()
	loaded := st.attack(o.rate, o.dur)
	wg.Wait()
	elapsed := time.Since(startBytes).Seconds()
	cancel()
	if o.cpuProfile != "" {
		pprof.StopCPUProfile()
	}
	peak := take()
	// payload учитывается в обе стороны (клиент -> DC и DC -> клиент)
	mbit := float64(sent.Load()+recv.Load()) * 8 / 1e6 / elapsed
	fmt.Printf("[3] эхо через 2 агента (%d соединений, пакет %d Б, окно %d): %.1f Мбит/с суммарно (%.1f в одну сторону), цель %.0f\n",
		nb, o.payload, o.window, mbit, float64(recv.Load())*8/1e6/elapsed, o.targetMbit)
	if e, _ := bulkErr.Load().(error); e != nil {
		fmt.Println("    ошибка эхо:", e)
	}
	ratio := float64(loaded.Latencies.P95) / float64(max(base.Latencies.P95, time.Microsecond))
	fmt.Printf("    getMe под нагрузкой: p50=%v p95=%v p99=%v success=%.2f%%; p95/базовый = %.2fx (порог < %.1fx)\n",
		rd(loaded.Latencies.P50), rd(loaded.Latencies.P95), rd(loaded.Latencies.P99), loaded.Success*100, ratio, o.maxP95x)
	fmt.Printf("    состояние под нагрузкой: RSS=%.0f МБ heap=%.0f МБ fd=%d горутин=%d\n", peak.rssMB, peak.heapMB, peak.fds, peak.goroutines)

	// 4. закрытие и утечки
	for _, c := range conns {
		_ = c.Close()
	}
	st.httpc.CloseIdleConnections()
	deadline := time.Now().Add(90 * time.Second)
	var after snap
	for {
		settle()
		after = take()
		if after.goroutines <= before.goroutines+before.goroutines/10+10 || time.Now().After(deadline) {
			break
		}
	}
	fmt.Printf("[4] после закрытия всех соединений: RSS=%.0f МБ fd=%d (было %d) горутин=%d (было %d)\n",
		after.rssMB, after.fds, before.fds, after.goroutines, before.goroutines)
	if os.Getenv("BENCH_GOROUTINES") != "" {
		_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 1)
	}

	fmt.Printf("\n%-34s %-18s %s\n", "метрика", "значение", "цель")
	row := func(name, val, goal string, ok bool) {
		mark := "OK  "
		if !ok {
			mark = "FAIL"
		}
		fmt.Printf("%-34s %-18s %-22s %s\n", name, val, goal, mark)
	}
	var failed []string
	check := func(name, val, goal string, ok bool) {
		row(name, val, goal, ok)
		if !ok {
			failed = append(failed, name)
		}
	}
	check("одновременных соединений", strconv.Itoa(len(conns)), ">= "+strconv.Itoa(o.n), len(conns) == o.n)
	check("пропускная способность, Мбит/с", fmt.Sprintf("%.1f", mbit), fmt.Sprintf(">= %.0f", o.targetMbit), mbit >= o.targetMbit && bulkErr.Load() == nil)
	check("getMe p95 нагр./база", fmt.Sprintf("%.2fx", ratio), fmt.Sprintf("< %.1fx", o.maxP95x), ratio < o.maxP95x && loaded.Success == 1)
	check("утечка горутин", fmt.Sprintf("%d -> %d", before.goroutines, after.goroutines), "без роста", after.goroutines <= before.goroutines+before.goroutines/10+10)
	check("утечка fd", fmt.Sprintf("%d -> %d", before.fds, after.fds), "без роста", after.fds <= before.fds+before.fds/10+20)
	fmt.Printf("RSS на соединение (idle): %.1f КБ; fd на соединение: %.1f\n",
		(held.rssMB-before.rssMB)*1024/float64(max(len(conns), 1)), float64(held.fds-before.fds)/float64(max(len(conns), 1)))
	if len(failed) > 0 {
		return fmt.Errorf("цели не достигнуты: %s", strings.Join(failed, ", "))
	}
	fmt.Println("\nOK: цели достигнуты")
	return nil
}

func rd(d time.Duration) time.Duration { return d.Round(10 * time.Microsecond) }

func settle() {
	time.Sleep(3 * time.Second)
	runtime.GC()
}

// bulk гонит эхо-пакеты конвейером: писатель держит в полёте не больше window пакетов.
func bulk(ctx context.Context, c *probe.Conn, o options, stopAt time.Time, sent, recv *atomic.Int64) error {
	payload := make([]byte, o.payload)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	credit := make(chan struct{}, o.window)
	for range o.window {
		credit <- struct{}{}
	}
	errc := make(chan error, 2)
	var inflight atomic.Int64
	done := make(chan struct{})
	go func() { // писатель
		for time.Now().Before(stopAt) {
			select {
			case <-credit:
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			}
			inflight.Add(1)
			if err := c.WritePacket(payload); err != nil {
				errc <- fmt.Errorf("write: %w", err)
				return
			}
			sent.Add(int64(len(payload)))
		}
		close(done)
		errc <- nil
	}()
	go func() { // читатель
		_ = c.SetDeadline(time.Now().Add(o.dur + 10*time.Second))
		for {
			select {
			case <-done:
				if inflight.Load() == 0 {
					errc <- nil
					return
				}
			default:
			}
			if time.Now().After(stopAt) && inflight.Load() == 0 {
				errc <- nil
				return
			}
			pkt, err := c.ReadPacket()
			if err != nil {
				errc <- fmt.Errorf("read: %w", err)
				return
			}
			if len(pkt) != len(payload) {
				errc <- fmt.Errorf("эхо: длина %d != %d", len(pkt), len(payload))
				return
			}
			inflight.Add(-1)
			recv.Add(int64(len(pkt)))
			select {
			case credit <- struct{}{}:
			default:
			}
		}
	}()
	e1, e2 := <-errc, <-errc
	_ = c.SetDeadline(time.Time{})
	return firstErr(e1, e2)
}

func firstErr(es ...error) error {
	for _, e := range es {
		if e != nil {
			return e
		}
	}
	return nil
}

// --- стенд ------------------------------------------------------------------

type stand struct {
	proxyAddr string
	key       [16]byte
	httpc     *http.Client
	stopFns   []func()
}

func (s *stand) stop() {
	for _, f := range slices.Backward(s.stopFns) {
		f()
	}
}

func (s *stand) attack(rate int, d time.Duration) vegeta.Metrics {
	at := vegeta.NewAttacker(vegeta.Client(s.httpc), vegeta.Timeout(10*time.Second), vegeta.Workers(64), vegeta.MaxWorkers(256))
	tgt := vegeta.NewStaticTargeter(vegeta.Target{Method: http.MethodGet, URL: "https://" + s.proxyAddr + "/bot" + token + "/getMe"})
	var m vegeta.Metrics
	for res := range at.Attack(tgt, vegeta.Rate{Freq: rate, Per: time.Second}, d, "getMe") {
		m.Add(res)
	}
	m.Close()
	at.Stop()
	return m
}

// openConns открывает n соединений (параллельно по dialPar) и проверяет каждое
// одним эхо-пакетом. Возвращает успешные и ошибки.
func (s *stand) openConns(n int) ([]*probe.Conn, []error) {
	var mu sync.Mutex
	var conns []*probe.Conn
	var errs []error
	sem := make(chan struct{}, dialPar)
	var wg sync.WaitGroup
	for range n {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c, err := probe.Dial(ctx, s.proxyAddr, s.key, domain, probe.DefaultDC)
			if err == nil {
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				if err = c.WritePacket([]byte("ping-ping-ping-ping")); err == nil {
					_, err = c.ReadPacket()
				}
				_ = c.SetDeadline(time.Time{})
				if err != nil {
					_ = c.Close()
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			conns = append(conns, c)
		}()
	}
	wg.Wait()
	return conns, errs
}

func listen() net.Listener {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	return ln
}

func startStand(o options) (*stand, error) {
	st := &stand{}
	tmp, err := os.MkdirTemp("", "tgproxy-bench-mt-")
	if err != nil {
		return nil, err
	}
	st.stopFns = append(st.stopFns, func() { _ = os.RemoveAll(tmp) })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tg := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+token+"/getMe" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, tgBody)
	}))
	st.stopFns = append(st.stopFns, tg.Close)
	upPool := x509.NewCertPool()
	upPool.AddCert(tg.Certificate())

	ids := []string{"a1", "a2"}
	pkiDir := filepath.Join(tmp, "pki")
	if err := os.Mkdir(pkiDir, 0o700); err != nil {
		return nil, err
	}
	if err := pki.DevInit(pkiDir, ids); err != nil {
		return nil, err
	}
	type ag struct {
		id, addr string
		cancel   context.CancelFunc
		done     chan struct{}
	}
	var ags []*ag
	for _, id := range ids {
		dc, dcAddr, err := probe.NewFakeDCEcho()
		if err != nil {
			return nil, err
		}
		st.stopFns = append(st.stopFns, func() { _ = dc.Close() })
		acfg := config.DefaultAgent()
		acfg.TLS = config.TLSFiles{
			CertFile: filepath.Join(pkiDir, pki.AgentCertFile(id)),
			KeyFile:  filepath.Join(pkiDir, pki.AgentKeyFile(id)),
			CAFile:   filepath.Join(pkiDir, pki.FileCACert),
		}
		acfg.DataDir = filepath.Join(tmp, "agent-"+id)
		if err := os.Mkdir(acfg.DataDir, 0o700); err != nil {
			return nil, err
		}
		acfg.Listen.Metrics = "127.0.0.1:0"
		acfg.MTProto.Enabled = true
		acfg.MTProto.MaxStreams = o.n + 1000
		acfg.MTProto.IdleTimeout = time.Hour
		acfg.MTProto.DCProbeInterval = time.Second
		acfg.OverrideMTProtoDCs(map[int][]netip.AddrPort{probe.DefaultDC: {netip.MustParseAddrPort(dcAddr)}})
		if err := acfg.OverrideTelegramAPIURL(tg.URL); err != nil {
			return nil, err
		}
		ln := listen()
		ctx, cancel := context.WithCancel(context.Background())
		a := &ag{id: id, addr: ln.Addr().String(), cancel: cancel, done: make(chan struct{})}
		ags = append(ags, a)
		go func() {
			defer close(a.done)
			_ = app.RunAgent(ctx, acfg, logger, app.AgentOptions{Agent: []agent.Option{agent.WithUpstreamRootCAs(upPool)}, Listener: ln})
		}()
	}
	st.stopFns = append(st.stopFns, func() {
		for _, a := range ags {
			a.cancel()
		}
		for _, a := range ags {
			<-a.done
		}
	})

	// сервер
	scfg := config.DefaultServer()
	scfg.Listen.Metrics = "127.0.0.1:0"
	scfg.Listen.Proxy = "127.0.0.1:0"
	for _, a := range ags {
		scfg.Agents = append(scfg.Agents, config.AgentEndpoint{ID: a.id, URL: "https://" + a.addr, Mode: config.AgentModeDial, Weight: 1})
	}
	scfg.AgentTLS = config.TLSFiles{
		CertFile: filepath.Join(pkiDir, pki.FileServerCert),
		KeyFile:  filepath.Join(pkiDir, pki.FileServerKey),
		CAFile:   filepath.Join(pkiDir, pki.FileCACert),
	}
	scfg.Store.SQLitePath = filepath.Join(tmp, "tgproxy.db")
	scfg.Buffer.TmpDir = filepath.Join(tmp, "buf")
	if err := os.Mkdir(scfg.Buffer.TmpDir, 0o700); err != nil {
		return nil, err
	}
	scfg.AccessRules = []config.AccessRule{{Name: "net", CIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	hash, err := auth.Hash("bench-password-0123456789", auth.DefaultHashParams())
	if err != nil {
		return nil, err
	}
	scfg.Auth.UsersFile = filepath.Join(tmp, "users.yml")
	users := fmt.Sprintf("users:\n  admin:\n    displayname: Bench\n    password: '%s'\n    telegram_id: 0\n", hash)
	if err := os.WriteFile(scfg.Auth.UsersFile, []byte(users), 0o600); err != nil {
		return nil, err
	}
	scfg.Auth.AllowPasswordOnly = true
	scfg.PKI.KEKFile = filepath.Join(tmp, "kek")
	if err := pki.GenerateKEK(scfg.PKI.KEKFile); err != nil {
		return nil, err
	}
	scfg.Server.PublicBaseURL = "https://127.0.0.1:8080"
	cf, kf, err := writeIngressPair(tmp)
	if err != nil {
		return nil, err
	}
	scfg.TLS = config.IngressTLS{Mode: config.TLSModeFiles, CertFile: cf, KeyFile: kf}
	scfg.MTProto.Enabled = true
	scfg.MTProto.FrontingDomain = domain
	scfg.MTProto.MaxConns = o.n + 1000
	scfg.MTProto.MaxConnsPerIP = o.n + 1000
	scfg.MTProto.MaxPendingHandshakes = 1024
	scfg.MTProto.IdleTimeout = time.Hour
	scfg.Ban.Enabled = false

	// секрет создаётся до старта сервера напрямую в SQLite (KEK тот же)
	if _, err := rand.Read(st.key[:]); err != nil {
		return nil, err
	}
	if err := seedSecret(scfg, st.key); err != nil {
		return nil, err
	}

	pln, adln := listen(), listen()
	srv, err := app.NewServer(context.Background(), scfg, logger, app.ServerOptions{
		ProxyListener: pln, AdminListener: adln, MetricsListener: listen(),
		AccessOptions: []access.Option{access.WithRefreshInterval(time.Second)},
		AgentOptions:  []agents.Option{agents.WithPollInterval(time.Second), agents.WithPollTimeout(time.Second)},
	})
	if err != nil {
		return nil, err
	}
	sctx, scancel := context.WithCancel(context.Background())
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Serve(sctx, pln, adln) }()
	st.stopFns = append(st.stopFns, func() {
		scancel()
		err := <-srvDone // ошибка Serve при остановке не интересна
		_ = err
	})

	st.proxyAddr = pln.Addr().String()
	st.httpc = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: domain}, //nolint:gosec // самоподписанный сертификат стенда
			MaxIdleConnsPerHost: 256,
		},
	}
	st.stopFns = append(st.stopFns, st.httpc.CloseIdleConnections)

	// готовность: getMe и MTProto-проба
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := probe.Dial(ctx, st.proxyAddr, st.key, domain, probe.DefaultDC)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if err = c.WritePacket([]byte("ready")); err == nil {
				_, err = c.ReadPacket()
			}
			_ = c.Close()
		}
		cancel()
		if err == nil {
			if st.attack(1, time.Second).Success == 1 {
				return st, nil
			}
			err = fmt.Errorf("getMe не отвечает")
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("стенд не готов: %w", last)
}

func seedSecret(scfg *config.ServerConfig, key [16]byte) error {
	ctx := context.Background()
	kek, err := pki.LoadKEK(scfg.PKI.KEKFile)
	if err != nil {
		return err
	}
	s, err := sqlite.Open(ctx, scfg.Store.SQLitePath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	_, err = s.MTProtoSecrets().Create(ctx, "bench", func(id int64) ([]byte, error) {
		return kek.Seal(key[:], []byte("mtproto/"+strconv.FormatInt(id, 10)))
	}, hex.EncodeToString(key[:4]), nil, 0)
	return err
}
