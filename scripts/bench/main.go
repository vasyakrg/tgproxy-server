// Команда bench — нагрузочный smoke (docs/plan.md M7-T2): поднимает в процессе
// фейковый Telegram, два агента и сервер (без сети наружу, всё на 127.0.0.1),
// гонит vegeta по getMe и проверяет пороги: p95 overhead сервера, RSS, рост горутин.
//
// Запуск: go run ./scripts/bench  (или make bench). Код возврата 1 — порог нарушен.
//
// Замечание об RSS: сервер, агенты, фейк и генератор нагрузки живут в одном
// процессе, поэтому измеряется RSS всего процесса (ps -o rss) — это верхняя
// оценка RSS одного сервера.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"strconv"
	"strings"
	"sync"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/app"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
)

const (
	token  = "123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tgBody = `{"ok":true,"result":{"id":123456,"is_bot":true,"username":"fake_bot"}}`
)

type limits struct {
	overheadP95 time.Duration
	rssMB       float64
}

type scenario struct {
	delay       time.Duration
	direct, via vegeta.Metrics
	rssMaxMB    float64
	heapMB      float64
	gBefore     int
	gAfter      int
}

func main() {
	rate := flag.Int("rate", 500, "запросов в секунду")
	dur := flag.Duration("duration", 30*time.Second, "длительность каждой фазы")
	delays := flag.String("delays", "0s,5ms", "задержки ответа фейкового Telegram через запятую")
	lim := limits{}
	flag.DurationVar(&lim.overheadP95, "max-overhead-p95", 10*time.Millisecond, "порог p95 overhead")
	flag.Float64Var(&lim.rssMB, "max-rss-mb", 200, "порог RSS, МБ")
	flag.Parse()

	var failed []string
	for _, ds := range strings.Split(*delays, ",") {
		d, err := time.ParseDuration(strings.TrimSpace(ds))
		if err != nil {
			fatalf("bad delay %q: %v", ds, err)
		}
		sc, err := run(d, *rate, *dur)
		if err != nil {
			fatalf("scenario delay=%v: %v", d, err)
		}
		failed = append(failed, report(sc, lim, *rate, *dur)...)
	}
	if len(failed) > 0 {
		fmt.Println("\nFAIL:")
		for _, f := range failed {
			fmt.Println("  -", f)
		}
		os.Exit(1)
	}
	fmt.Println("\nOK: все пороги соблюдены")
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "bench: "+f+"\n", a...)
	os.Exit(2)
}

func report(sc *scenario, lim limits, rate int, dur time.Duration) []string {
	over := sc.via.Latencies.P95 - sc.direct.Latencies.P95
	fmt.Printf("\n== фейк Telegram: задержка %v, %d rps x %v ==\n", sc.delay, rate, dur)
	row := func(name string, m vegeta.Metrics) {
		fmt.Printf("%-22s p50=%-10v p95=%-10v p99=%-10v ok=%.2f%% errors=%d\n", name,
			m.Latencies.P50.Round(10*time.Microsecond), m.Latencies.P95.Round(10*time.Microsecond),
			m.Latencies.P99.Round(10*time.Microsecond), m.Success*100, len(m.Errors))
	}
	row("напрямую (агент)", sc.direct)
	row("через сервер", sc.via)
	fmt.Printf("overhead p95 сервера:  %v (порог < %v)\n", over.Round(10*time.Microsecond), lim.overheadP95)
	fmt.Printf("RSS процесса (макс):   %.1f МБ (порог < %.0f); HeapInuse макс %.1f МБ\n", sc.rssMaxMB, lim.rssMB, sc.heapMB)
	fmt.Printf("горутины до/после:     %d / %d\n", sc.gBefore, sc.gAfter)

	var f []string
	tag := fmt.Sprintf("delay=%v: ", sc.delay)
	if over >= lim.overheadP95 {
		f = append(f, tag+fmt.Sprintf("p95 overhead %v >= %v", over, lim.overheadP95))
	}
	if sc.rssMaxMB >= lim.rssMB {
		f = append(f, tag+fmt.Sprintf("RSS %.1f МБ >= %.0f", sc.rssMaxMB, lim.rssMB))
	}
	if sc.gAfter > sc.gBefore+sc.gBefore/10+10 {
		f = append(f, tag+fmt.Sprintf("рост горутин %d -> %d", sc.gBefore, sc.gAfter))
	}
	if len(sc.via.Errors) > 0 || sc.via.Success < 1 {
		f = append(f, tag+fmt.Sprintf("ошибки через сервер: success=%.4f, %v", sc.via.Success, sc.via.Errors))
	}
	if len(sc.direct.Errors) > 0 || sc.direct.Success < 1 {
		f = append(f, tag+fmt.Sprintf("ошибки напрямую: success=%.4f, %v", sc.direct.Success, sc.direct.Errors))
	}
	return f
}

func listen() net.Listener {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		fatalf("listen: %v", err)
	}
	return ln
}

func run(delay time.Duration, rate int, dur time.Duration) (*scenario, error) {
	tmp, err := os.MkdirTemp("", "tgproxy-bench-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// фейковый Telegram
	tg := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+token+"/getMe" {
			http.NotFound(w, r)
			return
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, tgBody)
	}))
	defer tg.Close()
	upPool := x509.NewCertPool()
	upPool.AddCert(tg.Certificate())

	// PKI + 2 агента
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
	stopAgents := func() {
		for _, a := range ags {
			a.cancel()
		}
		for _, a := range ags {
			<-a.done
		}
	}

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
		stopAgents()
		return nil, err
	}
	scfg.Auth.UsersFile = filepath.Join(tmp, "users.yml")
	users := fmt.Sprintf("users:\n  admin:\n    displayname: Bench\n    password: '%s'\n    telegram_id: 0\n", hash)
	if err := os.WriteFile(scfg.Auth.UsersFile, []byte(users), 0o600); err != nil {
		stopAgents()
		return nil, err
	}
	scfg.Auth.AllowPasswordOnly = true
	scfg.PKI.KEKFile = filepath.Join(tmp, "kek")
	if err := pki.GenerateKEK(scfg.PKI.KEKFile); err != nil {
		stopAgents()
		return nil, err
	}
	scfg.Server.PublicBaseURL = "http://127.0.0.1:8080"
	pln, adln := listen(), listen()
	srv, err := app.NewServer(context.Background(), scfg, logger, app.ServerOptions{
		ProxyListener: pln, AdminListener: adln, MetricsListener: listen(),
		AccessOptions: []access.Option{access.WithRefreshInterval(time.Second)},
		AgentOptions:  []agents.Option{agents.WithPollInterval(time.Second), agents.WithPollTimeout(time.Second)},
	})
	if err != nil {
		stopAgents()
		return nil, err
	}
	sctx, scancel := context.WithCancel(context.Background())
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Serve(sctx, pln, adln) }()
	stopAll := func() {
		scancel()
		<-srvDone //nolint:errcheck // канал значения не несёт ошибок для bench
		stopAgents()
	}
	defer stopAll()

	// клиент напрямую к агенту (mTLS как у сервера)
	cert, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, pki.FileServerCert), filepath.Join(pkiDir, pki.FileServerKey))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, pki.FileCACert)) // #nosec G304 -- путь собран из tmp-каталога
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	directTLS, err := pki.ClientTLSConfig(cert, caPool, pki.VerifyAgentPeer(caPool, ags[0].id))
	if err != nil {
		return nil, err
	}

	viaURL := "http://" + pln.Addr().String() + "/bot" + token + "/getMe"
	directURL := "https://" + ags[0].addr + "/tg/bot" + token + "/getMe"

	if err := waitOK(viaURL, 15*time.Second, nil); err != nil {
		return nil, fmt.Errorf("server not ready: %w", err)
	}
	directClient := &http.Client{Transport: &http.Transport{TLSClientConfig: directTLS, ForceAttemptHTTP2: true,
		MaxIdleConnsPerHost: 200}, Timeout: 10 * time.Second}
	if err := waitOK(directURL, 5*time.Second, directClient); err != nil {
		return nil, fmt.Errorf("agent not ready: %w", err)
	}

	viaClient := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 200}, Timeout: 10 * time.Second}
	sc := &scenario{delay: delay}
	// прогрев на полной нагрузке: пулы keep-alive соединений (агент -> Telegram,
	// сервер -> агент) выходят на рабочий размер, он и считается базой для горутин
	_ = attack(viaURL, viaClient, rate, 10*time.Second)
	_ = attack(directURL, directClient, rate, 10*time.Second)
	viaClient.CloseIdleConnections()
	directClient.CloseIdleConnections()
	settle()
	sc.gBefore = runtime.NumGoroutine()

	rss := &rssSampler{}
	stop := rss.start()
	// фазы разнесены по времени, чтобы не мешать друг другу
	sc.direct = attack(directURL, directClient, rate, dur)
	sc.via = attack(viaURL, viaClient, rate, dur)
	stop()
	sc.rssMaxMB = rss.maxMB()
	rss.mu.Lock()
	sc.heapMB = rss.heap
	rss.mu.Unlock()

	settle()
	viaClient.CloseIdleConnections()
	directClient.CloseIdleConnections()
	settle()
	sc.gAfter = runtime.NumGoroutine()
	if os.Getenv("BENCH_GOROUTINES") != "" {
		_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 1)
	}
	return sc, nil
}

// settle даёт idle-соединениям/таймерам время закрыться и сборщику мусора отработать.
func settle() {
	time.Sleep(3 * time.Second)
	runtime.GC()
}

func waitOK(u string, d time.Duration, c *http.Client) error {
	if c == nil {
		c = &http.Client{Timeout: 3 * time.Second}
	}
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		resp, err := c.Get(u) //nolint:noctx // bench: короткий опрос готовности
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return last
}

func attack(u string, c *http.Client, rate int, d time.Duration) vegeta.Metrics {
	opts := []func(*vegeta.Attacker){vegeta.Timeout(10 * time.Second), vegeta.Connections(200), vegeta.MaxConnections(200), vegeta.Workers(64)}
	if c != nil {
		opts = append(opts, vegeta.Client(c))
	}
	at := vegeta.NewAttacker(opts...)
	tgt := vegeta.NewStaticTargeter(vegeta.Target{Method: http.MethodGet, URL: u})
	var m vegeta.Metrics
	for res := range at.Attack(tgt, vegeta.Rate{Freq: rate, Per: time.Second}, d, "getMe") {
		m.Add(res)
	}
	m.Close()
	at.Stop()
	return m
}

// rssSampler раз в 500 мс снимает RSS текущего процесса через `ps -o rss=`
// (КБ; работает на macOS и Linux) и хранит максимум.
type rssSampler struct {
	mu   sync.Mutex
	max  float64
	heap float64 // макс HeapInuse, МБ (runtime.MemStats)
}

func (r *rssSampler) start() (stop func()) {
	done, fin := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(fin)
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			r.sample()
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	}()
	return func() { close(done); <-fin }
}

func (r *rssSampler) sample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.mu.Lock()
	r.heap = max(r.heap, float64(ms.HeapInuse)/(1<<20))
	r.mu.Unlock()
	out, err := exec.CommandContext(context.Background(), "ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output() // #nosec G204 -- фиксированная команда ps, аргумент — собственный pid
	if err != nil {
		return
	}
	kb, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.max = max(r.max, kb/1024)
	r.mu.Unlock()
}

func (r *rssSampler) maxMB() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
}
