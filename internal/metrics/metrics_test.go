package metrics

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func TestPromlintClean(t *testing.T) {
	sreg, s := NewServerRegistry()
	areg, a := NewAgentRegistry()
	// Заполняем все серии, чтобы lint видел их.
	s.RequestDone("r", "sendMessage", 200)
	s.RequestDuration("send", "a1", time.Second, false)
	s.UpstreamAttempt("a1", "ok")
	s.Retry("c", "r")
	s.Telegram429("r")
	s.SetAgentUp("a1", "dial", true)
	s.SetAgentInflight("a1", 1)
	s.SetAgentReverseConns("a1", 2)
	s.EnrollAttempt("ok")
	s.NoHealthyAgents()
	s.LongPollActive(1)
	s.WebhookBlocked()
	s.InstallJob("ok")
	s.AdminLogin("ok")
	s.AlertUndeliverable()
	s.SetIngressCertNotAfter(time.Now())
	s.BufferedBytes().Add(10)
	a.Request("2xx", "none")
	a.UpstreamDuration(time.Second)
	a.SetInflight(1)
	a.UpstreamBytes("in", 5)
	a.UpstreamBytes("out", -1)
	a.DialError("dns")
	for name, reg := range map[string]*prometheus.Registry{"server": sreg, "agent": areg} {
		p, err := testutil.GatherAndLint(reg)
		if err != nil || len(p) != 0 {
			t.Errorf("%s: lint err=%v problems=%v", name, err, p)
		}
	}
}

func TestRequestsTotalExposition(t *testing.T) {
	_, s := NewServerRegistry()
	s.RequestDone("rule1", "SendMessage", 200)
	s.RequestDone("rule1", "sendmessage", 200)
	s.RequestDone("rule1", "bogusMethod", 502)
	s.RequestDone("rule1", "sendMessage", 0)
	exp := `
# HELP tgp_requests_total Proxied Bot API requests.
# TYPE tgp_requests_total counter
tgp_requests_total{code="200",method="sendmessage",rule="rule1"} 2
tgp_requests_total{code="5xx",method="other",rule="rule1"} 1
tgp_requests_total{code="proxy_err",method="sendmessage",rule="rule1"} 1
`
	if err := testutil.CollectAndCompare(s.requests, strings.NewReader(exp), "tgp_requests_total"); err != nil {
		t.Fatal(err)
	}
}

func TestCodeLabel(t *testing.T) {
	cases := map[int]string{200: "200", 400: "400", 401: "401", 403: "403", 404: "404", 409: "409",
		413: "413", 429: "429", 500: "5xx", 599: "5xx", 0: "proxy_err", -1: "proxy_err",
		201: "other", 302: "other", 418: "other", 600: "other"}
	for in, want := range cases {
		if got := CodeLabel(in); got != want {
			t.Errorf("CodeLabel(%d)=%q want %q", in, got, want)
		}
	}
}

// collectors вынимает все Collector-поля через рефлексию.
func collectDescs(v any) []*prometheus.Desc {
	var out []*prometheus.Desc
	rv := reflect.ValueOf(v).Elem()
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		f = reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
		c, ok := f.Interface().(prometheus.Collector)
		if !ok {
			continue
		}
		ch := make(chan *prometheus.Desc, 16)
		go func() { c.Describe(ch); close(ch) }()
		for d := range ch {
			out = append(out, d)
		}
	}
	return out
}

func TestNoBotIDLabel(t *testing.T) {
	_, s := NewServerRegistry()
	_, a := NewAgentRegistry()
	descs := append(collectDescs(s), collectDescs(a)...)
	if len(descs) < 15 {
		t.Fatalf("too few descs found: %d", len(descs))
	}
	for _, d := range descs {
		if strings.Contains(d.String(), "bot_id") {
			t.Errorf("bot_id label in %s", d)
		}
	}
	// То же по выводу Gather.
	for _, r := range []*prometheus.Registry{func() *prometheus.Registry { r, _ := NewServerRegistry(); return r }()} {
		mfs, _ := r.Gather()
		for _, mf := range mfs {
			for _, m := range mf.Metric {
				for _, l := range m.Label {
					if l.GetName() == "bot_id" {
						t.Errorf("bot_id in %s", mf.GetName())
					}
				}
			}
		}
	}
}

func TestMethodCardinality(t *testing.T) {
	_, s := NewServerRegistry()
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		b := make([]byte, 1+rnd.Intn(20))
		for j := range b {
			b[j] = byte('a' + rnd.Intn(26))
		}
		s.RequestDone("r", string(b), 200)
	}
	s.RequestDone("r", "sendMessage", 200)
	if n := testutil.CollectAndCount(s.requests); n > tgapi.KnownMethodCount()+1 {
		t.Errorf("series=%d > %d", n, tgapi.KnownMethodCount()+1)
	}
}

func TestLongPollNotInHistogram(t *testing.T) {
	_, s := NewServerRegistry()
	s.RequestDuration("poll", "a1", 30*time.Second, true)
	if n := testutil.CollectAndCount(s.duration); n != 0 {
		t.Fatalf("long-poll recorded: %d", n)
	}
	s.RequestDuration("send", "a1", 100*time.Millisecond, false)
	if n := testutil.CollectAndCount(s.duration); n != 1 {
		t.Fatalf("want 1 series, got %d", n)
	}
}

func TestServerRecorders(t *testing.T) {
	_, s := NewServerRegistry()
	s.SetAgentUp("a1", "dial", true)
	s.SetAgentUp("a1", "reverse", false) // смена mode заменяет серию
	if n := testutil.CollectAndCount(s.agentUp); n != 1 {
		t.Errorf("agent_up series=%d", n)
	}
	if v := testutil.ToFloat64(s.agentUp.WithLabelValues("a1", "reverse")); v != 0 {
		t.Errorf("up=%v", v)
	}
	s.SetAgentUp("a1", "reverse", true)
	s.SetAgentInflight("a1", 3)
	s.SetAgentReverseConns("a1", 2)
	s.ForgetAgent("a1")
	for _, c := range []prometheus.Collector{s.agentUp, s.agentInflight, s.agentReverse} {
		if testutil.CollectAndCount(c) != 0 {
			t.Error("ForgetAgent left series")
		}
	}
	s.LongPollActive(2)
	s.LongPollActive(-1)
	if v := testutil.ToFloat64(s.longPoll); v != 1 {
		t.Errorf("longpoll=%v", v)
	}
	g := s.BufferedBytes()
	g.Add(100)
	g.Add(-40)
	if v := testutil.ToFloat64(s.buffered); v != 60 {
		t.Errorf("buffered=%v", v)
	}
	ts := time.Unix(1_900_000_000, 0)
	s.SetIngressCertNotAfter(ts)
	if v := testutil.ToFloat64(s.ingressCertAfter); v != 1_900_000_000 {
		t.Errorf("cert=%v", v)
	}
	s.NoHealthyAgents()
	s.WebhookBlocked()
	s.AlertUndeliverable()
	for _, c := range []prometheus.Counter{s.noHealthy, s.webhookBlocked, s.undeliverable} {
		if testutil.ToFloat64(c) != 1 {
			t.Error("counter != 1")
		}
	}
	s.InstallJob("ok")
	s.AdminLogin("bad")
	s.EnrollAttempt("ok")
	s.UpstreamAttempt("a1", "ok")
	s.Retry("idempotent", "5xx")
	s.Telegram429("r")
	if testutil.ToFloat64(s.tg429.WithLabelValues("r")) != 1 {
		t.Error("429")
	}
}

func TestAgentRecorders(t *testing.T) {
	_, a := NewAgentRegistry()
	a.UpstreamBytes("in", 10)
	a.UpstreamBytes("in", 0)
	if v := testutil.ToFloat64(a.bytes.WithLabelValues("in")); v != 10 {
		t.Errorf("bytes=%v", v)
	}
	a.SetInflight(4)
	if testutil.ToFloat64(a.inflight) != 4 {
		t.Error("inflight")
	}
	a.UpstreamDuration(time.Millisecond)
	a.Request("2xx", "none")
	a.DialError("tls")
	if testutil.CollectAndCount(a.requests) != 1 || testutil.CollectAndCount(a.dialErr) != 1 {
		t.Error("series")
	}
}

func TestBuildInfo(t *testing.T) {
	for _, r := range []*prometheus.Registry{func() *prometheus.Registry { r, _ := NewServerRegistry(); return r }(),
		func() *prometheus.Registry { r, _ := NewAgentRegistry(); return r }()} {
		mfs, err := r.Gather()
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, mf := range mfs {
			found[mf.GetName()] = true
			if mf.GetName() == "tgp_build_info" {
				m := mf.Metric[0]
				if m.Gauge.GetValue() != 1 || len(m.Label) != 3 {
					t.Errorf("build_info %v", m)
				}
			}
		}
		if !found["tgp_build_info"] || !found["go_goroutines"] {
			t.Errorf("missing build_info/go collector: %v", found)
		}
	}
}

func get(t *testing.T, h http.Handler, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandlerBearer(t *testing.T) {
	reg, _ := NewServerRegistry()
	h, err := NewHandler(reg, "s3cret", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "Bearer wrong", "Bearer ", "Bearer s3cret1", "s3cret", "Basic s3cret", "Bearer"} {
		if rec := get(t, h, bad); rec.Code != http.StatusUnauthorized {
			t.Errorf("auth %q: code %d", bad, rec.Code)
		}
	}
	for _, ok := range []string{"Bearer s3cret", "bearer s3cret"} {
		rec := get(t, h, ok)
		body, _ := io.ReadAll(rec.Body)
		if rec.Code != 200 || !strings.Contains(string(body), "tgp_build_info") {
			t.Errorf("auth %q: code %d", ok, rec.Code)
		}
	}
}

func TestHandlerBearerRequired(t *testing.T) {
	reg, _ := NewServerRegistry()
	if h, err := NewHandler(reg, "", false); err != ErrBearerRequired || h != nil {
		t.Fatalf("got %v %v", h, err)
	}
	h, err := NewHandler(reg, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(t, h, ""); rec.Code != 200 {
		t.Errorf("loopback no-auth: %d", rec.Code)
	}
}

// ---- TopBots ----

func newTB(limit int) (*TopBots, *time.Time) {
	now := time.Unix(1_800_000_000, 0)
	tb := NewTopBots(limit)
	tb.now = func() time.Time { return now }
	return tb, &now
}

func TestTopBotsOrderAndStats(t *testing.T) {
	tb, _ := newTB(0)
	for i := 0; i < 5; i++ {
		tb.Observe(1, "ruleA", 200)
	}
	for i := 0; i < 3; i++ {
		tb.Observe(2, "ruleB", 429)
	}
	tb.Observe(2, "ruleB", 500)
	tb.Observe(2, "ruleB", 0)
	for i := 0; i < 9; i++ {
		tb.Observe(3, "ruleC", 200)
	}
	tb.Observe(4, "r", 200)
	tb.Observe(5, "r", 200) // равенство с 4 -> меньший id первым
	top := tb.Top(4)
	want := []BotStat{
		{3, "ruleC", 9, 0, 0},
		{2, "ruleB", 5, 5, 3},
		{1, "ruleA", 5, 0, 0},
		{4, "r", 1, 0, 0},
	}
	// 2 и 1 оба по 5: меньший id (1) первым
	want[1], want[2] = want[2], want[1]
	if !reflect.DeepEqual(top, want) {
		t.Errorf("got %+v\nwant %+v", top, want)
	}
	if tb.Top(0) != nil || tb.Top(-1) != nil {
		t.Error("k<=0")
	}
	if len(tb.Top(100)) != 5 {
		t.Error("all")
	}
}

func TestTopBotsWindow(t *testing.T) {
	tb, now := newTB(0)
	tb.Observe(1, "r", 200)
	*now = now.Add(23 * time.Hour)
	tb.Observe(2, "r", 200)
	if len(tb.Top(10)) != 2 {
		t.Fatal("both within window")
	}
	*now = now.Add(61 * time.Minute) // бот 1 вышел за 24ч
	top := tb.Top(10)
	if len(top) != 1 || top[0].BotID != 2 {
		t.Fatalf("got %+v", top)
	}
	// слот переиспользуется после полного оборота кольца
	*now = now.Add(25 * time.Hour)
	tb.Observe(2, "r", 200)
	if top := tb.Top(10); len(top) != 1 || top[0].Requests != 1 {
		t.Fatalf("got %+v", top)
	}
}

func TestTopBotsMemoryLimit(t *testing.T) {
	tb, now := newTB(100)
	// "тяжёлые" боты должны пережить вытеснение
	for id := int64(1); id <= 10; id++ {
		for i := 0; i < 50; i++ {
			tb.Observe(id, "r", 200)
		}
	}
	for id := int64(1000); id < 5000; id++ {
		tb.Observe(id, "r", 200)
		if tb.Len() > 100 {
			t.Fatalf("len=%d > 100", tb.Len())
		}
	}
	top := tb.Top(10)
	for i, b := range top {
		if b.BotID > 10 || b.Requests != 50 {
			t.Errorf("heavy bot evicted, top[%d]=%+v", i, b)
		}
	}
	// протухшие боты вычищаются без потери живых
	*now = now.Add(48 * time.Hour)
	for id := int64(10000); id < 10100; id++ {
		tb.Observe(id, "r", 200)
	}
	tb.Observe(99999, "r", 200)
	if tb.Len() > 100 || tb.Len() == 0 {
		t.Errorf("len=%d", tb.Len())
	}
}

func TestTopBotsEvictSmall(t *testing.T) {
	tb, _ := newTB(1)
	tb.Observe(1, "r", 200)
	tb.Observe(2, "r", 200) // n<1 -> evict ≥1
	if tb.Len() != 1 {
		t.Errorf("len=%d", tb.Len())
	}
}

func TestTopBotsRace(t *testing.T) {
	tb := NewTopBots(50)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				tb.Observe(int64(i%200), fmt.Sprint("r", g), 200+(i%3)*229)
				if i%100 == 0 {
					tb.Top(5)
				}
			}
		}(g)
	}
	wg.Wait()
	if tb.Len() > 50 {
		t.Errorf("len=%d", tb.Len())
	}
}
