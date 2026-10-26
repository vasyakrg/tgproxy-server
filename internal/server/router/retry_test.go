package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// ---- тестовая обвязка ----

type fclock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func newClock() *fclock { return &fclock{t: time.Unix(1_700_000_000, 0)} }

func (c *fclock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fclock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func (c *fclock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.mu.Unlock()
	c.Advance(d)
	return nil
}

func (c *fclock) slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

type rec struct {
	agent   string
	req     *http.Request
	ctx     context.Context
	body    []byte
	attempt string
	ms      string
}

// read читает тело запроса целиком (имитация записи в агента).
func (r *rec) read() []byte {
	if r.req.Body != nil {
		r.body, _ = io.ReadAll(r.req.Body)
	}
	return r.body
}

type fleet struct {
	mu   sync.Mutex
	fns  map[string]func(*rec) (*http.Response, error)
	recs []*rec
}

func newFleet() *fleet { return &fleet{fns: map[string]func(*rec) (*http.Response, error){}} }

func (f *fleet) on(agent string, fn func(*rec) (*http.Response, error)) { f.fns[agent] = fn }

func (f *fleet) RoundTrip(ctx context.Context, agent string, req *http.Request) (*http.Response, error) {
	r := &rec{agent: agent, req: req, ctx: ctx,
		attempt: req.Header.Get(tgapi.HeaderAttempt), ms: req.Header.Get(tgapi.HeaderTimeoutMs)}
	f.mu.Lock()
	f.recs = append(f.recs, r)
	fn := f.fns[agent]
	f.mu.Unlock()
	if fn == nil {
		return tgOK(`{"ok":true}`), nil
	}
	return fn(r)
}

func (f *fleet) calls(agent string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.recs {
		if r.agent == agent {
			n++
		}
	}
	return n
}

func (f *fleet) order() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var o []string
	for _, r := range f.recs {
		o = append(o, r.agent)
	}
	return o
}

func tgOK(body string) *http.Response { return tgResp(200, body) }

func tgResp(status int, body string) *http.Response {
	h := http.Header{}
	h.Set(tgapi.HeaderSource, tgapi.SourceTelegram)
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

func phaseErr(phase string) error {
	return &transport.PhaseError{Phase: phase, Source: transport.SourceServerAgent, Err: errors.New("boom")}
}

// seqPicker — детерминированный Picker: первый агент не из exclude.
type seqPicker struct {
	mu      sync.Mutex
	ids     []string
	noneFor int // первые N вызовов — ErrNoHealthyAgents
	calls   int
	err     error
	results []balancer.Result
}

func (p *seqPicker) Pick(_ context.Context, exclude []string) (string, func(balancer.Result), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return "", nil, p.err
	}
	if p.calls <= p.noneFor {
		return "", nil, balancer.ErrNoHealthyAgents
	}
	for _, id := range p.ids {
		if !contains(exclude, id) {
			return id, func(r balancer.Result) {
				p.mu.Lock()
				p.results = append(p.results, r)
				p.mu.Unlock()
			}, nil
		}
	}
	return "", nil, balancer.ErrNoHealthyAgents
}

func (p *seqPicker) res() []balancer.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]balancer.Result(nil), p.results...)
}

type harness struct {
	r   *Router
	fl  *fleet
	pk  *seqPicker
	clk *fclock
	cfg *config.ServerConfig
}

func newHarness(t *testing.T, mut func(*config.ServerConfig), opts ...Opt) *harness {
	t.Helper()
	c := cfg("a1", "a2", "a3")
	c.Buffer.TmpDir = t.TempDir()
	if mut != nil {
		mut(c)
	}
	h := &harness{fl: newFleet(), pk: &seqPicker{ids: []string{"a1", "a2", "a3"}}, clk: newClock(), cfg: c}
	all := append([]Opt{WithBalancer(h.pk), WithClock(h.clk.Now), WithSleep(h.clk.Sleep)}, opts...)
	h.r = New(c, h.fl, lg(), all...)
	return h
}

func (h *harness) do(t *testing.T, ctx context.Context, method, target, ct, body string) (*http.Response, error) { //nolint:revive
	t.Helper()
	r, route := newReq(method, target, ct, body) //nolint:contextcheck
	return h.r.Do(ctx, r, route)
}

func errOf(t *testing.T, err error, status int, desc string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Status != status || e.Desc != desc {
		t.Fatalf("want %d %q, got %v", status, desc, err)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	sendURL = "/bot" + tok + "/sendMessage"
	getMe   = "/bot" + tok + "/getMe"
)

// ---- сценарии M2-T5 ----

func TestDialFailoverUnsafeByteForByte(t *testing.T) {
	// тело больше RAMMax: буфер на диске, на агент-2 уходит то же самое
	h := newHarness(t, func(c *config.ServerConfig) { c.Buffer.RAMMax = 8 })
	payload := `{"chat_id":1,"text":"` + strings.Repeat("привет ", 50) + `"}`
	h.fl.on("a1", func(*rec) (*http.Response, error) { return nil, phaseErr(tgapi.PhaseDial) })
	var got []byte
	h.fl.on("a2", func(r *rec) (*http.Response, error) { got = r.read(); return tgOK(`{"ok":true,"result":1}`), nil })
	resp, err := h.do(t, context.Background(), "POST", sendURL, "application/json", payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("body differs: %q", got)
	}
	if body := readAll(t, resp); body != `{"ok":true,"result":1}` {
		t.Fatal(body)
	}
	if o := h.fl.order(); len(o) != 2 || o[0] != "a1" || o[1] != "a2" || h.fl.calls("a3") != 0 {
		t.Fatal(o)
	}
	if h.fl.recs[0].attempt != "1" || h.fl.recs[1].attempt != "2" {
		t.Fatal("attempt headers")
	}
	_ = resp.Body.Close()
	ents, _ := os.ReadDir(h.cfg.Buffer.TmpDir)
	if len(ents) != 0 {
		t.Fatalf("tmp files left: %d", len(ents))
	}
	if rs := h.pk.res(); len(rs) != 2 || !rs[0].TransportError || rs[1].TransportError {
		t.Fatalf("%+v", rs)
	}
}

func TestWriteFailureUnsafeDeliveryUnknown(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(r *rec) (*http.Response, error) { r.read(); return nil, phaseErr(tgapi.PhaseWrite) })
	_, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`) //nolint:bodyclose
	errOf(t, err, 502, DescDeliveryUnknown)
	if h.fl.calls("a2") != 0 || len(h.clk.slept()) != 0 {
		t.Fatal("agent-2 must not be called")
	}
}

func TestRawErrorAfterBodyWrittenIsWrite(t *testing.T) {
	// «сырая» ошибка после чтения тела → write → delivery unknown
	h := newHarness(t, nil)
	h.fl.on("a1", func(r *rec) (*http.Response, error) { r.read(); return nil, io.ErrUnexpectedEOF })
	_, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`) //nolint:bodyclose
	errOf(t, err, 502, DescDeliveryUnknown)
	if h.fl.calls("a2") != 0 {
		t.Fatal("agent-2 called")
	}
}

func TestAgentReportedPhase(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) {
		hd := http.Header{}
		hd.Set(tgapi.HeaderErrorPhase, tgapi.PhaseWrite)
		return &http.Response{StatusCode: 502, Header: hd, Body: io.NopCloser(strings.NewReader("x"))}, nil
	})
	_, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`) //nolint:bodyclose
	errOf(t, err, 502, DescDeliveryUnknown)

	// dial на стороне агента — ретрай на другом
	h = newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) {
		hd := http.Header{}
		hd.Set(tgapi.HeaderErrorPhase, tgapi.PhaseDial)
		return &http.Response{StatusCode: 502, Header: hd, Body: io.NopCloser(strings.NewReader("x"))}, nil
	})
	resp, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if h.fl.calls("a2") != 1 {
		t.Fatal("no failover")
	}
}

func TestLongPollDeadline65(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) { return tgOK(`{"ok":true,"result":[]}`), nil })
	resp, err := h.do(t, context.Background(), "GET", "/bot"+tok+"/getUpdates?timeout=50", "", "")
	if err != nil {
		t.Fatal(err)
	}
	rc := h.fl.recs[0]
	dl, _ := rc.ctx.Deadline()
	if left := time.Until(dl); left > 65*time.Second || left < 63*time.Second {
		t.Fatal(left)
	}
	if ms, _ := strconv.Atoi(rc.ms); ms > 65000 || ms < 64000 {
		t.Fatal(rc.ms)
	}
	_ = resp.Body.Close() // release балансировщика — по закрытию тела
	if rs := h.pk.res(); len(rs) != 1 || !rs[0].LongPoll || rs[0].TransportError {
		t.Fatalf("%+v", rs)
	}
}

func TestBudgetExhaustedBeforeDeadline(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) {
		h.clk.Advance(20 * time.Second)
		return nil, phaseErr(tgapi.PhaseDial)
	})
	h.fl.on("a2", func(*rec) (*http.Response, error) {
		h.clk.Advance(6 * time.Second)
		return nil, phaseErr(tgapi.PhaseDial)
	})
	_, err := h.do(t, context.Background(), "GET", getMe, "", "") //nolint:bodyclose
	errOf(t, err, 504, DescTimeout)
	if h.fl.calls("a3") != 0 {
		t.Fatal("budget exceeded, a3 must not be called")
	}
	// агенту-2 передан остаток бюджета
	if ms, _ := strconv.Atoi(h.fl.recs[1].ms); ms != 5000 {
		t.Fatal(h.fl.recs[1].ms)
	}
}

func TestBackoffNotFitBudget(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) {
		h.clk.Advance(24800 * time.Millisecond) // остаток 200ms < backoff 500ms
		return tgResp(502, `{"ok":false,"error_code":502,"description":"Bad Gateway"}`), nil
	})
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 502 || !strings.Contains(readAll(t, resp), "Bad Gateway") || h.fl.calls("a2") != 0 {
		t.Fatal("expected passthrough of last telegram response")
	}
}

func TestExcludeRealBalancer(t *testing.T) {
	b := balancer.New()
	b.Update([]balancer.Candidate{{ID: "a1", Weight: 1}, {ID: "a2", Weight: 1}, {ID: "a3", Weight: 1}})
	fl := newFleet()
	for _, id := range []string{"a1", "a2", "a3"} {
		fl.on(id, func(*rec) (*http.Response, error) { return nil, phaseErr(tgapi.PhaseDial) })
	}
	var passive []string
	c := cfg("a1", "a2", "a3")
	clk := newClock()
	r := New(c, fl, lg(), WithBalancer(b), WithClock(clk.Now), WithSleep(clk.Sleep),
		WithPassive(func(id string, terr bool) { passive = append(passive, fmt.Sprint(id, terr)) }))
	req, route := newReq("POST", sendURL, "application/json", `{"chat_id":1}`)
	_, err := r.Do(context.Background(), req, route) //nolint:bodyclose
	errOf(t, err, 502, DescUpstreamUnavailable)
	seen := map[string]bool{}
	for _, id := range fl.order() {
		seen[id] = true
	}
	if len(fl.order()) != 3 || len(seen) != 3 {
		t.Fatalf("each agent exactly once: %v", fl.order())
	}
	if len(passive) != 3 || !strings.HasSuffix(passive[0], "true") {
		t.Fatal(passive)
	}
}

func TestRateWindow429(t *testing.T) {
	clk := newClock()
	w := NewWindows(NewMemStore(clk.Now), clk.Now)
	h := newHarness(t, nil, WithWindows(w))
	h.clk = clk
	h.r = New(h.cfg, h.fl, lg(), WithBalancer(h.pk), WithClock(clk.Now), WithSleep(clk.Sleep), WithWindows(w))
	h.fl.on("a1", func(*rec) (*http.Response, error) {
		return tgResp(429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}`), nil
	})
	resp, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":100,"text":"a"}`)
	if err != nil || resp.StatusCode != 429 {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if h.fl.calls("a1") != 1 || len(clk.slept()) != 0 {
		t.Fatal("429 must be passed through without retry")
	}
	// тот же чат: 429 сам, агент не вызывается
	resp, err = h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":100,"text":"b"}`)
	if err != nil || resp.StatusCode != 429 {
		t.Fatal(err)
	}
	if resp.Header.Get("Retry-After") != "7" || !strings.Contains(readAll(t, resp), `"retry_after":7`) {
		t.Fatal("bad 429 body")
	}
	_ = resp.Body.Close()
	if h.fl.calls("a1") != 1 {
		t.Fatal("agent called while window is open")
	}
	// chat_id в query — проверка до буферизации тела
	resp, err = h.do(t, context.Background(), "POST", sendURL+"?chat_id=100", "", "")
	if err != nil || resp.StatusCode != 429 || h.fl.calls("a1") != 1 {
		t.Fatal("query chat_id must hit the window")
	}
	_ = resp.Body.Close()
	// другой чат проходит
	h.fl.on("a1", nil)
	resp, err = h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":200,"text":"c"}`)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	// окно истекло
	clk.Advance(8 * time.Second)
	resp, err = h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":100}`)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestTelegram5xxSafeRetriedWithBackoff(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) { return tgResp(502, `{"ok":false,"error_code":502}`), nil })
	h.fl.on("a2", func(*rec) (*http.Response, error) { return tgResp(500, `{"ok":false,"error_code":500}`), nil })
	h.fl.on("a3", func(*rec) (*http.Response, error) { return tgOK(`{"ok":true}`), nil })
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if s := h.clk.slept(); len(s) != 2 || s[0] != 500*time.Millisecond || s[1] != time.Second {
		t.Fatal(s)
	}
	for _, r := range h.pk.res() {
		if r.TransportError {
			t.Fatal("telegram 5xx is not a transport error")
		}
	}
}

func TestTelegram5xxAllAttemptsPassthrough(t *testing.T) {
	h := newHarness(t, nil)
	for _, id := range []string{"a1", "a2", "a3"} {
		h.fl.on(id, func(r *rec) (*http.Response, error) {
			return tgResp(502, `{"ok":false,"error_code":502,"description":"from `+r.agent+`"}`), nil
		})
	}
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 502 || !strings.Contains(readAll(t, resp), "from a3") {
		t.Fatal("last response expected")
	}
}

func TestTelegram5xxUnsafePassthrough(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) { return tgResp(500, `{"ok":false,"error_code":500}`), nil })
	resp, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 500 || h.fl.calls("a2") != 0 || len(h.clk.slept()) != 0 {
		t.Fatal("unsafe 5xx must pass through")
	}
}

func TestSemiNotModifiedOnRetry(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(r *rec) (*http.Response, error) { r.read(); return nil, phaseErr(tgapi.PhaseWrite) })
	h.fl.on("a2", func(*rec) (*http.Response, error) {
		return tgResp(400, `{"ok":false,"error_code":400,"description":"Bad Request: message is not modified"}`), nil
	})
	resp, err := h.do(t, context.Background(), "POST", "/bot"+tok+"/editMessageText", "application/json", `{"chat_id":1}`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
}

func TestClientCancelNoRetry(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	h.fl.on("a1", func(*rec) (*http.Response, error) { cancel(); return nil, context.Canceled })
	_, err := h.do(t, ctx, "GET", getMe, "", "") //nolint:bodyclose
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if h.fl.calls("a2") != 0 {
		t.Fatal("retry after cancel")
	}
	if rs := h.pk.res(); len(rs) != 1 || !rs[0].Canceled || rs[0].TransportError {
		t.Fatalf("%+v", rs)
	}

	// отмена, замаскированная под другую ошибку, тоже распознаётся
	h = newHarness(t, nil)
	ctx, cancel = context.WithCancel(context.Background())
	h.fl.on("a1", func(*rec) (*http.Response, error) { cancel(); return nil, io.EOF })
	_, err = h.do(t, ctx, "GET", getMe, "", "") //nolint:bodyclose
	if !errors.Is(err, context.Canceled) || h.fl.calls("a2") != 0 {
		t.Fatal(err)
	}
}

func TestNonReplayableBody(t *testing.T) {
	small := func(c *config.ServerConfig) { c.Buffer.RAMMax = 4; c.Buffer.DiskMax = 8 }
	payload := strings.Repeat("x", 100)
	up := "/bot" + tok + "/sendDocument"

	// pre-send после частичного чтения → ретрая нет
	h := newHarness(t, small)
	h.fl.on("a1", func(r *rec) (*http.Response, error) {
		buf := make([]byte, 10)
		_, _ = r.req.Body.Read(buf)
		return nil, phaseErr(tgapi.PhasePreSend)
	})
	_, err := h.do(t, context.Background(), "POST", up, "application/octet-stream", payload) //nolint:bodyclose
	errOf(t, err, 502, DescUpstreamUnavailable)
	if h.fl.calls("a2") != 0 {
		t.Fatal("partially consumed stream must not be retried")
	}

	// dial без чтения тела → ретрай, агент-2 получает всё тело
	h = newHarness(t, small)
	h.fl.on("a1", func(*rec) (*http.Response, error) { return nil, phaseErr(tgapi.PhaseDial) })
	var got []byte
	h.fl.on("a2", func(r *rec) (*http.Response, error) { got = r.read(); return tgOK(`{"ok":true}`), nil })
	resp, err := h.do(t, context.Background(), "POST", up, "application/octet-stream", payload)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if string(got) != payload {
		t.Fatalf("got %d bytes", len(got))
	}

	// write после чтения: safe-метод не ретраится, т.к. тело потеряно
	h = newHarness(t, small)
	h.fl.on("a1", func(r *rec) (*http.Response, error) { r.read(); return nil, phaseErr(tgapi.PhaseWrite) })
	_, err = h.do(t, context.Background(), "POST", "/bot"+tok+"/setChatPhoto", "application/octet-stream", payload) //nolint:bodyclose
	errOf(t, err, 502, DescUpstreamUnavailable)

	// semi + write → delivery unknown
	h = newHarness(t, small)
	h.fl.on("a1", func(r *rec) (*http.Response, error) { r.read(); return nil, phaseErr(tgapi.PhaseRead) })
	_, err = h.do(t, context.Background(), "POST", "/bot"+tok+"/editMessageMedia", "application/octet-stream", payload) //nolint:bodyclose
	errOf(t, err, 502, DescDeliveryUnknown)

	// tg-5xx на non-replayable safe: отдаём ответ Telegram как есть
	h = newHarness(t, small)
	h.fl.on("a1", func(r *rec) (*http.Response, error) {
		r.read()
		return tgResp(500, `{"ok":false,"error_code":500}`), nil
	})
	resp, err = h.do(t, context.Background(), "POST", "/bot"+tok+"/setChatPhoto", "application/octet-stream", payload)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 500 || h.fl.calls("a2") != 0 {
		t.Fatal("expected passthrough")
	}
}

func TestNoHealthyAgentsWaitsThen502(t *testing.T) {
	h := newHarness(t, func(c *config.ServerConfig) { c.Router.NoAgentWait = time.Second })
	h.pk.ids = nil
	_, err := h.do(t, context.Background(), "GET", getMe, "", "") //nolint:bodyclose
	errOf(t, err, 502, DescNoAgents)
	var total time.Duration
	for _, s := range h.clk.slept() {
		if s != noAgentPollStep {
			t.Fatal(s)
		}
		total += s
	}
	if total != time.Second {
		t.Fatal(total)
	}
}

func TestNoHealthyAgentsAppear(t *testing.T) {
	h := newHarness(t, nil)
	h.pk.noneFor = 3
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(h.clk.slept()) != 3 || h.fl.calls("a1") != 1 {
		t.Fatal(h.clk.slept())
	}
}

func TestNoHealthyAgentsParentCanceled(t *testing.T) {
	h := newHarness(t, nil)
	h.pk.noneFor = 100
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.do(t, ctx, "GET", getMe, "", "") //nolint:bodyclose
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPickErrors(t *testing.T) {
	h := newHarness(t, nil)
	h.pk.err = errors.New("picker broke")
	_, err := h.do(t, context.Background(), "GET", getMe, "", "") //nolint:bodyclose
	errOf(t, err, 502, DescNoAgents)

	// на ретрае агентов не осталось — финал по последней ошибке
	h = newHarness(t, nil)
	h.pk.ids = []string{"a1"}
	h.fl.on("a1", func(*rec) (*http.Response, error) { return nil, phaseErr(tgapi.PhaseDial) })
	_, err = h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`) //nolint:bodyclose
	errOf(t, err, 502, DescUpstreamUnavailable)
}

func TestBufferClosedWithResponse(t *testing.T) {
	g := &gauge{}
	h := newHarness(t, func(c *config.ServerConfig) { c.Buffer.RAMMax = 8 }, WithBufferGauge(g))
	var bufBytes float64
	h.fl.on("a1", func(r *rec) (*http.Response, error) {
		r.read()
		bufBytes = g.cur()
		return tgOK(`{"ok":true}`), nil
	})
	resp, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1,"text":"0123456789"}`)
	if err != nil {
		t.Fatal(err)
	}
	if bufBytes <= 0 || g.cur() <= 0 {
		t.Fatal("buffer must be held while response is open")
	}
	_ = readAll(t, resp)
	if g.cur() <= 0 {
		t.Fatal("buffer closed before Close")
	}
	_ = resp.Body.Close()
	_ = resp.Body.Close() // идемпотентно
	if g.cur() != 0 {
		t.Fatalf("buffer not released: %v", g.cur())
	}
	// и на ошибке
	h.fl.on("a1", func(r *rec) (*http.Response, error) { r.read(); return nil, phaseErr(tgapi.PhaseWrite) })
	_, _ = h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1,"text":"0123456789"}`) //nolint:bodyclose
	if g.cur() != 0 {
		t.Fatalf("buffer leaked on error: %v", g.cur())
	}
}

type gauge struct {
	mu sync.Mutex
	v  float64
}

func (g *gauge) Add(d float64) { g.mu.Lock(); g.v += d; g.mu.Unlock() }
func (g *gauge) cur() float64  { g.mu.Lock(); defer g.mu.Unlock(); return g.v }

func TestBodyErrors(t *testing.T) {
	h := newHarness(t, nil)
	req, route := newReq("POST", sendURL, "application/json", "")
	req.Body = io.NopCloser(&errReader{})
	req.ContentLength = -1
	_, err := h.r.Do(context.Background(), req, route) //nolint:bodyclose
	errOf(t, err, 400, DescBadBody)

	mb := &http.MaxBytesError{Limit: 1}
	req, route = newReq("POST", sendURL, "application/json", "")
	req.Body = io.NopCloser(&errReader{err: mb})
	req.ContentLength = -1
	_, err = h.r.Do(context.Background(), req, route) //nolint:bodyclose
	if !errors.Is(err, mb) {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, route = newReq("POST", sendURL, "application/json", "")
	req.Body = io.NopCloser(&errReader{})
	req.ContentLength = -1
	_, err = h.r.Do(ctx, req, route) //nolint:bodyclose
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	return 0, errors.New("client reset")
}

func TestMaxBytesFromStreamingBody(t *testing.T) {
	h := newHarness(t, func(c *config.ServerConfig) { c.Buffer.RAMMax = 4; c.Buffer.DiskMax = 8 })
	mb := &http.MaxBytesError{Limit: 1}
	h.fl.on("a1", func(*rec) (*http.Response, error) { return nil, mb })
	_, err := h.do(t, context.Background(), "POST", "/bot"+tok+"/sendDocument", "application/octet-stream", strings.Repeat("x", 100)) //nolint:bodyclose
	if !errors.Is(err, mb) || h.fl.calls("a2") != 0 {
		t.Fatal(err)
	}
	if rs := h.pk.res(); len(rs) != 1 || !rs[0].Canceled {
		t.Fatalf("%+v", rs)
	}
}

func TestBigTelegramErrorBodyPassthrough(t *testing.T) {
	h := newHarness(t, nil)
	big := `{"ok":false,"error_code":400,"description":"` + strings.Repeat("a", envelopeLimit+10) + `"}`
	h.fl.on("a1", func(*rec) (*http.Response, error) { return tgResp(400, big), nil })
	resp, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := readAll(t, resp); got != big {
		t.Fatalf("body mangled: %d vs %d", len(got), len(big))
	}
}

func TestErrorBodyReadFailureIsTransport(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) {
		r := tgResp(502, "")
		r.Body = io.NopCloser(&errReader{})
		return r, nil
	})
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if h.fl.calls("a2") != 1 {
		t.Fatal("read failure of a safe method must be retried")
	}
}

func TestBackoffSleepErrors(t *testing.T) {
	// родитель отменён во время backoff
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	h.r = New(h.cfg, h.fl, lg(), WithBalancer(h.pk), WithClock(h.clk.Now),
		WithSleep(func(context.Context, time.Duration) error { cancel(); return context.Canceled }))
	h.fl.on("a1", func(*rec) (*http.Response, error) { return tgResp(500, `{"ok":false,"error_code":500}`), nil })
	_, err := h.do(t, ctx, "GET", getMe, "", "") //nolint:bodyclose
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	// sleep упал не по вине клиента → отдаём последний ответ Telegram
	h = newHarness(t, nil)
	h.r = New(h.cfg, h.fl, lg(), WithBalancer(h.pk), WithClock(h.clk.Now),
		WithSleep(func(context.Context, time.Duration) error { return context.DeadlineExceeded }))
	h.fl.on("a1", func(*rec) (*http.Response, error) { return tgResp(500, `{"ok":false,"error_code":500}`), nil })
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil || resp.StatusCode != 500 {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestRealTimeDeadline(t *testing.T) {
	// реальный дедлайн контекста срабатывает раньше часов роутера
	h := newHarness(t, func(c *config.ServerConfig) { c.Router.Budget = 30 * time.Millisecond })
	h.fl.on("a1", func(r *rec) (*http.Response, error) { <-r.ctx.Done(); return nil, r.ctx.Err() })
	_, err := h.do(t, context.Background(), "GET", getMe, "", "") //nolint:bodyclose
	errOf(t, err, 504, DescTimeout)
	// unsafe с таймаутом после записи → delivery unknown
	h = newHarness(t, func(c *config.ServerConfig) { c.Router.Budget = 30 * time.Millisecond })
	h.fl.on("a1", func(r *rec) (*http.Response, error) { r.read(); <-r.ctx.Done(); return nil, r.ctx.Err() })
	_, err = h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`) //nolint:bodyclose
	errOf(t, err, 502, DescDeliveryUnknown)
}

func TestWindowFromBodyBlocksBeforeAgent(t *testing.T) {
	clk := newClock()
	w := NewWindows(NewMemStore(clk.Now), clk.Now)
	w.Observe(1, "-1001", &tgapi.Envelope{ErrorCode: 429, Parameters: &tgapi.ResponseParameters{RetryAfter: 3}})
	h := newHarness(t, nil, WithWindows(w))
	// бот 123456 ≠ 1 — окно чужое; открываем для нужного бота
	w.Observe(123456, "-1001", &tgapi.Envelope{ErrorCode: 429, Parameters: &tgapi.ResponseParameters{RetryAfter: 3}})
	body := "--b\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n-1001\r\n--b--\r\n"
	r, route := newReq("POST", sendURL, "multipart/form-data; boundary=b", body)
	resp, err := h.r.Do(context.Background(), r, route)
	if err != nil || resp.StatusCode != 429 || h.fl.calls("a1") != 0 {
		t.Fatalf("%v", err)
	}
	_ = resp.Body.Close()
}

func TestNewOptionsIgnoreNil(t *testing.T) {
	c := cfg("a1")
	r := New(c, newFleet(), lg(), WithBalancer(nil), WithClock(nil), WithSleep(nil), WithBufferConfig(c.Buffer))
	if r.balanced || r.clock == nil || r.sleep == nil {
		t.Fatal("nil options must be ignored")
	}
	if err := sleepCtx(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Fatal("canceled sleep must fail")
	}
}

// inflight агента держится до закрытия тела ответа (стрим /file/*).
func TestReleaseOnBodyClose(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) { return tgOK(`{"ok":true}`), nil })
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(h.pk.res()); n != 0 {
		t.Fatalf("released before body close: %d", n)
	}
	_ = readAll(t, resp)
	if n := len(h.pk.res()); n != 0 {
		t.Fatalf("released before Close, after EOF: %d", n)
	}
	_ = resp.Body.Close()
	_ = resp.Body.Close()
	res := h.pk.res()
	if len(res) != 1 || res[0].TransportError || res[0].Canceled {
		t.Fatalf("results: %+v", res)
	}
}

// Ошибка чтения тела — не транспортная ошибка агента, а Canceled-исход.
func TestReleaseOnBodyReadErrorIsCanceled(t *testing.T) {
	h := newHarness(t, nil)
	h.fl.on("a1", func(*rec) (*http.Response, error) {
		r := tgOK("")
		r.Body = io.NopCloser(io.MultiReader(strings.NewReader("part"), iotestErrReader{}))
		return r, nil
	})
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	res := h.pk.res()
	if len(res) != 1 || res[0].TransportError || !res[0].Canceled {
		t.Fatalf("results: %+v", res)
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errors.New("stream broken") }
