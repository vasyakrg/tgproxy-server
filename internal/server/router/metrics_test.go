package router

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

type fakeRec struct {
	mu       sync.Mutex
	attempts []string
	retries  []string
	noHealth int
	durs     []string
	inflight map[string]int
	lp       int
}

func (f *fakeRec) UpstreamAttempt(a, r string) {
	f.lock(func() { f.attempts = append(f.attempts, a+"/"+r) })
}
func (f *fakeRec) Retry(c, r string) { f.lock(func() { f.retries = append(f.retries, c+"/"+r) }) }
func (f *fakeRec) NoHealthyAgents()  { f.lock(func() { f.noHealth++ }) }
func (f *fakeRec) RequestDuration(c, a string, _ time.Duration, lp bool) {
	f.lock(func() { f.durs = append(f.durs, fmt.Sprintf("%s/%s/%v", c, a, lp)) })
}
func (f *fakeRec) SetAgentInflight(a string, n int) {
	f.lock(func() {
		if f.inflight == nil {
			f.inflight = map[string]int{}
		}
		f.inflight[a] = n
	})
}
func (f *fakeRec) LongPollActive(d int) { f.lock(func() { f.lp += d }) }
func (f *fakeRec) lock(fn func())       { f.mu.Lock(); fn(); f.mu.Unlock() }

type fakeHist struct {
	mu  sync.Mutex
	obs []string
}

func (f *fakeHist) ObserveRequest(a string, o history.Outcome, _ time.Duration, lp bool) {
	f.mu.Lock()
	f.obs = append(f.obs, fmt.Sprintf("%s/%d/%v", a, o, lp))
	f.mu.Unlock()
}
func (f *fakeHist) SetInflight(string, int) {}

type fakeErrs struct {
	mu sync.Mutex
	ev []store.ErrorEvent
}

func (f *fakeErrs) Record(_ context.Context, e store.ErrorEvent) {
	f.mu.Lock()
	f.ev = append(f.ev, e)
	f.mu.Unlock()
}

func TestMetricsRetryOnDial(t *testing.T) {
	fr, hist, errs := &fakeRec{}, &fakeHist{}, &fakeErrs{}
	h := newHarness(t, nil, WithRecorder(fr), WithHistory(hist), WithErrorLog(errs))
	h.fl.on("a1", func(*rec) (*http.Response, error) { return nil, phaseErr(tgapi.PhaseDial) })
	resp, err := h.do(t, context.Background(), "POST", sendURL, "application/json", `{"chat_id":1}`)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := strings.Join(fr.attempts, ","); got != "a1/error,a2/ok" {
		t.Fatal(got)
	}
	if len(fr.retries) != 1 || fr.retries[0] != "unsafe/dial" {
		t.Fatal(fr.retries)
	}
	if len(fr.durs) != 1 || fr.durs[0] != "unsafe/a2/false" {
		t.Fatal(fr.durs)
	}
	if len(hist.obs) != 1 || hist.obs[0] != fmt.Sprintf("a2/%d/false", history.OutcomeOK) {
		t.Fatal(hist.obs)
	}
	if fr.inflight["a1"] != 0 || fr.inflight["a2"] != 0 {
		t.Fatal(fr.inflight)
	}
	if len(errs.ev) != 1 {
		t.Fatalf("%+v", errs.ev)
	}
	ev := errs.ev[0]
	if ev.Outcome != store.OutcomeRetried || ev.Phase != tgapi.PhaseDial || ev.AgentID != "a1" || ev.Method != tgapi.MethodLabel("sendMessage") || ev.BotID != "123456" {
		t.Fatalf("%+v", ev)
	}
	if strings.Contains(ev.Description, tok) {
		t.Fatal("token leaked")
	}
}

func TestMetricsNoHealthyAndTelegram429(t *testing.T) {
	fr, hist, errs := &fakeRec{}, &fakeHist{}, &fakeErrs{}
	h := newHarness(t, nil, WithRecorder(fr), WithHistory(hist), WithErrorLog(errs))
	h.pk.noneFor = 1
	h.cfg.Router.NoAgentWait = 0
	if _, err := h.do(t, context.Background(), "GET", getMe, "", ""); err == nil { //nolint:bodyclose
		t.Fatal("want error")
	}
	if fr.noHealth != 1 || len(hist.obs) != 1 || !strings.HasPrefix(hist.obs[0], NoAgent+"/") {
		t.Fatal(fr.noHealth, hist.obs)
	}
	h.fl.on("a1", func(*rec) (*http.Response, error) {
		return tgResp(429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 3","parameters":{"retry_after":3}}`), nil
	})
	resp, err := h.do(t, context.Background(), "GET", getMe, "", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	last := hist.obs[len(hist.obs)-1]
	if last != fmt.Sprintf("a1/%d/false", history.OutcomeTG429) {
		t.Fatal(last)
	}
	if len(errs.ev) != 1 || errs.ev[0].Outcome != store.OutcomePassedToBot || errs.ev[0].Code != 429 {
		t.Fatalf("%+v", errs.ev)
	}
}

func TestMetricsInternalNotCounted(t *testing.T) {
	fr, hist, errs := &fakeRec{}, &fakeHist{}, &fakeErrs{}
	h := newHarness(t, nil, WithRecorder(fr), WithHistory(hist), WithErrorLog(errs))
	h.fl.on("a1", func(*rec) (*http.Response, error) { return nil, phaseErr(tgapi.PhaseDial) })
	resp, err := h.do(t, notify.InternalContext(context.Background()), "POST", sendURL, "application/json", `{"chat_id":1}`)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if h.fl.calls("a1") != 1 || h.fl.calls("a2") != 1 {
		t.Fatal("balancer/retry must work for internal requests", h.fl.order())
	}
	if len(fr.attempts)+len(fr.retries)+len(fr.durs)+fr.noHealth != 0 || len(hist.obs) != 0 || len(errs.ev) != 0 {
		t.Fatalf("internal counted: %+v %+v %+v", fr, hist.obs, errs.ev)
	}
}
