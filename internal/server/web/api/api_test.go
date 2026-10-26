package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

// secretTail — секретная часть токена; склеено, чтобы литерал не совпадал с шаблоном токена (secret scanning).
const (
	secretTail  = "AAHdq" + "TcvCH1vGWJxfSeofSAs0K5PALDsaw3"
	secretToken = "7012345678:" + secretTail
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type lister []agents.State

func (l lister) List() []agents.State { return l }

func setup(t *testing.T, wrap api.Wrap, ag api.AgentLister) (*http.ServeMux, *memtest.Store) {
	t.Helper()
	st := memtest.New()
	q := &history.Query{History: st.History(), ErrorRepo: st.Errors(), Now: func() time.Time { return t0 }}
	mux := http.NewServeMux()
	(&api.StatsAPI{Stats: q, Agents: ag}).Routes(mux, wrap)
	(&api.ErrorsAPI{Source: q}).Routes(mux, wrap)
	return mux, st
}

func do(h http.Handler, url string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil))
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type=%q", ct)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("json: %v\n%s", err, rec.Body.String())
	}
}

func keys(t *testing.T, rec *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	decode(t, rec, &m)
	return m
}

func TestWrapAppliedToEveryRoute(t *testing.T) {
	deny := api.Wrap(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	})
	mux, _ := setup(t, deny, nil)
	for _, u := range []string{"/api/v1/stats/summary", "/api/v1/stats/timeseries", "/api/v1/errors"} {
		if c := do(mux, u).Code; c != http.StatusUnauthorized {
			t.Errorf("%s: %d без сессии", u, c)
		}
	}
}

func TestSummarySchemaAndEmpty(t *testing.T) {
	mux, _ := setup(t, nil, nil)
	rec := do(mux, "/api/v1/stats/summary")
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	m := keys(t, rec)
	for _, k := range []string{"rps", "proxy_err_pct", "r429", "inflight", "peak_rps", "peak_at", "agents_up", "agents_total"} {
		if _, ok := m[k]; !ok {
			t.Errorf("нет поля %s", k)
		}
	}
	var s api.Summary
	decode(t, rec, &s)
	if s.RPS != 0 || s.AgentsTotal != 0 {
		t.Errorf("пустое состояние: %+v", s)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("нет no-store")
	}
}

func TestSummaryValuesAndAgents(t *testing.T) {
	ag := lister{{Up: true}, {Up: true}, {Up: false}}
	mux, st := setup(t, nil, ag)
	_ = st.History().Append(context.Background(), store.Res10s, []store.Sample{
		{At: t0.Add(-30 * time.Second), AgentID: history.AggregateID, OK: 900, Err: 90, RateLimited: 10, Inflight: 12},
	})
	var s api.Summary
	decode(t, do(mux, "/api/v1/stats/summary"), &s)
	if s.AgentsUp != 2 || s.AgentsTotal != 3 || s.Inflight != 12 || s.R429 != 10 {
		t.Errorf("%+v", s)
	}
	if s.ProxyErrPct < 8.9 || s.ProxyErrPct > 9.1 {
		t.Errorf("err pct %v", s.ProxyErrPct)
	}
}

type liveFake int

func (l liveFake) LiveInflight() int { return int(l) }

// KPI «in-flight сейчас» берётся из живого счётчика, а не из последнего снимка истории.
func TestSummaryInflightIsLive(t *testing.T) {
	st := memtest.New()
	q := &history.Query{History: st.History(), Now: func() time.Time { return t0 }}
	_ = st.History().Append(context.Background(), store.Res10s, []store.Sample{
		{At: t0.Add(-30 * time.Second), AgentID: history.AggregateID, OK: 10, Inflight: 12},
	})
	mux := http.NewServeMux()
	(&api.StatsAPI{Stats: q, Live: liveFake(0)}).Routes(mux, nil)
	var s api.Summary
	decode(t, do(mux, "/api/v1/stats/summary"), &s)
	if s.Inflight != 0 {
		t.Errorf("inflight = %d, want 0 (живое значение)", s.Inflight)
	}
}

func TestTimeseriesSchemaSinceAndAgent(t *testing.T) {
	mux, st := setup(t, nil, nil)
	var ss []store.Sample
	for i := range 6 {
		at := t0.Add(-time.Duration(6-i) * 10 * time.Second)
		ss = append(ss, store.Sample{At: at, AgentID: history.AggregateID, OK: 100, Err: 10, RateLimited: 20, P95Ms: 150, Inflight: i})
		ss = append(ss, store.Sample{At: at, AgentID: "fra-1", OK: 50})
	}
	_ = st.History().Append(context.Background(), store.Res10s, ss)

	var s history.Series
	rec := do(mux, "/api/v1/stats/timeseries?range=1h")
	decode(t, rec, &s)
	if rec.Code != 200 || len(s.Points) != 6 || s.StepSec != 10 || s.Range != history.Range1h {
		t.Fatalf("code=%d %+v", rec.Code, s)
	}
	var raw struct {
		Points []map[string]json.RawMessage `json:"points"`
	}
	decode(t, rec, &raw)
	for _, k := range []string{"t", "ok_rps", "err_rps", "r429_rps", "p95_ms", "inflight"} {
		if _, ok := raw.Points[0][k]; !ok {
			t.Errorf("в точке нет %s", k)
		}
	}
	if s.Points[0].OKRPS != 10 || s.Points[0].ErrRPS != 1 || s.Points[0].R429RPS != 2 {
		t.Errorf("rps: %+v", s.Points[0])
	}

	// since: строго новее
	mid := s.Points[2].T
	var inc history.Series
	decode(t, do(mux, "/api/v1/stats/timeseries?range=1h&since="+strconv.FormatInt(mid, 10)), &inc)
	if len(inc.Points) != 3 || inc.Points[0].T <= mid {
		t.Errorf("since: %+v", inc.Points)
	}
	var none history.Series
	decode(t, do(mux, "/api/v1/stats/timeseries?range=1h&since="+strconv.FormatInt(s.Points[5].T, 10)), &none)
	if none.Points == nil || len(none.Points) != 0 {
		t.Errorf("пусто должно быть [] а не null: %s", do(mux, "/api/v1/stats/timeseries?range=1h&since=9999999999").Body.String())
	}

	var one history.Series
	decode(t, do(mux, "/api/v1/stats/timeseries?agent=fra-1"), &one) // range по умолчанию 24h (5m-данные) -> пусто
	if one.Agent != "fra-1" || one.Range != history.Range24h {
		t.Errorf("agent/range: %+v", one)
	}
	decode(t, do(mux, "/api/v1/stats/timeseries?range=1h&agent=fra-1"), &one)
	if len(one.Points) != 6 || one.Points[0].OKRPS != 5 {
		t.Errorf("агент: %+v", one)
	}
}

func TestTimeseriesBadParams(t *testing.T) {
	mux, _ := setup(t, nil, nil)
	for u, kind := range map[string]string{
		"/api/v1/stats/timeseries?range=2y":  "bad_range",
		"/api/v1/stats/timeseries?since=abc": "bad_since",
		"/api/v1/stats/timeseries?since=-5":  "bad_since",
		"/api/v1/errors?code=abc":            "bad_code",
		"/api/v1/errors?code=99999":          "bad_code",
		"/api/v1/errors?cursor=!!!":          "bad_cursor",
		"/api/v1/errors?limit=0":             "bad_limit",
	} {
		rec := do(mux, u)
		var e struct{ Error string }
		decode(t, rec, &e)
		if rec.Code != 400 || e.Error != kind {
			t.Errorf("%s: %d %s", u, rec.Code, e.Error)
		}
	}
}

func seed(t *testing.T, st *memtest.Store, n int) {
	t.Helper()
	for i := range n {
		ev := store.ErrorEvent{
			At: t0.Add(-time.Duration(n-i) * time.Minute), RequestID: "req-" + strconv.Itoa(i), BotID: "111", AgentID: "fra-1",
			Method: "sendMessage", Phase: "dial", Code: 200, Outcome: store.OutcomeRetried, Description: "i/o timeout",
		}
		if i%3 == 0 {
			ev.AgentID, ev.Phase, ev.Code, ev.Outcome = "ams-1", "timeout", 504, store.OutcomeFailedToBot
			ev.Description = "обрыв: " + secretToken
		}
		if _, err := st.Errors().Append(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
}

func TestErrorsEmptyAndSchema(t *testing.T) {
	mux, st := setup(t, nil, nil)
	rec := do(mux, "/api/v1/errors")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("пустой журнал: %d %s", rec.Code, rec.Body.String())
	}
	seed(t, st, 3)
	var raw struct {
		Items      []map[string]json.RawMessage `json:"items"`
		NextCursor string                       `json:"next_cursor"`
	}
	decode(t, do(mux, "/api/v1/errors"), &raw)
	if len(raw.Items) != 3 || raw.NextCursor != "" {
		t.Fatalf("%+v", raw)
	}
	for _, k := range []string{"id", "at", "request_id", "bot_id", "agent_id", "method", "phase", "code", "outcome", "description"} {
		if _, ok := raw.Items[0][k]; !ok {
			t.Errorf("нет поля %s", k)
		}
	}
}

func TestErrorsFiltersCursorLimit(t *testing.T) {
	mux, st := setup(t, nil, nil)
	seed(t, st, 30)
	list := func(u string) api.ErrorsPage {
		var p api.ErrorsPage
		rec := do(mux, u)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", u, rec.Code, rec.Body.String())
		}
		decode(t, rec, &p)
		return p
	}
	if p := list("/api/v1/errors?agent=ams-1"); len(p.Items) != 10 {
		t.Errorf("agent: %d", len(p.Items))
	}
	if p := list("/api/v1/errors?agent=ams-1&phase=timeout&code=504&bot_id=111"); len(p.Items) != 10 {
		t.Errorf("комбинация: %d", len(p.Items))
	}
	if p := list("/api/v1/errors?agent=ams-1&phase=dial"); len(p.Items) != 0 {
		t.Errorf("пересечение: %d", len(p.Items))
	}
	if p := list("/api/v1/errors?request_id=req-7"); len(p.Items) != 1 || p.Items[0].RequestID != "req-7" {
		t.Errorf("request_id: %+v", p.Items)
	}
	// курсор: страницы не пересекаются и покрывают всё, новые первыми
	seen := map[int64]bool{}
	cursor, pages := "", 0
	for {
		p := list("/api/v1/errors?limit=12&cursor=" + cursor)
		pages++
		for _, it := range p.Items {
			if seen[it.ID] {
				t.Fatalf("дубль id=%d", it.ID)
			}
			seen[it.ID] = true
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if len(seen) != 30 || pages != 3 {
		t.Errorf("seen=%d pages=%d", len(seen), pages)
	}
}

func TestErrorsDescriptionRedacted(t *testing.T) {
	mux, st := setup(t, nil, nil)
	// запись в обход ErrorLog: в хранилище лежит «сырой» токен
	seed(t, st, 3)
	body := do(mux, "/api/v1/errors").Body.String()
	if strings.Contains(body, secretTail) {
		t.Fatalf("токен утёк в JSON: %s", body)
	}
	if !strings.Contains(body, "***") {
		t.Errorf("нет маски: %s", body)
	}
}

type failSource struct{}

func (failSource) Errors(context.Context, string, history.Filters) (history.Page, error) {
	return history.Page{}, errors.New("db down secret-detail")
}

type failStats struct{}

func (failStats) Timeseries(context.Context, history.Range, string, time.Time) (history.Series, error) {
	return history.Series{}, errors.New("db down secret-detail")
}
func (failStats) Summary(context.Context) (history.KPI, error) {
	return history.KPI{}, errors.New("db down secret-detail")
}

func TestInternalErrorsDoNotLeakDetails(t *testing.T) {
	mux := http.NewServeMux()
	(&api.StatsAPI{Stats: failStats{}}).Routes(mux, nil)
	(&api.ErrorsAPI{Source: failSource{}}).Routes(mux, nil)
	for _, u := range []string{"/api/v1/stats/summary", "/api/v1/stats/timeseries", "/api/v1/errors"} {
		rec := do(mux, u)
		if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret-detail") {
			t.Errorf("%s: %d %s", u, rec.Code, rec.Body.String())
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	mux, _ := setup(t, nil, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/errors", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}
