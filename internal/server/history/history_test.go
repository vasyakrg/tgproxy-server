package history_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func sum(ss []store.Sample) (n int64) {
	for _, s := range ss {
		if s.AgentID != history.AggregateID {
			n += s.OK + s.Err + s.RateLimited
		}
	}
	return n
}

func TestDrainAtomicUnderLoad(t *testing.T) {
	c := history.NewCollector()
	const workers, per = 8, 5000
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range per {
				c.ObserveRequest(fmt.Sprintf("a%d", w%3), history.Outcome(i%4), time.Duration(i)*time.Millisecond, i%7 == 0)
				c.SetInflight("a0", i%5)
			}
		}()
	}
	var total int64
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
loop:
	for {
		select {
		case <-done:
			break loop
		default:
			total += sum(c.Drain())
		}
	}
	total += sum(c.Drain())
	if total != workers*per {
		t.Fatalf("lost events: %d != %d", total, workers*per)
	}
}

func TestCollectorMapping(t *testing.T) {
	c := history.NewCollector()
	c.ObserveRequest("a", history.OutcomeOK, 3*time.Millisecond, false)
	c.ObserveRequest("a", history.OutcomeTGErr, 3*time.Millisecond, false)
	c.ObserveRequest("a", history.OutcomeProxyErr, time.Minute, false)
	c.ObserveRequest("a", history.OutcomeTG429, time.Millisecond, false)
	c.ObserveRequest("a", history.OutcomeOK, 40*time.Second, true) // long-poll: мимо гистограммы
	c.ObserveRequest("a", history.Outcome(99), 0, false)           // мусор игнорируется
	c.SetInflight("a", 5)
	c.SetInflight("a", 2)
	c.SetInflight("a", -1) // отрицательное → 0
	c.SetInflight("a", 2)
	c.SetInflight("idle", 0)
	ss := c.Drain()
	if len(ss) != 2 { // a + агрегат; idle без активности не пишется
		t.Fatalf("samples: %+v", ss)
	}
	a, agg := ss[0], ss[1]
	if a.AgentID != "a" || a.OK != 3 || a.Err != 1 || a.RateLimited != 1 || a.Inflight != 5 {
		t.Fatalf("a = %+v", a)
	}
	var obs int64
	for _, b := range a.Buckets {
		obs += b
	}
	if obs != 4 || len(a.Buckets) != history.NumBuckets() {
		t.Fatalf("buckets %v", a.Buckets)
	}
	if agg.AgentID != history.AggregateID || agg.OK != 3 || agg.Inflight != 5 {
		t.Fatalf("agg = %+v", agg)
	}
	// после Drain: счётчики обнулены, inflight перенесён
	ss = c.Drain()
	if len(ss) != 2 || ss[0].OK != 0 || ss[0].Inflight != 2 {
		t.Fatalf("second drain %+v", ss)
	}
	c.SetInflight("a", 0)
	if ss = c.Drain(); len(ss) != 2 || ss[0].Inflight != 2 { // максимум интервала всё ещё 2
		t.Fatalf("third drain %+v", ss)
	}
	if ss = c.Drain(); len(ss) != 1 || ss[0].AgentID != history.AggregateID {
		t.Fatalf("empty drain must yield only aggregate: %+v", ss)
	}
}

func TestQuantile(t *testing.T) {
	if history.P95(nil) != 0 {
		t.Fatal("empty")
	}
	b := make([]int64, history.NumBuckets())
	b[len(b)-1] = 10 // всё в переполняющем бакете
	if got := history.P95(b); got != history.LatencyBoundsMs[len(history.LatencyBoundsMs)-1] {
		t.Fatalf("overflow p95 %v", got)
	}
	b = make([]int64, history.NumBuckets())
	b[0], b[3] = 100, 100 // 50% ≤5мс, 50% в (25,50]
	if got := history.P95(b); got <= 25 || got > 50 {
		t.Fatalf("p95 %v", got)
	}
	if got := history.Quantile(b, 0.25); got <= 0 || got > 5 {
		t.Fatalf("p25 %v", got)
	}
}

func TestRollupP95FromHistogramNotAverage(t *testing.T) {
	ctx := context.Background()
	st := memtest.New()
	repo := st.History()
	fast := make([]int64, history.NumBuckets())
	fast[1] = 1000 // 1000 запросов ≤10мс
	slow := make([]int64, history.NumBuckets())
	slow[9] = 10 // 10 запросов ≤5с
	base := t0
	for i, bk := range [][]int64{fast, slow} {
		s := store.Sample{At: base.Add(time.Duration(i) * history.Step10s), AgentID: "a", OK: 1, Inflight: i + 1, Buckets: bk}
		s.P95Ms = history.P95(bk)
		if err := repo.Append(ctx, store.Res10s, []store.Sample{s}); err != nil {
			t.Fatal(err)
		}
	}
	naive := (history.P95(fast) + history.P95(slow)) / 2
	r := history.NewRoller(repo)
	if err := r.Step(ctx, base.Add(history.Step5m)); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.Range(ctx, store.Res5m, "a", base, base.Add(history.Step5m))
	if len(got) != 1 {
		t.Fatalf("rolled %+v", got)
	}
	if got[0].OK != 2 || got[0].Inflight != 2 || got[0].Buckets[1] != 1000 || got[0].Buckets[9] != 10 {
		t.Fatalf("sums %+v", got[0])
	}
	if got[0].P95Ms > 10 || naive < 1000 {
		t.Fatalf("p95=%v naive=%v: rollup must use merged histogram", got[0].P95Ms, naive)
	}
}

func TestRollupWaitsForCompleteBucketAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	repo := memtest.New().History()
	_ = repo.Append(ctx, store.Res10s, []store.Sample{{At: t0.Add(10 * time.Second), AgentID: "a", OK: 5}})
	r := history.NewRoller(repo)
	if err := r.Step(ctx, t0.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.Range(ctx, store.Res5m, "", t0.Add(-time.Hour), t0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("incomplete bucket rolled: %+v", got)
	}
	for range 2 {
		if err := r.Step(ctx, t0.Add(5*time.Minute+time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := repo.Range(ctx, store.Res5m, "", t0, t0.Add(time.Hour))
	if len(got) != 1 || got[0].OK != 5 || got[0].At != t0 {
		t.Fatalf("%+v", got)
	}
}

type errHistory struct{ store.HistoryRepo }

func (errHistory) Range(context.Context, store.Resolution, string, time.Time, time.Time) ([]store.Sample, error) {
	return nil, errors.New("boom")
}

func TestRollerPropagatesErrors(t *testing.T) {
	r := history.NewRoller(errHistory{memtest.New().History()})
	if err := r.Step(context.Background(), t0); err == nil {
		t.Fatal("want error")
	}
}

func TestRetention(t *testing.T) {
	ctx := context.Background()
	repo := memtest.New().History()
	now := t0
	old10 := now.Add(-25 * time.Hour)
	new10 := now.Add(-23 * time.Hour)
	old5 := now.Add(-31 * 24 * time.Hour)
	new5 := now.Add(-29 * 24 * time.Hour)
	_ = repo.Append(ctx, store.Res10s, []store.Sample{{At: old10, AgentID: "a"}, {At: new10, AgentID: "a"}})
	_ = repo.Append(ctx, store.Res5m, []store.Sample{{At: old5, AgentID: "a"}, {At: new5, AgentID: "a"}})
	r := history.NewRoller(repo)
	r.Keep10s, r.Keep5m = 0, 0
	if err := r.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	a, _ := repo.Range(ctx, store.Res10s, "a", now.Add(-48*time.Hour), now)
	b, _ := repo.Range(ctx, store.Res5m, "a", now.Add(-40*24*time.Hour), now)
	if len(a) != 1 || !a[0].At.Equal(new10.Truncate(time.Millisecond)) || len(b) != 1 || !b[0].At.Equal(new5) {
		t.Fatalf("10s=%+v 5m=%+v", a, b)
	}
}

func TestSamplerTickWritesAggregateAndRolls(t *testing.T) {
	ctx := context.Background()
	repo := memtest.New().History()
	c := history.NewCollector()
	s := &history.Sampler{Collector: c, Repo: repo, Roller: history.NewRoller(repo)}
	c.ObserveRequest("a", history.OutcomeOK, time.Millisecond, false)
	c.ObserveRequest("b", history.OutcomeTG429, time.Millisecond, false)
	tick := t0.Add(history.Step5m + time.Second) // сразу после границы 5m
	if err := s.Tick(ctx, tick); err != nil {
		t.Fatal(err)
	}
	at := tick.Truncate(history.Step10s).Add(-history.Step10s)
	got, _ := repo.Range(ctx, store.Res10s, history.AggregateID, at, at.Add(time.Second))
	if len(got) != 1 || got[0].OK != 1 || got[0].RateLimited != 1 {
		t.Fatalf("aggregate %+v", got)
	}
	if per, _ := repo.Range(ctx, store.Res10s, "", at, at.Add(time.Second)); len(per) != 3 {
		t.Fatalf("rows %+v", per)
	}
	// интервал [t0, t0+5m) ещё не содержал данных; следующее окно свернётся позже
	_ = s.Tick(ctx, tick.Add(history.Step5m))
	if r5, _ := repo.Range(ctx, store.Res5m, history.AggregateID, t0, t0.Add(time.Hour)); len(r5) == 0 {
		t.Fatal("expected rolled 5m rows")
	}
	// Tick без Roller и с ошибкой репозитория
	s2 := &history.Sampler{Collector: c, Repo: errAppend{repo}}
	if err := s2.Tick(ctx, tick); err == nil {
		t.Fatal("want append error")
	}
	s3 := &history.Sampler{Collector: c, Repo: errHistory{repo}, Roller: history.NewRoller(errHistory{repo})}
	if err := s3.Tick(ctx, tick); err == nil {
		t.Fatal("want roller error")
	}
}

type errAppend struct{ store.HistoryRepo }

func (errAppend) Append(context.Context, store.Resolution, []store.Sample) error {
	return errors.New("db down")
}

func TestSamplerRun(t *testing.T) {
	repo := memtest.New().History()
	c := history.NewCollector()
	s := &history.Sampler{Collector: c, Repo: repo}
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, ticks); close(done) }()
	c.ObserveRequest("a", history.OutcomeOK, time.Millisecond, false)
	ticks <- t0.Add(10 * time.Second)
	ticks <- t0.Add(20 * time.Second) // синхронизация: первый Tick уже завершён
	cancel()
	<-done
	got, _ := repo.Range(context.Background(), store.Res10s, "a", t0, t0.Add(time.Hour))
	if len(got) != 1 || got[0].OK != 1 {
		t.Fatalf("%+v", got)
	}
	// закрытый канал завершает Run
	ticks2 := make(chan time.Time)
	close(ticks2)
	s.Run(context.Background(), ticks2)
	// RunTicker выходит по отмене
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	s.RunTicker(ctx2)
}

func TestTimeseriesResolutionAndSince(t *testing.T) {
	ctx := context.Background()
	st := memtest.New()
	now := t0.Add(time.Hour)
	q := &history.Query{History: st.History(), ErrorRepo: st.Errors(), Now: func() time.Time { return now }}
	var s10 []store.Sample
	for i := range 6 {
		s10 = append(s10, store.Sample{At: now.Add(-time.Duration(60-10*i) * time.Second), AgentID: history.AggregateID, OK: 20, Err: 10, RateLimited: 30, P95Ms: 12, Inflight: i})
	}
	_ = st.History().Append(ctx, store.Res10s, s10)
	_ = st.History().Append(ctx, store.Res5m, []store.Sample{{At: now.Add(-10 * time.Minute), AgentID: history.AggregateID, OK: 3000}})
	_ = st.History().Append(ctx, store.Res10s, []store.Sample{{At: now.Add(-20 * time.Second), AgentID: "a1", OK: 100}})

	s, err := q.Timeseries(ctx, history.Range1h, "", time.Time{})
	if err != nil || len(s.Points) != 6 || s.StepSec != 10 {
		t.Fatalf("%+v %v", s, err)
	}
	if p := s.Points[0]; p.OKRPS != 2 || p.ErrRPS != 1 || p.R429RPS != 3 || p.P95Ms != 12 {
		t.Fatalf("point %+v", p)
	}
	last := time.Unix(s.Points[3].T, 0)
	inc, _ := q.Timeseries(ctx, history.Range6h, "", last)
	if len(inc.Points) != 2 || inc.Points[0].T <= s.Points[3].T {
		t.Fatalf("since: %+v", inc.Points)
	}
	if none, _ := q.Timeseries(ctx, history.Range1h, "", time.Unix(s.Points[5].T, 0)); len(none.Points) != 0 {
		t.Fatalf("since=last must be empty: %+v", none.Points)
	}
	day, _ := q.Timeseries(ctx, history.Range24h, "", time.Time{})
	if len(day.Points) != 2 || day.StepSec != 300 || day.Points[0].OKRPS != 10 || day.Points[1].OKRPS != 0.4 { // 5m + хвост из 10s
		t.Fatalf("24h %+v", day)
	}
	if w, _ := q.Timeseries(ctx, history.Range7d, "", time.Time{}); len(w.Points) != 2 {
		t.Fatalf("7d %+v", w)
	}
	ag, _ := q.Timeseries(ctx, history.Range1h, "a1", time.Time{})
	if len(ag.Points) != 1 || ag.Points[0].OKRPS != 10 || ag.Agent != "a1" {
		t.Fatalf("agent %+v", ag)
	}
	if _, err := q.Timeseries(ctx, history.Range("2d"), "", time.Time{}); !errors.Is(err, history.ErrBadRange) {
		t.Fatalf("err %v", err)
	}
	if _, err := q.Timeseries(ctx, history.Range1h, "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	bad := &history.Query{History: errHistory{st.History()}, Now: func() time.Time { return now }}
	if _, err := bad.Timeseries(ctx, history.Range1h, "", time.Time{}); err == nil {
		t.Fatal("want err")
	}
	if _, err := bad.Summary(ctx); err == nil {
		t.Fatal("want err")
	}
}

// Свежая установка: 5m-окон ещё нет, 24h/7d обязаны показать 10s-хвост текущего окна.
func TestTimeseriesOpenTailOnFreshInstall(t *testing.T) {
	ctx := context.Background()
	st := memtest.New()
	now := t0.Add(2*time.Minute + 5*time.Second) // 12:02:05 — окно 12:00 не закрыто
	q := &history.Query{History: st.History(), Now: func() time.Time { return now }}
	_ = st.History().Append(ctx, store.Res10s, []store.Sample{
		{At: t0, AgentID: history.AggregateID, OK: 100, Inflight: 2},
		{At: t0.Add(10 * time.Second), AgentID: history.AggregateID, OK: 50, Err: 5, Inflight: 4},
		{At: t0.Add(10 * time.Second), AgentID: "a1", OK: 7},
	})
	for _, rng := range []history.Range{history.Range24h, history.Range7d} {
		s, err := q.Timeseries(ctx, rng, "", time.Time{})
		if err != nil || len(s.Points) != 1 {
			t.Fatalf("%s: %+v %v", rng, s, err)
		}
		p := s.Points[0]
		if p.T != t0.Unix() || p.OKRPS != 150.0/125 || p.ErrRPS != 5.0/125 || p.Inflight != 4 {
			t.Fatalf("%s: point %+v", rng, p)
		}
		// открытое окно отдаётся и при since == T (клиент перезаписывает последнюю точку)
		inc, _ := q.Timeseries(ctx, rng, "", time.Unix(p.T, 0))
		if len(inc.Points) != 1 {
			t.Fatalf("%s since: %+v", rng, inc.Points)
		}
		if after, _ := q.Timeseries(ctx, rng, "", time.Unix(p.T+1, 0)); len(after.Points) != 0 {
			t.Fatalf("%s since>T: %+v", rng, after.Points)
		}
	}
	// закрытое окно уже в 5m — дубликата из 10s нет
	_ = st.History().Append(ctx, store.Res5m, []store.Sample{{At: t0, AgentID: history.AggregateID, OK: 999}})
	if s, _ := q.Timeseries(ctx, history.Range24h, "", time.Time{}); len(s.Points) != 1 || s.Points[0].OKRPS != 999.0/300 {
		t.Fatalf("dup: %+v", s.Points)
	}
}

func TestParseRange(t *testing.T) {
	for _, s := range []string{"1h", "6h", "24h", "7d"} {
		if _, err := history.ParseRange(s); err != nil {
			t.Fatal(s, err)
		}
	}
	if _, err := history.ParseRange("x"); !errors.Is(err, history.ErrBadRange) {
		t.Fatal(err)
	}
}

func TestSummary(t *testing.T) {
	ctx := context.Background()
	st := memtest.New()
	now := t0
	q := &history.Query{History: st.History(), Now: func() time.Time { return now }}
	if k, err := q.Summary(ctx); err != nil || k.RPS != 0 || k.ProxyErrPct != 0 {
		t.Fatalf("empty %+v %v", k, err)
	}
	_ = st.History().Append(ctx, store.Res10s, []store.Sample{
		{At: now.Add(-3 * time.Hour), AgentID: history.AggregateID, OK: 5000}, // пик (500 rps), но вне 5 минут
		{At: now.Add(-40 * time.Second), AgentID: history.AggregateID, OK: 270, Err: 30, RateLimited: 0, Inflight: 4},
		{At: now.Add(-20 * time.Second), AgentID: history.AggregateID, OK: 600, Err: 60, RateLimited: 40, Inflight: 7},
		{At: now.Add(-20 * time.Second), AgentID: "a1", OK: 999999},
	})
	k, err := q.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if k.R429 != 40 || k.Inflight != 7 || k.PeakRPS != 500 || !k.PeakAt.Equal(now.Add(-3*time.Hour)) {
		t.Fatalf("%+v", k)
	}
	if want := 1000.0 / 300; k.RPS < want-1e-9 || k.RPS > want+1e-9 {
		t.Fatalf("rps %v", k.RPS)
	}
	if k.ProxyErrPct < 8.99 || k.ProxyErrPct > 9.01 {
		t.Fatalf("err%% %v", k.ProxyErrPct)
	}
	// Now по умолчанию
	if _, err := (&history.Query{History: st.History()}).Summary(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestErrorsCursorStableUnderInserts(t *testing.T) {
	ctx := context.Background()
	st := memtest.New()
	q := &history.Query{History: st.History(), ErrorRepo: st.Errors()}
	add := func(i int, agent string) {
		_, err := st.Errors().Append(ctx, store.ErrorEvent{At: t0.Add(time.Duration(i) * time.Second), RequestID: fmt.Sprintf("r%d", i),
			BotID: "123", AgentID: agent, Method: "sendMessage", Phase: "dial", Code: 502, Outcome: store.OutcomeRetried})
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range 10 {
		add(i, "a1")
	}
	p1, err := q.Errors(ctx, "", history.Filters{Limit: 4})
	if err != nil || len(p1.Items) != 4 || p1.NextCursor == "" || p1.Items[0].RequestID != "r9" {
		t.Fatalf("%+v %v", p1, err)
	}
	add(100, "a1") // вставка между страницами
	add(101, "a2")
	p2, _ := q.Errors(ctx, p1.NextCursor, history.Filters{Limit: 4})
	if len(p2.Items) != 4 || p2.Items[0].RequestID != "r5" || p2.Items[3].RequestID != "r2" {
		t.Fatalf("p2 %+v", p2.Items)
	}
	p3, _ := q.Errors(ctx, p2.NextCursor, history.Filters{Limit: 4})
	if len(p3.Items) != 2 || p3.NextCursor != "" || p3.Items[1].RequestID != "r0" {
		t.Fatalf("p3 %+v", p3)
	}
	// фильтры
	f, _ := q.Errors(ctx, "", history.Filters{AgentID: "a2", Phase: "dial", Code: 502, BotID: "123", RequestID: "r101", Method: "sendMessage", Outcome: store.OutcomeRetried})
	if len(f.Items) != 1 {
		t.Fatalf("filters %+v", f)
	}
	if f, _ = q.Errors(ctx, "", history.Filters{Phase: "tls"}); len(f.Items) != 0 {
		t.Fatal("phase filter")
	}
	if d, _ := q.Errors(ctx, "", history.Filters{}); len(d.Items) != 12 {
		t.Fatalf("default limit: %d", len(d.Items))
	}
	if d, _ := q.Errors(ctx, "", history.Filters{Limit: 100000}); len(d.Items) != 12 {
		t.Fatalf("max limit: %d", len(d.Items))
	}
	for _, c := range []string{"!!!", "YWJj", "LTE"} { // не base64 / не число / отрицательное
		if _, err := q.Errors(ctx, c, history.Filters{}); !errors.Is(err, history.ErrBadCursor) {
			t.Fatalf("cursor %q: %v", c, err)
		}
	}
}

func TestErrorLogRedactsToken(t *testing.T) {
	ctx := context.Background()
	st := memtest.New()
	l := history.NewErrorLog(st.Errors(), 0)
	const tok = "123456789:" + "AAH9x" + "_4kLmNoPqRsTuVwXyZ0123456789abc" // склеено: литерал не должен совпадать с шаблоном токена (secret scanning)
	l.Record(ctx, store.ErrorEvent{Outcome: store.OutcomeFailedToBot, Description: `Post "https://api.telegram.org/bot` + tok + `/sendMessage": dial tcp: timeout`})
	if l.Pending() != 1 {
		t.Fatal("not queued")
	}
	rctx, cancel := context.WithCancel(ctx)
	cancel() // Run дописывает очередь и выходит
	l.Run(rctx)
	got, _ := st.Errors().List(ctx, store.ErrorQuery{})
	if len(got) != 1 || strings.Contains(got[0].Description, "AAH9x") || !strings.Contains(got[0].Description, "123456789:***") {
		t.Fatalf("description %+v", got)
	}
}

func TestErrorLogOverflowDoesNotBlock(t *testing.T) {
	st := memtest.New()
	l := history.NewErrorLog(st.Errors(), 2)
	done := make(chan struct{})
	go func() {
		for range 1000 {
			l.Record(context.Background(), store.ErrorEvent{Outcome: store.OutcomeRetried})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked")
	}
	if l.Dropped() != 998 || l.Pending() != 2 {
		t.Fatalf("dropped=%d pending=%d", l.Dropped(), l.Pending())
	}
}

func TestErrorLogRunAndTrim(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	st := memtest.New()
	l := history.NewErrorLog(st.Errors(), 8)
	l.Keep, l.MaxAge, l.TrimEvery = 3, time.Hour, 5*time.Millisecond
	done := make(chan struct{})
	go func() { l.Run(ctx); close(done) }()
	now := time.Now()
	for i := range 6 {
		l.Record(ctx, store.ErrorEvent{At: now, RequestID: fmt.Sprint(i), Outcome: store.OutcomeRetried})
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := st.Errors().List(context.Background(), store.ErrorQuery{})
		if len(got) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("trim by count: %d", len(got))
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	// Trim по возрасту + дефолты
	l2 := history.NewErrorLog(st.Errors(), 1)
	if err := l2.Trim(context.Background(), now.Add(48*time.Hour*30)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Errors().List(context.Background(), store.ErrorQuery{}); len(got) != 0 {
		t.Fatalf("age trim left %d", len(got))
	}
	// ошибка репозитория не роняет Run
	l3 := history.NewErrorLog(st.Errors(), 1)
	l3.Record(context.Background(), store.ErrorEvent{Outcome: "bad"})
	c3, cancel3 := context.WithCancel(context.Background())
	cancel3()
	l3.Run(c3)
}

// Отказы доступа: попадают в строку-агрегат (даже без трафика), сворачиваются в 5m и
// не влияют на RPS/долю ошибок прокси.
func TestDeniedCollectedRolledAndQueried(t *testing.T) {
	ctx := context.Background()
	st := memtest.New()
	repo := st.History()
	c := history.NewCollector()
	s := &history.Sampler{Collector: c, Repo: repo, Roller: history.NewRoller(repo)}
	for range 3 {
		c.ObserveDenied("no_rule")
	}
	c.ObserveDenied("banned")
	tick := t0.Add(history.Step5m + time.Second)
	if err := s.Tick(ctx, tick); err != nil {
		t.Fatal(err)
	}
	at := tick.Truncate(history.Step10s).Add(-history.Step10s)
	got, _ := repo.Range(ctx, store.Res10s, history.AggregateID, at, at.Add(time.Second))
	if len(got) != 1 || got[0].Denied["no_rule"] != 3 || got[0].Denied["banned"] != 1 || got[0].OK != 0 {
		t.Fatalf("aggregate %+v", got)
	}
	// следующий тик: счётчики обнулены
	if err := s.Tick(ctx, tick.Add(history.Step10s)); err != nil {
		t.Fatal(err)
	}
	next, _ := repo.Range(ctx, store.Res10s, history.AggregateID, at.Add(history.Step10s), at.Add(2*history.Step10s))
	if len(next) != 1 || len(next[0].Denied) != 0 {
		t.Fatalf("denied not reset: %+v", next)
	}
	// rollup 5m суммирует
	if err := history.NewRoller(repo).Step(ctx, tick.Add(history.Step5m)); err != nil {
		t.Fatal(err)
	}
	q := &history.Query{History: repo, ErrorRepo: st.Errors(), Now: func() time.Time { return tick.Add(history.Step5m) }}
	ser, err := q.Timeseries(ctx, history.Range24h, "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, p := range ser.Points {
		total += p.DeniedRPS * 300
		if p.OKRPS != 0 || p.ErrRPS != 0 {
			t.Fatalf("denied leaked into proxy counters: %+v", p)
		}
	}
	if total < 3.9 || total > 4.1 {
		t.Fatalf("denied total %v want 4 (points %+v)", total, ser.Points)
	}
	// агентский ряд отказов не содержит
	if a, _ := q.Timeseries(ctx, history.Range1h, "a", time.Time{}); len(a.Points) != 0 {
		t.Fatalf("agent series: %+v", a.Points)
	}
}
