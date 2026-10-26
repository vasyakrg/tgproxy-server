package screens_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/web"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

var update = flag.Bool("update", false, "обновить golden-файлы")

const secretToken = "7012345678:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw3"

var (
	t0       = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	hashRe   = regexp.MustCompile(`\?v=[0-9a-f]{12}`)
	inlineJS = regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>`)
	styleAtt = regexp.MustCompile(`(?i)\sstyle\s*=`)
)

type env struct {
	st    *memtest.Store
	q     *history.Query
	shell *web.Router
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := memtest.New()
	return &env{
		st:    st,
		q:     &history.Query{History: st.History(), ErrorRepo: st.Errors(), Now: func() time.Time { return t0 }},
		shell: web.NewRouter(web.Deps{Version: "v1.4.1"}),
	}
}

func get(h http.Handler, url string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// checkCSP: нет inline-стилей и inline-скриптов (script только с src).
func checkCSP(t *testing.T, html string) {
	t.Helper()
	if styleAtt.MatchString(html) {
		t.Errorf("в HTML есть style=")
	}
	for _, m := range inlineJS.FindAllString(html, -1) {
		if !strings.Contains(m, "src=") {
			t.Errorf("inline-скрипт: %s", m)
		}
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(html) {
		t.Errorf("inline-обработчики событий в HTML")
	}
}

func golden(t *testing.T, name string, c templ.Component) {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Render(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	got := hashRe.ReplaceAllString(buf.String(), "?v=HASH")
	path := filepath.Join("testdata", name+".golden.html")
	if *update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // тестовая константа
	if err != nil {
		t.Fatalf("нет golden %s (запустите с -update): %v", path, err)
	}
	if strings.TrimSuffix(string(want), "\n") != got {
		t.Errorf("%s: не совпало с golden (-update, если намеренно)\n%s", name, got)
	}
}

// ---------- фейки ----------

type fakeAgents []agents.State

func (f fakeAgents) List() []agents.State { return f }

type fakeEvents struct {
	evs []screens.Event
	err error
}

func (f fakeEvents) RecentEvents(context.Context, int) ([]screens.Event, error) { return f.evs, f.err }

type failStats struct{}

func (failStats) Timeseries(context.Context, history.Range, string, time.Time) (history.Series, error) {
	return history.Series{}, errors.New("db down")
}
func (failStats) Summary(context.Context) (history.KPI, error) {
	return history.KPI{}, errors.New("db down")
}

func seedHistory(t *testing.T, e *env) {
	t.Helper()
	var ss []store.Sample
	for i := range 30 {
		ss = append(ss, store.Sample{At: t0.Add(-time.Duration(30-i) * 10 * time.Second), AgentID: history.AggregateID, OK: 100, Err: 2, RateLimited: 1, P95Ms: 180, Inflight: 7})
	}
	ss = append(ss, store.Sample{At: t0.Add(-20 * time.Second), AgentID: "fra-1", OK: 90, Err: 10, P95Ms: 200, Inflight: 3})
	if err := e.st.History().Append(context.Background(), store.Res10s, ss); err != nil {
		t.Fatal(err)
	}
}

func agentStates() fakeAgents {
	mk := func(id, url string, up, drain bool, fails int, ver string) agents.State {
		return agents.State{
			Agent: store.Agent{ID: id, Name: id, URL: url, Mode: store.ModeDial}, Up: up, Draining: drain, ConsecutiveFails: fails,
			LastStatus: &transport.AgentStatus{Version: ver, RPS1m: 96, Inflight: 8},
		}
	}
	return fakeAgents{
		mk("fra-1", "https://185.12.4.10:8443", true, false, 0, "v1.4.1"),
		mk("ams-1", "https://91.204.8.3:8443", true, false, 2, "v1.4.1"),
		mk("hel-1", "https://65.21.90.7:8443", true, false, 0, "v1.3.9"),
		mk("ist-1", "https://78.135.2.9:8443", false, false, 5, "v1.4.1"),
		mk("waw-1", "https://51.68.12.40:8443", true, true, 0, "v1.4.1"),
	}
}

func overviewHandler(e *env, ag screens.AgentLister, ev screens.EventSource) http.Handler {
	return screens.NewOverview(screens.OverviewDeps{
		Shell: e.shell, Stats: e.q, Agents: ag, Events: ev, ServerVersion: "v1.4.1",
		Location: time.UTC, Now: func() time.Time { return t0 },
	})
}

// ---------- Обзор ----------

type liveFake int

func (l liveFake) LiveInflight() int { return int(l) }

func TestOverviewInflightIsLive(t *testing.T) {
	e := newEnv(t)
	seedHistory(t, e) // в истории последний снимок inflight = 7
	h := screens.NewOverview(screens.OverviewDeps{
		Shell: e.shell, Stats: e.q, Live: liveFake(0), Location: time.UTC, Now: func() time.Time { return t0 },
	})
	body := get(h, "/").Body.String()
	if !strings.Contains(body, "In-flight сейчас") || strings.Contains(body, ">7<") {
		t.Errorf("KPI должен брать живое значение 0, а не снимок 7")
	}
}

func TestOverviewEmpty(t *testing.T) {
	e := newEnv(t)
	rec := get(overviewHandler(e, nil, nil), "/")
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Агентов пока нет", "Событий пока не было", "0 / 0", "нет агентов", `data-chart`, `data-poll-ms="5000"`, "Все агенты →"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	checkCSP(t, body)
	if !strings.Contains(body, "<html") || !strings.Contains(body, "js/charts.js") || !strings.Contains(body, "uPlot.iife.min.js") {
		t.Errorf("страница без каркаса/скриптов графика")
	}
}

func TestOverviewFull(t *testing.T) {
	e := newEnv(t)
	seedHistory(t, e)
	ev := fakeEvents{evs: []screens.Event{
		{At: t0, AgentID: "ist-1", Type: "agent_down", State: "firing", Text: "ist-1 недоступен: dial timeout", Sent: true},
		{At: t0.Add(-time.Hour), Type: "agent_down", State: "resolved", Text: "waw-1 восстановлен"},
		{At: t0.Add(-2 * time.Hour), Type: "rate_limited", State: "firing", Text: "бот " + secretToken + " получает 429"},
	}}
	body := get(overviewHandler(e, agentStates(), ev), "/?range=6h").Body.String()
	checks := []string{
		`data-range="6h"`, `aria-pressed="true"`, "4 / 5", "1 недоступно", // 4 up из 5
		"fra-1", "185.12.4.10:8443", "в работе", "Деградация", "Недоступен", "Drain",
		"ver-stale", "v1.3.9", "ist-1 недоступен: dial timeout", "12:00 · agent_down · отправлено",
		"event-err", "event-ok", "event-tg",
	}
	for _, c := range checks {
		if !strings.Contains(body, c) {
			t.Errorf("нет %q", c)
		}
	}
	if strings.Contains(strings.ToLower(body), strings.ToLower(secretToken)) || strings.Contains(body, "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw3") {
		t.Errorf("токен в событии не замаскирован")
	}
	checkCSP(t, body)
}

func TestOverviewFragmentAndHistoryRestore(t *testing.T) {
	e := newEnv(t)
	h := overviewHandler(e, nil, nil)
	frag := get(h, "/?range=1h", "HX-Request", "true")
	if strings.Contains(frag.Body.String(), "<html") || !strings.Contains(frag.Body.String(), `id="overview"`) {
		t.Errorf("htmx-запрос должен получить только #overview")
	}
	if !strings.Contains(frag.Header().Get("Vary"), "HX-Request") {
		t.Errorf("нет Vary: HX-Request")
	}
	if strings.Contains(frag.Body.String(), "<script") {
		t.Errorf("во фрагменте не должно быть скриптов (htmx их не исполняет)")
	}
	restore := get(h, "/?range=1h", "HX-Request", "true", "HX-History-Restore-Request", "true")
	if !strings.Contains(restore.Body.String(), "<html") {
		t.Errorf("восстановление истории требует полную страницу")
	}
}

func TestOverviewBadRangeFallsBack(t *testing.T) {
	e := newEnv(t)
	body := get(overviewHandler(e, nil, nil), "/?range=999d").Body.String()
	if !strings.Contains(body, `data-range="24h"`) {
		t.Errorf("неверный range должен давать 24h")
	}
}

func TestOverviewStatsFailure(t *testing.T) {
	e := newEnv(t)
	h := screens.NewOverview(screens.OverviewDeps{Shell: e.shell, Stats: failStats{}, Agents: agentStates(), Events: fakeEvents{err: errors.New("x")}, Now: func() time.Time { return t0 }})
	rec := get(h, "/")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "fra-1") {
		t.Fatalf("страница должна отрисоваться при сбое БД: %d", rec.Code)
	}
}

func TestOverviewPollClamp(t *testing.T) {
	e := newEnv(t)
	for in, want := range map[time.Duration]string{500 * time.Millisecond: "2000", 30 * time.Second: "5000", 3 * time.Second: "3000"} {
		h := screens.NewOverview(screens.OverviewDeps{Shell: e.shell, Stats: e.q, PollInterval: in})
		if body := get(h, "/").Body.String(); !strings.Contains(body, `data-poll-ms="`+want+`"`) {
			t.Errorf("poll %v: ожидали %s", in, want)
		}
	}
}

// ---------- Ошибки ----------

// countRows — число строк данных (по ячейке времени), без заголовка и строки «Показать ещё».
func countRows(html string) int { return strings.Count(html, `<td class="mono muted">`) }

func seedErrors(t *testing.T, e *env, n int) {
	t.Helper()
	ctx := context.Background()
	for i := range n {
		ev := store.ErrorEvent{
			At: t0.Add(-time.Duration(n-i) * time.Minute), RequestID: "01JBX4ABCDEFGH" + strconv.Itoa(1000+i),
			BotID: "6123450001", AgentID: "fra-1", Method: "sendMessage", Phase: "dial", Code: 200,
			Outcome: store.OutcomeRetried, Description: "connect: i/o timeout",
		}
		switch i % 4 {
		case 1:
			ev.AgentID, ev.Phase, ev.Code, ev.Outcome, ev.BotID = "ams-1", "timeout", 504, store.OutcomeFailedToBot, "6801234567"
		case 2:
			ev.Phase, ev.Code, ev.Outcome = "telegram", 429, store.OutcomePassedToBot
		case 3:
			ev.Phase, ev.Code, ev.Description = "pre-send", 200, "TLS до api.telegram.org: "+secretToken
		}
		if _, err := e.st.Errors().Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
}

func errorsHandler(e *env) http.Handler {
	return screens.NewErrors(screens.ErrorsDeps{Shell: e.shell, Source: e.q, Agents: agentStates(), Location: time.UTC, Now: func() time.Time { return t0 }})
}

func TestErrorsEmpty(t *testing.T) {
	e := newEnv(t)
	body := get(errorsHandler(e), "/errors").Body.String()
	for _, want := range []string{"Ошибок нет", "dial / tls", "нет агентов", "Применить", `name="request_id"`} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	checkCSP(t, body)
	if strings.Contains(body, "Показать ещё") {
		t.Errorf("кнопка «Показать ещё» без данных")
	}
}

func TestErrorsPageKPIAndRows(t *testing.T) {
	e := newEnv(t)
	seedErrors(t, e, 8)
	body := get(errorsHandler(e), "/errors").Body.String()
	for _, want := range []string{
		"переотправлен", "отказ боту", "передан боту", "01JBX4…", "connect: i/o timeout",
		`phase-warn`, `phase-err`, `phase-tg`, "все переотправлены", "переданы ботам",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	checkCSP(t, body)
	if strings.Contains(body, "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw3") {
		t.Errorf("токен из описания утёк в HTML")
	}
	if !strings.Contains(body, "7012345678:***") && !strings.Contains(body, "***") {
		t.Errorf("описание не замаскировано: %s", body)
	}
}

func TestErrorsFiltersCombine(t *testing.T) {
	e := newEnv(t)
	seedErrors(t, e, 40)
	h := errorsHandler(e)
	rows := func(url string) int {
		rec := get(h, url, "HX-Request", "true")
		return countRows(rec.Body.String())
	}
	if got := rows("/errors"); got != 40 {
		t.Fatalf("без фильтров: %d", got)
	}
	if got := rows("/errors?agent=ams-1"); got != 10 {
		t.Errorf("agent: %d", got)
	}
	if got := rows("/errors?phase=timeout"); got != 10 {
		t.Errorf("phase: %d", got)
	}
	if got := rows("/errors?agent=ams-1&phase=timeout&code=504"); got != 10 {
		t.Errorf("agent+phase+code: %d", got)
	}
	if got := rows("/errors?agent=fra-1&phase=timeout"); got != 0 {
		t.Errorf("пересечение пусто: %d", got)
	}
	if got := rows("/errors?bot_id=6801234567&code=429"); got != 0 {
		t.Errorf("bot+code: %d", got)
	}
	if got := rows("/errors?code=abc"); got != 40 {
		t.Errorf("мусорный code игнорируется: %d", got)
	}
	empty := get(h, "/errors?agent=nope", "HX-Request", "true").Body.String()
	if !strings.Contains(empty, "Ничего не найдено") {
		t.Errorf("нет пустого состояния фильтра")
	}
	// выбранные значения сохраняются в форме
	full := get(h, "/errors?agent=ams-1&phase=timeout&code=504&bot_id=6801234567&request_id=01JB").Body.String()
	for _, want := range []string{`value="ams-1" selected`, `value="timeout" selected`, `value="504" selected`, `value="6801234567"`, `value="01JB"`} {
		if !strings.Contains(full, want) {
			t.Errorf("фильтр не сохранён: %q", want)
		}
	}
}

func TestErrorsCursor(t *testing.T) {
	e := newEnv(t)
	seedErrors(t, e, 120)
	h := errorsHandler(e)
	first := get(h, "/errors", "HX-Request", "true").Body.String()
	if countRows(first) != 50 {
		t.Fatalf("первая страница: %d строк", countRows(first))
	}
	m := regexp.MustCompile(`hx-get="(/errors\?[^"]*cursor=[^"]*)"`).FindStringSubmatch(first)
	if m == nil {
		t.Fatalf("нет ссылки «Показать ещё»")
	}
	url := strings.ReplaceAll(m[1], "&amp;", "&")
	if !strings.Contains(first, `hx-target="closest tr"`) {
		t.Errorf("кнопка должна подменять свою строку")
	}
	second := get(h, url, "HX-Request", "true").Body.String()
	if strings.Contains(second, "<html") || strings.Contains(second, `id="errors-results"`) {
		t.Errorf("подгрузка должна отдавать только строки")
	}
	if countRows(second) != 50 || !strings.Contains(second, "errs-more-row") {
		t.Errorf("вторая страница: %d строк, more=%v", countRows(second), strings.Contains(second, "errs-more-row"))
	}
	m2 := regexp.MustCompile(`hx-get="(/errors\?[^"]*cursor=[^"]*)"`).FindStringSubmatch(second)
	third := get(h, strings.ReplaceAll(m2[1], "&amp;", "&"), "HX-Request", "true").Body.String()
	if countRows(third) != 20 || strings.Contains(third, "errs-more-row") {
		t.Errorf("последняя страница: %d строк", countRows(third))
	}
	// фильтры переносятся в ссылку курсора
	filtered := get(h, "/errors?agent=ams-1&phase=timeout", "HX-Request", "true").Body.String()
	if strings.Contains(filtered, "errs-more-row") {
		t.Errorf("30 записей не требуют второй страницы")
	}
	if get(h, "/errors?cursor=!!!", "HX-Request", "true").Code != 400 {
		t.Errorf("битый cursor -> 400")
	}
}

func TestErrorsHistoryRestoreFullPage(t *testing.T) {
	e := newEnv(t)
	body := get(errorsHandler(e), "/errors?phase=dial", "HX-Request", "true", "HX-History-Restore-Request", "true").Body.String()
	if !strings.Contains(body, "<html") {
		t.Errorf("нужна полная страница")
	}
}

// ---------- golden ----------

func TestGolden(t *testing.T) {
	vm := screens.OverviewVM{
		Range: "24h", PollMS: 5000, PollSec: 5, TimeseriesURL: screens.TimeseriesPath, SummaryURL: screens.SummaryPath,
		Ranges: []screens.RangeOpt{{Value: "1h", Label: "1ч"}, {Value: "24h", Label: "24ч", Active: true}},
		KPIs: []screens.KPIView{
			{Key: "rps", Label: "Запросов в секунду", Value: "341", Hint: "пик за 24 ч: 690"},
			{Key: "err_pct", Label: "Ошибки прокси", Value: "1,4 %", Hint: "502/504 за 5 мин", Tone: "warn"},
		},
		Agents: []screens.AgentRow{{Name: "fra-1", Addr: "185.12.4.10:8443", Status: "up", RPS: "96", P95: "182 мс", Err: "0,2 %", Inflight: "8", Version: "v1.3.9", VersionStale: true}},
		Events: []screens.EventRow{{Tone: "err", Text: "ist-1 недоступен", Meta: "14:32 · agent_down"}},
	}
	golden(t, "overview_body", screens.OverviewBody(vm))
	golden(t, "error_rows", screens.ErrorRows([]screens.ErrorRow{{
		Time: "14:32:18", RequestID: "01JBX4…Q2", RequestIDFull: "01JBX4ABCDEFGHQ2", BotID: "6123450001", Method: "sendMessage",
		Agent: "ist-1", Phase: "dial", PhaseTone: "warn", Code: "200", OutcomeText: "переотправлен", OutcomeTone: "ok",
		Description: "connect: <i/o> timeout",
	}}, "/errors?cursor=abc&phase=dial"))
}
