package screens_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type errPurgeFx struct {
	*fx
	sid *http.Cookie
}

func newErrPurgeFx(t *testing.T) *errPurgeFx {
	t.Helper()
	f := newFx(t, false)
	q := &history.Query{History: f.st.History(), ErrorRepo: f.st.Errors(), Now: f.clock.now}
	d := screens.ErrorsDeps{
		Shell: f.rt, Source: q, Location: time.UTC, Now: f.clock.now,
		Purge: api.NewErrorsPurgeService(f.st.Errors(), f.st.Audit(), nil, f.clock.now),
	}
	f.rt.Mount("GET /errors", auth.Protect(f.a.RequireAuth(screens.NewErrors(d))))
	screens.MountErrorsPurge(f.rt, f.a, d)
	return &errPurgeFx{fx: f, sid: f.sessionCookie("alice")}
}

func (e *errPurgeFx) call(method, path string, form url.Values, hdr map[string]string, session bool) *struct {
	Code int
	Body string
	Hdr  http.Header
} {
	var cs []*http.Cookie
	if session {
		cs = []*http.Cookie{e.sid}
	}
	w := e.do(req{method: method, path: path, form: form, hdr: hdr, cookies: cs})
	return &struct {
		Code int
		Body string
		Hdr  http.Header
	}{w.Code, w.Body.String(), w.Header()}
}

// seed кладёт события заданного возраста (часы назад) с фазой dial/timeout.
func (e *errPurgeFx) seed(phase string, hours ...int) {
	e.t.Helper()
	for i, h := range hours {
		_, err := e.st.Errors().Append(context.Background(), store.ErrorEvent{
			At: e.clock.now().Add(-time.Duration(h) * time.Hour), RequestID: fmt.Sprintf("%s-%d-%d", phase, h, i),
			Outcome: store.OutcomeRetried, Phase: phase, Code: 200, AgentID: "a1",
		})
		if err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *errPurgeFx) left() int {
	l, err := e.st.Errors().List(context.Background(), store.ErrorQuery{Limit: 1000})
	if err != nil {
		e.t.Fatal(err)
	}
	return len(l)
}

func TestErrorsPurgeButtonAndModal(t *testing.T) {
	e := newErrPurgeFx(t)
	e.seed("dial", 1)
	page := e.call("GET", "/errors", nil, nil, true)
	for _, want := range []string{"Очистить журнал", `hx-get="/errors/purge"`, `id="errors-purge-modal"`, `id="errors-filters"`, `id="errors-kpis"`} {
		if !strings.Contains(page.Body, want) {
			t.Errorf("нет %q", want)
		}
	}
	form := e.call("GET", "/errors/purge", nil, hx, true)
	if form.Code != 200 {
		t.Fatal(form.Code)
	}
	for _, want := range []string{"нельзя", "Всё", "30 дней", "15 дней", "5 дней", "3 дня", `name="keep_days"`, `hx-post="/errors/purge"`, `hx-include="#errors-filters"`} {
		if !strings.Contains(form.Body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if r := e.call("GET", "/errors/purge", nil, nil, true); r.Code != http.StatusSeeOther {
		t.Errorf("без htmx: %d", r.Code)
	}
	// без Purge-сервиса кнопки нет
	plain := get(errorsHandler(newEnv(t)), "/errors").Body.String()
	if strings.Contains(plain, "Очистить журнал") {
		t.Error("кнопка без сервиса очистки")
	}
}

func TestErrorsPurgeAuthCSRF(t *testing.T) {
	e := newErrPurgeFx(t)
	e.seed("dial", 1)
	if r := e.call("GET", "/errors/purge", nil, nil, false); r.Code != http.StatusFound || r.Hdr.Get("Location") != "/login" {
		t.Errorf("GET без сессии: %d", r.Code)
	}
	form := url.Values{"keep_days": {"0"}}
	if r := e.call("POST", "/errors/purge", form, hx, false); r.Code != 401 {
		t.Errorf("POST без сессии: %d", r.Code)
	}
	cross := map[string]string{"HX-Request": "true", "Sec-Fetch-Site": "cross-site"}
	if r := e.call("POST", "/errors/purge", form, cross, true); r.Code != 403 {
		t.Errorf("cross-site: %d", r.Code)
	}
	if r := e.call("POST", "/errors/purge", form, nil, true); r.Code != 400 {
		t.Errorf("без htmx: %d", r.Code)
	}
	if e.left() != 1 {
		t.Fatal("журнал изменился без авторизации/CSRF")
	}
}

func TestErrorsPurgeInvalid(t *testing.T) {
	e := newErrPurgeFx(t)
	e.seed("dial", 1, 100)
	for _, v := range []string{"", "7", "-1", "abc"} {
		r := e.call("POST", "/errors/purge", url.Values{"keep_days": {v}}, hx, true)
		if r.Code != 422 || !strings.Contains(r.Body, "Выберите вариант") {
			t.Errorf("%q: %d", v, r.Code)
		}
	}
	if e.left() != 2 {
		t.Fatal("невалидный запрос стёр записи")
	}
}

func TestErrorsPurgeKeepDays(t *testing.T) {
	for _, days := range []int{3, 5, 15, 30} {
		t.Run(strconv.Itoa(days), func(t *testing.T) {
			e := newErrPurgeFx(t)
			e.seed("dial", 1, days*24-1, days*24+1, 40*24)
			r := e.call("POST", "/errors/purge", url.Values{"keep_days": {strconv.Itoa(days)}}, hx, true)
			if r.Code != 200 {
				t.Fatalf("%d %s", r.Code, r.Body)
			}
			if !strings.Contains(r.Hdr.Get("HX-Trigger"), `удалено`) && !strings.Contains(r.Hdr.Get("HX-Trigger"), "toast") {
				t.Errorf("нет тоста: %q", r.Hdr.Get("HX-Trigger"))
			}
			if !strings.Contains(r.Hdr.Get("HX-Trigger"), ": 2") {
				t.Errorf("тост без числа 2: %q", r.Hdr.Get("HX-Trigger"))
			}
			if e.left() != 2 {
				t.Fatalf("осталось %d", e.left())
			}
			for _, want := range []string{`id="errors-results"`, `hx-swap-oob="true"`, `id="errors-kpis"`, `id="errors-purge-wrap"`} {
				if !strings.Contains(r.Body, want) {
					t.Errorf("нет %q", want)
				}
			}
			if countRows(r.Body) != 2 {
				t.Errorf("в списке %d строк", countRows(r.Body))
			}
		})
	}
}

func TestErrorsPurgeAllResetsKPI(t *testing.T) {
	e := newErrPurgeFx(t)
	e.seed("timeout", 100, 4) // от старых к новым: KPI читают журнал от новых и останавливаются на первой записи старше 24 ч
	e.seed("dial", 3, 2, 1)
	before := e.call("GET", "/errors", nil, nil, true).Body
	if !strings.Contains(before, `<div class="phase-value mono">3</div>`) {
		t.Fatalf("KPI dial/tls до очистки: %s", before)
	}
	r := e.call("POST", "/errors/purge", url.Values{"keep_days": {"0"}}, hx, true)
	if r.Code != 200 || e.left() != 0 {
		t.Fatalf("%d, осталось %d", r.Code, e.left())
	}
	if !strings.Contains(r.Hdr.Get("HX-Trigger"), ": 5") || countRows(r.Body) != 0 || !strings.Contains(r.Body, "Ошибок нет") {
		t.Errorf("ответ: trigger=%q rows=%d", r.Hdr.Get("HX-Trigger"), countRows(r.Body))
	}
	if strings.Contains(r.Body, `<div class="phase-value mono">3</div>`) || strings.Count(r.Body, `<div class="phase-value mono">0</div>`) != 6 {
		t.Errorf("KPI после очистки не обнулились: %s", r.Body)
	}
	after := e.call("GET", "/errors", nil, nil, true).Body
	if strings.Count(after, `<div class="phase-value mono">0</div>`) != 6 {
		t.Error("KPI на странице после очистки")
	}
	// аудит
	es, _ := e.st.Audit().List(context.Background(), store.AuditQuery{Limit: 10})
	if len(es) != 1 || es[0].Action != api.AuditErrorsPurge || es[0].Actor != "alice" || !strings.Contains(es[0].Detail, "keep_days=0 deleted=5") {
		t.Errorf("аудит: %+v", es)
	}
}

func TestErrorsPurgeKeepsFilters(t *testing.T) {
	e := newErrPurgeFx(t)
	e.seed("dial", 1, 100)
	e.seed("timeout", 2, 200)
	r := e.call("POST", "/errors/purge", url.Values{"keep_days": {"5"}, "phase": {"timeout"}}, hx, true)
	if r.Code != 200 || e.left() != 3 || countRows(r.Body) != 1 {
		t.Fatalf("%d left=%d rows=%d", r.Code, e.left(), countRows(r.Body))
	}
}

func TestErrorsPurgeGolden(t *testing.T) {
	cases := map[string]templ.Component{
		"errors_purge_form":       screens.ErrorsPurgeForm(screens.ErrorsPurgeVM{Opts: screensPurgeOpts(), Selected: "30"}),
		"errors_purge_form_error": screens.ErrorsPurgeForm(screens.ErrorsPurgeVM{Opts: screensPurgeOpts(), Err: "Выберите вариант очистки."}),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { accGolden(t, name, c) })
	}
}

func screensPurgeOpts() []screens.PurgeOpt {
	return []screens.PurgeOpt{{Days: "0", Label: "Всё"}, {Days: "30", Label: "30 дней"}}
}
