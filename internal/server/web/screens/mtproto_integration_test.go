package screens_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

type mtLive struct {
	enabled bool
	conns   int
	bps     float64
}

func (m mtLive) MTProtoLive() (bool, int, float64) { return m.enabled, m.conns, m.bps }

func mtOverview(e *env, m screens.MTProtoLive) string {
	h := screens.NewOverview(screens.OverviewDeps{
		Shell: e.shell, Stats: e.q, MTProto: m, Location: time.UTC, Now: func() time.Time { return t0 },
	})
	return get(h, "/").Body.String()
}

func TestOverviewMTProtoKPI(t *testing.T) {
	e := newEnv(t)
	body := mtOverview(e, mtLive{enabled: true, conns: 1234, bps: 1_250_000})
	for _, want := range []string{`data-kpi-card="mtproto"`, "MTProto: соединения, полоса", `data-kpi="mtproto"`, ">1234<", "10,0 Мбит/с", `data-mtproto="1"`, "legend-mt"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	for name, m := range map[string]screens.MTProtoLive{"enabled:false": mtLive{}, "nil": nil} {
		b := mtOverview(e, m)
		for _, bad := range []string{`data-kpi-card="mtproto"`, "data-mtproto", "legend-mt", "MTProto: соединения"} {
			if strings.Contains(b, bad) {
				t.Errorf("%s: %q не должно быть", name, bad)
			}
		}
	}
}

func TestMTProtoOverviewGolden(t *testing.T) {
	vm := screens.OverviewVM{
		Range: "24h", PollMS: 5000, PollSec: 5, TimeseriesURL: screens.TimeseriesPath, SummaryURL: screens.SummaryPath,
		Ranges: []screens.RangeOpt{{Value: "24h", Label: "24ч", Active: true}}, MTProto: true,
		KPIs: []screens.KPIView{
			{Key: "rps", Label: "Запросов в секунду", Value: "341", Hint: "пик за 24 ч: 690"},
			{Key: "mtproto", Label: "MTProto: соединения, полоса", Value: "1234", Hint: "полоса 10,0 Мбит/с"},
		},
	}
	golden(t, "overview_body_mtproto", screens.OverviewBody(vm))
}

func TestMTProtoAgentsChip(t *testing.T) {
	a := newAgFx(t, agOpts{})
	a.fleet.states[0].LastStatus.Capabilities = []string{transport.CapMTProto}
	a.fleet.states[0].LastStatus.MTProto = &transport.MTProtoStatus{DC: map[string]transport.DCStatus{
		"4": {Up: false}, "2": {Up: true, RTTMs: 34},
	}}
	_, body, _ := a.call("GET", "/agents", nil, true)
	if n := strings.Count(body, ">MTProto<"); n != 1 {
		t.Errorf("чип MTProto: %d, ожидали 1 (только fra-1)", n)
	}
	_, more, _ := a.call("GET", "/agents/fra-1/more", nil, true)
	contains(t, "more", more, "DC2", "34 мс", "DC4", "недоступен")
	golden(t, "agent_more_mtproto", screens.MoreCard(screens.MoreVM{
		Row: screens.AgentRowVM{ID: "fra-1", Name: "fra-1", Addr: "185.12.4.10:8443", LinkLabel: "→ агент", Cert: "71 д", Version: "v1.4.1",
			MTProto: true, DC: []screens.DCVM{{Name: "DC2", Up: true, RTT: "34 мс"}, {Name: "DC4"}}},
		CanRemove: true,
	}))
	_, plain, _ := a.call("GET", "/agents/hel-1/more", nil, true)
	if strings.Contains(plain, "MTProto") {
		t.Errorf("агент без capability: блок MTProto не нужен")
	}
}

func TestMTProtoErrorsFilter(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i, reason := range []string{"mtproto_replay", "mtproto_conn_limit", "mtproto_bad_secret"} {
		_, err := e.st.Errors().Append(ctx, store.ErrorEvent{
			At: t0.Add(-time.Duration(i+1) * time.Minute), RequestID: "01JBX4MT" + reason[8:10], Phase: "mtproto",
			Code: 403, Outcome: store.OutcomeFailedToBot, Description: "mtproto denied", ClientIP: "203.0.113.9", Reason: reason,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	body := get(errorsHandler(e), "/errors?phase=mtproto").Body.String()
	for _, want := range []string{`value="mtproto" selected`, "MTProto: повтор рукопожатия", "MTProto: лимит соединений", "MTProto: неверный секрет",
		`value="mtproto_replay"`, `value="mtproto_conn_limit"`, `value="mtproto_bad_secret"`} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q", want)
		}
	}
	if n := countRows(body); n != 3 {
		t.Errorf("строк %d, ожидали 3", n)
	}
}
