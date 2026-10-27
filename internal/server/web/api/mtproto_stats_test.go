package api_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type fakeMTSrc struct{ s api.MTProtoStats }

func (f fakeMTSrc) Snapshot() api.MTProtoStats { return f.s }

func mtMux(src api.MTProtoStatsSource) *http.ServeMux {
	mux := http.NewServeMux()
	(&api.MTProtoStatsAPI{Source: src}).Routes(mux, nil)
	return mux
}

func TestMTProtoStatsShape(t *testing.T) {
	src := fakeMTSrc{api.MTProtoStats{
		Enabled: true,
		Agents: []api.MTProtoAgentStat{
			{AgentID: "b", Capable: false},
			{AgentID: "a", Capable: true, Streams: 3, DC: []api.MTProtoDCStat{
				{DC: 4, Up: false}, {DC: 2, Up: true, RTTMs: 12.5, Streams: 3, Errors: 1},
			}},
		},
		Totals: api.MTProtoTotals{ActiveConns: 7, BytesIn: 10, BytesOut: 20, SecretsActive: 2},
	}}
	rec := do(mtMux(src), "/api/v1/mtproto/stats")
	if rec.Code != 200 {
		t.Fatalf("code=%d", rec.Code)
	}
	var got map[string]any
	decode(t, rec, &got)
	want := map[string]any{
		"enabled": true,
		"agents": []any{
			map[string]any{"agent_id": "a", "capable": true, "streams": 3.0, "dc": []any{
				map[string]any{"dc": 2.0, "up": true, "rtt_ms": 12.5, "streams": 3.0, "errors": 1.0},
				map[string]any{"dc": 4.0, "up": false, "rtt_ms": 0.0, "streams": 0.0, "errors": 0.0},
			}},
			map[string]any{"agent_id": "b", "capable": false, "streams": 0.0, "dc": []any{}},
		},
		"totals": map[string]any{"active_conns": 7.0, "bytes_in": 10.0, "bytes_out": 20.0, "secrets_active": 2.0},
	}
	if !reflect.DeepEqual(got, want) {
		b, _ := json.MarshalIndent(got, "", " ")
		t.Fatalf("форма JSON:\n%s", b)
	}
}

func TestMTProtoStatsDisabledEmptyMatrix(t *testing.T) {
	src := fakeMTSrc{api.MTProtoStats{
		Enabled: false,
		Agents:  []api.MTProtoAgentStat{{AgentID: "a", DC: []api.MTProtoDCStat{{DC: 2}}}},
		Totals:  api.MTProtoTotals{ActiveConns: 5},
	}}
	for name, s := range map[string]api.MTProtoStatsSource{"disabled": src, "nil": nil} {
		var got api.MTProtoStats
		decode(t, do(mtMux(s), "/api/v1/mtproto/stats"), &got)
		if got.Enabled || len(got.Agents) != 0 || got.Totals != (api.MTProtoTotals{}) {
			t.Fatalf("%s: %+v", name, got)
		}
		raw := do(mtMux(s), "/api/v1/mtproto/stats").Body.String()
		if want := `{"enabled":false,"agents":[],"totals":{"active_conns":0,"bytes_in":0,"bytes_out":0,"secrets_active":0}}`; trim(raw) != want {
			t.Fatalf("%s: %s", name, raw)
		}
	}
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

func TestMTProtoStatsRequiresAuth(t *testing.T) {
	mux := http.NewServeMux()
	deny := api.Wrap(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	})
	(&api.MTProtoStatsAPI{}).Routes(mux, deny)
	rec := do(mux, "/api/v1/mtproto/stats")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestTimeseriesMTProtoSeries(t *testing.T) {
	st := memtest.New()
	q := &history.Query{History: st.History(), ErrorRepo: st.Errors(), Now: func() time.Time { return t0 }}
	_ = st.History().Append(t.Context(), store.Res10s, []store.Sample{
		{At: t0.Add(-30 * time.Second), AgentID: history.AggregateID, MTConns: 4, MTBytesIn: 100, MTBytesOut: 200},
	})
	mux := http.NewServeMux()
	(&api.StatsAPI{Stats: q}).Routes(mux, nil)
	var s struct {
		Points []map[string]any `json:"points"`
	}
	decode(t, do(mux, "/api/v1/stats/timeseries?range=1h"), &s)
	if len(s.Points) != 1 || s.Points[0]["mtproto_conns"] != 4.0 || s.Points[0]["mtproto_bps"] != 30.0 {
		t.Fatalf("%+v", s.Points)
	}
}

func TestErrorsPhaseMTProtoFilter(t *testing.T) {
	st := memtest.New()
	q := &history.Query{History: st.History(), ErrorRepo: st.Errors(), Now: func() time.Time { return t0 }}
	mux := http.NewServeMux()
	(&api.ErrorsAPI{Source: q}).Routes(mux, nil)
	if rec := do(mux, "/api/v1/errors?phase=mtproto"); rec.Code != 200 {
		t.Fatalf("code=%d %s", rec.Code, rec.Body)
	}
}
