package metrics

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func cmp(t *testing.T, c prometheus.Collector, exp, name string) {
	t.Helper()
	if err := testutil.CollectAndCompare(c, strings.NewReader(exp), name); err != nil {
		t.Fatal(err)
	}
}

func TestServerMTProtoMetrics(t *testing.T) {
	_, s := NewServerRegistry()
	m := s.mtp

	s.MTProtoClientConns("shared", 2)
	s.MTProtoClientConns("shared", -1)
	s.MTProtoClientConns("weird", 1)
	cmp(t, m.clientConns, `
# HELP tgp_mtproto_client_conns Active MTProto client connections (listener: shared|dedicated).
# TYPE tgp_mtproto_client_conns gauge
tgp_mtproto_client_conns{listener="other"} 1
tgp_mtproto_client_conns{listener="shared"} 1
`, "tgp_mtproto_client_conns")

	s.MTProtoConnection("alice", "ok")
	s.MTProtoConnection("alice", "bogus")
	cmp(t, m.conns, `
# HELP tgp_mtproto_connections_total MTProto connections by secret name and result (ok|replay|conn_limit|no_agents|upstream_error|closed).
# TYPE tgp_mtproto_connections_total counter
tgp_mtproto_connections_total{result="closed",secret="alice"} 1
tgp_mtproto_connections_total{result="ok",secret="alice"} 1
`, "tgp_mtproto_connections_total")

	s.MTProtoHandshakeFailure("timeout")
	s.MTProtoHandshakeFailure("zzz")
	cmp(t, m.hsFail, `
# HELP tgp_mtproto_handshake_failures_total Failed FakeTLS handshakes (timeout|bad_record|replay|time_skew|conn_limit).
# TYPE tgp_mtproto_handshake_failures_total counter
tgp_mtproto_handshake_failures_total{reason="bad_record"} 1
tgp_mtproto_handshake_failures_total{reason="timeout"} 1
`, "tgp_mtproto_handshake_failures_total")

	s.MTProtoFallthrough()
	cmp(t, m.fallthroughTotal, `
# HELP tgp_mtproto_fallthrough_total Connections handed over to the TLS fronting site.
# TYPE tgp_mtproto_fallthrough_total counter
tgp_mtproto_fallthrough_total 1
`, "tgp_mtproto_fallthrough_total")

	s.MTProtoBytes("a1", "in", 10)
	s.MTProtoBytes("a1", "out", 5)
	s.MTProtoBytes("a1", "out", -1)
	s.MTProtoBytes("a1", "sideways", 7)
	cmp(t, m.bytes, `
# HELP tgp_mtproto_bytes_total MTProto bytes via agents (direction: in = client to Telegram, out = Telegram to client).
# TYPE tgp_mtproto_bytes_total counter
tgp_mtproto_bytes_total{agent="a1",direction="in"} 10
tgp_mtproto_bytes_total{agent="a1",direction="out"} 5
`, "tgp_mtproto_bytes_total")

	s.MTProtoStreams("a1", 2, 1)
	s.MTProtoStreams("a1", 2, 1)
	s.MTProtoStreams("a1", 2, -1)
	cmp(t, m.streams, `
# HELP tgp_mtproto_streams Active MTProto streams per agent and DC.
# TYPE tgp_mtproto_streams gauge
tgp_mtproto_streams{agent="a1",dc="2"} 1
`, "tgp_mtproto_streams")

	s.SetMTProtoDC("a1", 2, true, 50*time.Millisecond)
	s.SetMTProtoDC("a1", 4, false, time.Second)
	cmp(t, m.dcUp, `
# HELP tgp_mtproto_dc_up 1 if the DC is reachable from the agent.
# TYPE tgp_mtproto_dc_up gauge
tgp_mtproto_dc_up{agent="a1",dc="2"} 1
tgp_mtproto_dc_up{agent="a1",dc="4"} 0
`, "tgp_mtproto_dc_up")
	cmp(t, m.dcRTT, `
# HELP tgp_mtproto_dc_rtt_seconds Last probed RTT from the agent to the DC.
# TYPE tgp_mtproto_dc_rtt_seconds gauge
tgp_mtproto_dc_rtt_seconds{agent="a1",dc="2"} 0.05
tgp_mtproto_dc_rtt_seconds{agent="a1",dc="4"} 0
`, "tgp_mtproto_dc_rtt_seconds")

	s.SetMTProtoDCs("a1", map[int]DCState{5: {Up: true, RTT: time.Second}})
	if n := testutil.CollectAndCount(m.dcUp); n != 1 {
		t.Fatalf("SetMTProtoDCs must replace the set, got %d series", n)
	}

	s.MTProtoUpstreamError("a1", 2, "dial")
	s.MTProtoUpstreamError("a1", 2, "x")
	cmp(t, m.upErrors, `
# HELP tgp_mtproto_upstream_errors_total Errors opening MTProto streams via agents.
# TYPE tgp_mtproto_upstream_errors_total counter
tgp_mtproto_upstream_errors_total{agent="a1",dc="2",phase="dial"} 1
tgp_mtproto_upstream_errors_total{agent="a1",dc="2",phase="other"} 1
`, "tgp_mtproto_upstream_errors_total")

	s.MTProtoSession(2 * time.Second)
	cmp(t, m.session, `
# HELP tgp_mtproto_session_duration_seconds Duration of finished MTProto sessions.
# TYPE tgp_mtproto_session_duration_seconds histogram
tgp_mtproto_session_duration_seconds_bucket{le="1"} 0
tgp_mtproto_session_duration_seconds_bucket{le="5"} 1
tgp_mtproto_session_duration_seconds_bucket{le="15"} 1
tgp_mtproto_session_duration_seconds_bucket{le="60"} 1
tgp_mtproto_session_duration_seconds_bucket{le="300"} 1
tgp_mtproto_session_duration_seconds_bucket{le="900"} 1
tgp_mtproto_session_duration_seconds_bucket{le="3600"} 1
tgp_mtproto_session_duration_seconds_bucket{le="14400"} 1
tgp_mtproto_session_duration_seconds_bucket{le="86400"} 1
tgp_mtproto_session_duration_seconds_bucket{le="+Inf"} 1
tgp_mtproto_session_duration_seconds_sum 2
tgp_mtproto_session_duration_seconds_count 1
`, "tgp_mtproto_session_duration_seconds")

	s.ForgetAgent("a1")
	if n := testutil.CollectAndCount(m.dcUp) + testutil.CollectAndCount(m.streams) +
		testutil.CollectAndCount(m.bytes) + testutil.CollectAndCount(m.upErrors); n != 0 {
		t.Fatalf("ForgetAgent left %d mtproto series", n)
	}
}

func TestAgentMTProtoMetrics(t *testing.T) {
	_, a := NewAgentRegistry()
	a.MTProtoStreams(2, 1)
	a.MTProtoStreams(2, 1)
	a.MTProtoStreams(2, -1)
	cmp(t, a.mtp.streams, `
# HELP tgp_agent_mtproto_streams Active MTProto streams of the agent per DC.
# TYPE tgp_agent_mtproto_streams gauge
tgp_agent_mtproto_streams{dc="2"} 1
`, "tgp_agent_mtproto_streams")

	a.MTProtoDialError(2, "refused")
	a.MTProtoDialError(2, "weird")
	cmp(t, a.mtp.dialErr, `
# HELP tgp_agent_mtproto_dial_errors_total MTProto DC dial errors.
# TYPE tgp_agent_mtproto_dial_errors_total counter
tgp_agent_mtproto_dial_errors_total{dc="2",kind="other"} 1
tgp_agent_mtproto_dial_errors_total{dc="2",kind="refused"} 1
`, "tgp_agent_mtproto_dial_errors_total")

	a.MTProtoBytes("in", 3)
	a.MTProtoBytes("out", 0)
	a.MTProtoBytes("x", 3)
	cmp(t, a.mtp.bytes, `
# HELP tgp_agent_mtproto_bytes_total MTProto bytes relayed (in = client to DC, out = DC to client).
# TYPE tgp_agent_mtproto_bytes_total counter
tgp_agent_mtproto_bytes_total{direction="in"} 3
`, "tgp_agent_mtproto_bytes_total")
}

func TestMTProtoLintAndNoSecretsInExposition(t *testing.T) {
	sreg, s := NewServerRegistry()
	areg, a := NewAgentRegistry()
	s.MTProtoClientConns("shared", 1)
	s.MTProtoConnection("alice", "ok")
	s.MTProtoHandshakeFailure("replay")
	s.MTProtoFallthrough()
	s.MTProtoBytes("a1", "in", 1)
	s.MTProtoStreams("a1", 2, 1)
	s.SetMTProtoDC("a1", 2, true, time.Millisecond)
	s.MTProtoUpstreamError("a1", 2, "dial")
	s.MTProtoSession(time.Second)
	a.MTProtoStreams(2, 1)
	a.MTProtoDialError(2, "dns")
	a.MTProtoBytes("out", 1)

	ipRe := regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-fA-F:]{2,}::[0-9a-fA-F:]*`)
	keyRe := regexp.MustCompile(`(?i)\bee[0-9a-f]{32,}|[0-9a-f]{32,}`)
	for name, reg := range map[string]*prometheus.Registry{"server": sreg, "agent": areg} {
		if p, err := testutil.GatherAndLint(reg); err != nil || len(p) != 0 {
			t.Errorf("%s: lint err=%v problems=%v", name, err, p)
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if !strings.Contains(mf.GetName(), "mtproto") {
				continue
			}
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if ipRe.MatchString(lp.GetValue()) || keyRe.MatchString(lp.GetValue()) {
						t.Errorf("%s: label %s=%q looks like IP/key", mf.GetName(), lp.GetName(), lp.GetValue())
					}
				}
			}
		}
	}
}
