package transport

import (
	"encoding/json"
	"testing"
)

func TestAgentStatusOldJSON(t *testing.T) {
	var st AgentStatus
	old := `{"version":"v1","commit":"c","uptime_s":5,"inflight":1,"rps_1m":0.5,"errors_by_phase":{},"upstream_rtt_ms":3,"draining":false,"cert_not_after":"2030-01-01T00:00:00Z"}`
	if err := json.Unmarshal([]byte(old), &st); err != nil {
		t.Fatal(err)
	}
	if st.MTProto != nil || len(st.Capabilities) != 0 || st.HasCapability(CapMTProto) {
		t.Fatalf("старый статус не должен содержать mtproto: %+v", st)
	}
}

func TestAgentStatusMTProto(t *testing.T) {
	var st AgentStatus
	in := `{"capabilities":["mtproto/1"],"mtproto":{"streams":3,"dc":{"2":{"up":true,"rtt_ms":12.5},"4":{"up":false,"rtt_ms":0}}}}`
	if err := json.Unmarshal([]byte(in), &st); err != nil {
		t.Fatal(err)
	}
	if !st.HasCapability(CapMTProto) || st.MTProto == nil || st.MTProto.Streams != 3 {
		t.Fatalf("статус: %+v", st)
	}
	if d := st.MTProto.DC["2"]; !d.Up || d.RTTMs != 12.5 {
		t.Fatalf("dc 2: %+v", d)
	}
	if st.MTProto.DC["4"].Up {
		t.Fatal("dc 4 должен быть down")
	}
	var nilSt *AgentStatus
	if nilSt.HasCapability(CapMTProto) {
		t.Fatal("nil-статус без capability")
	}
}
