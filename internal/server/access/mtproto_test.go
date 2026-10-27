package access

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func TestMTProtoReasons(t *testing.T) {
	for r, ban := range map[Reason]bool{ReasonMTProtoReplay: true, ReasonMTProtoConnLimit: false, ReasonMTProtoBadSecret: false} {
		if !r.Valid() {
			t.Errorf("%s not in Reasons", r)
		}
		if r.CountsForBan() != ban {
			t.Errorf("%s CountsForBan=%v, want %v", r, r.CountsForBan(), ban)
		}
	}
}

func TestMTProtoErrorEvent(t *testing.T) {
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	ev := MTProtoErrorEvent(at, netip.MustParseAddr("198.51.100.7"), ReasonMTProtoReplay)
	if ev.Phase != tgapi.PhaseMTProto || ev.ClientIP != "198.51.100.7" ||
		ev.Reason != "mtproto_replay" || !ev.At.Equal(at) {
		t.Fatalf("event: %+v", ev)
	}
	if strings.Contains(ev.Description, "ee") && len(ev.Description) > 64 {
		t.Fatalf("description: %q", ev.Description)
	}
	if MTProtoErrorEvent(at, netip.Addr{}, ReasonMTProtoBadSecret).ClientIP != "" {
		t.Fatal("invalid ip must give empty ClientIP")
	}
}
