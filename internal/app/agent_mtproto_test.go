package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

type fakeLimits struct{ got config.AgentMTProtoConfig }

func (f *fakeLimits) SetMTProtoLimits(c config.AgentMTProtoConfig) { f.got = c }

func TestApplyAgentMTProtoReload(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cur := config.AgentMTProtoConfig{Enabled: true, MaxStreams: 1}
	f := &fakeLimits{}

	next := cur
	next.MaxStreams = 7
	next.DCProbeInterval = time.Minute
	applyAgentMTProtoReload(f, logger, cur, next)
	if f.got != next || buf.Len() != 0 {
		t.Fatalf("limits not applied or unexpected log: %+v %q", f.got, buf.String())
	}

	next.Enabled = false
	applyAgentMTProtoReload(f, logger, cur, next)
	if !strings.Contains(buf.String(), "restart required") {
		t.Fatalf("нет предупреждения: %q", buf.String())
	}
}
