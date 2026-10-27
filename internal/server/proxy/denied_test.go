package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/ban"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type sink struct {
	mu sync.Mutex
	ev []store.ErrorEvent
}

func (s *sink) Record(_ context.Context, e store.ErrorEvent) {
	s.mu.Lock()
	s.ev = append(s.ev, e)
	s.mu.Unlock()
}

type geoStub struct{}

func (geoStub) Lookup(a netip.Addr) string {
	if a == netip.MustParseAddr("203.0.113.9") {
		return "NL"
	}
	return ""
}

type deniedRig struct {
	*env
	reasons []string
	errs    *sink
	mgr     *ban.Manager
}

func newDeniedRig(t *testing.T, threshold int) *deniedRig {
	t.Helper()
	r := &deniedRig{errs: &sink{}}
	mgr, err := ban.New(context.Background(), memtest.New().Bans(), ban.Options{Config: config.BanConfig{
		Enabled: true, Threshold: threshold, Window: time.Minute, Duration: time.Hour,
		ResetAfter: 24 * time.Hour, MaxTracked: 100,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Wait)
	r.mgr = mgr
	var mu sync.Mutex
	r.env = setupOpts(t, func(c *config.ServerConfig) {
		// правило «сеть И ключ» — сценарий из продакшена
		c.AccessRules = []config.AccessRule{{
			Name: "lan-key", CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			KeySHA256: "x", KeyHash: access.HashKey("secret"),
		}}
	}, WithBans(mgr), WithErrorLog(r.errs), WithGeo(geoStub{}), WithDenied(func(reason string) {
		mu.Lock()
		r.reasons = append(r.reasons, reason)
		mu.Unlock()
	}))
	return r
}

func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestDeniedLogMetricsAndJournal(t *testing.T) {
	r := newDeniedRig(t, 100)
	w := r.do("POST", "/bot"+tok+"/sendMessage", "203.0.113.9:5555", nil, nil)
	errDesc(t, w, 403, descDenied)
	w = r.do("POST", "/k/wrong/bot"+tok+"/getMe", "203.0.113.9:5555", nil, nil)
	errDesc(t, w, 403, descDenied)
	w = r.do("POST", "/bot"+tok+"/sendMessage", "8.8.8.8:1", nil, nil)
	errDesc(t, w, 403, descDenied)

	if got := strings.Join(r.reasons, ","); got != "key_required,bad_key,no_rule" {
		t.Fatalf("reasons %s", got)
	}
	logs := logLines(t, r.log)
	if len(logs) != 3 {
		t.Fatalf("log lines %d: %s", len(logs), r.log)
	}
	l := logs[0]
	if l["msg"] != "request" || l["client_ip"] != "203.0.113.9" || l["reason"] != "key_required" || l["country"] != "NL" || l["status"] != float64(403) {
		t.Fatalf("log %v", l)
	}
	if strings.Contains(r.log.String(), tok) || tokRe.MatchString(r.log.String()) || strings.Contains(r.log.String(), "secret") {
		t.Fatalf("token or key leaked into log: %s", r.log)
	}
	if len(r.errs.ev) != 3 {
		t.Fatalf("events %+v", r.errs.ev)
	}
	e := r.errs.ev[0]
	if e.Phase != "access" || e.Reason != "key_required" || e.ClientIP != "203.0.113.9" || e.Code != 403 ||
		e.BotID != "123456" || e.Method != "sendmessage" || e.Outcome != store.OutcomeFailedToBot || strings.Contains(e.Description, tok) {
		t.Fatalf("event %+v", e)
	}
	if r.up.req != nil {
		t.Fatal("agent must not be touched")
	}
	// легитимный запрос проходит и в журнал отказов не попадает
	w = r.do("POST", "/k/secret/bot"+tok+"/getMe", "203.0.113.9:1", nil, nil)
	if w.Code != 200 || len(r.errs.ev) != 3 {
		t.Fatalf("ok request: %d %d", w.Code, len(r.errs.ev))
	}
}

func TestBanBeforeRulesAndAgents(t *testing.T) {
	r := newDeniedRig(t, 3)
	for range 3 {
		errDesc(t, r.do("POST", "/bot"+tok+"/sendMessage", "203.0.113.9:1", nil, nil), 403, descDenied)
	}
	r.mgr.Wait()
	if !r.mgr.Banned(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("not banned after threshold")
	}
	r.up.req = nil
	r.reasons = nil
	n := len(r.errs.ev)
	// теперь даже запрос с правильным ключом отбивается баном, а агент не трогается
	w := r.do("POST", "/k/secret/bot"+tok+"/sendMessage", "203.0.113.9:1", nil, nil)
	errDesc(t, w, 403, descDenied)
	if r.up.req != nil {
		t.Fatal("banned request reached the agent")
	}
	if strings.Join(r.reasons, ",") != "banned" {
		t.Fatalf("reasons %v", r.reasons)
	}
	if len(r.errs.ev) != n {
		t.Fatal("banned requests must not flood the error journal")
	}
	last := logLines(t, r.log)
	l := last[len(last)-1]
	if l["reason"] != "banned" || l["client_ip"] != "203.0.113.9" || l["level"] != "DEBUG" {
		t.Fatalf("banned log %v", l)
	}
	// мусорный путь от забаненного — тоже 403 (проверка до разбора пути)
	errDesc(t, r.do("GET", "/wp-login.php", "203.0.113.9:1", nil, nil), 403, descDenied)
	// другой клиент не затронут
	if w := r.do("POST", "/k/secret/bot"+tok+"/getMe", "203.0.113.10:1", nil, nil); w.Code != 200 {
		t.Fatalf("other client: %d", w.Code)
	}
}

func TestRateLimitedNotCountedForBan(t *testing.T) {
	r := newDeniedRig(t, 2)
	// 429 от лимита правила: проверяем напрямую через Record — rate_limited игнорируется
	for range 10 {
		r.mgr.Record(netip.MustParseAddr("203.0.113.9"), access.ReasonRateLimited)
	}
	r.mgr.Wait()
	if r.mgr.Banned(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("rate_limited must not ban")
	}
}
