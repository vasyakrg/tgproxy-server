package router_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/router"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

const maxAtt = 3

func transportOut(phase string) router.Outcome {
	return router.Outcome{Kind: router.OutcomeTransport, Phase: phase, NotSent: tgapi.PhaseNotSent(phase)}
}

func tgOut(status int, desc string) router.Outcome {
	return router.Outcome{Kind: router.OutcomeTelegram, Status: status,
		Env: &tgapi.Envelope{OK: false, ErrorCode: status, Description: desc}}
}

var outcomes = map[string]router.Outcome{
	"dial":                transportOut(tgapi.PhaseDial),
	"tls":                 transportOut(tgapi.PhaseTLS),
	"pre-send":            transportOut(tgapi.PhasePreSend),
	"write":               transportOut(tgapi.PhaseWrite),
	"read":                transportOut(tgapi.PhaseRead),
	"timeout":             transportOut(tgapi.PhaseTimeout),
	"tg-5xx":              tgOut(502, "Bad Gateway"),
	"tg-429":              tgOut(429, "Too Many Requests: retry after 7"),
	"tg-4xx":              tgOut(403, "Forbidden: bot was blocked by the user"),
	"tg-400-not-modified": tgOut(400, "Bad Request: message is not modified: specified new message content"),
	"ok":                  {Kind: router.OutcomeOK},
}

func describe(d router.Decision) string {
	switch {
	case d.Final != nil:
		return fmt.Sprintf("final %d %s", d.Final.Status, d.Final.Desc)
	case d.Retry:
		if d.Backoff > 0 {
			return "retry+" + d.Backoff.String()
		}
		return "retry"
	case d.Passthrough && d.TreatAsSuccess:
		return "pass+success"
	case d.Passthrough:
		return "pass"
	}
	return "invalid"
}

const (
	fUnavail = "final 502 tgproxy: upstream unavailable"
	fUnknown = "final 502 tgproxy: delivery unknown"
)

// row: ожидание для safe, semi, unsafe на попытках 1 и 3.
type row struct {
	outcome string
	safe    [2]string
	semi    [2]string
	unsafe  [2]string
}

func same(a, b string) [2]string { return [2]string{a, b} }

var matrix = []row{
	{"dial", same("retry", fUnavail), same("retry", fUnavail), same("retry", fUnavail)},
	{"tls", same("retry", fUnavail), same("retry", fUnavail), same("retry", fUnavail)},
	{"pre-send", same("retry", fUnavail), same("retry", fUnavail), same("retry", fUnavail)},
	{"write", same("retry", fUnavail), same("retry", fUnknown), same(fUnknown, fUnknown)},
	{"read", same("retry", fUnavail), same("retry", fUnknown), same(fUnknown, fUnknown)},
	{"timeout", same("retry", fUnavail), same("retry", fUnknown), same(fUnknown, fUnknown)},
	{"tg-5xx", same("retry+500ms", "pass"), same("retry+500ms", "pass"), same("pass", "pass")},
	{"tg-429", same("pass", "pass"), same("pass", "pass"), same("pass", "pass")},
	{"tg-4xx", same("pass", "pass"), same("pass", "pass"), same("pass", "pass")},
	{"tg-400-not-modified", same("pass", "pass"), same("pass", "pass+success"), same("pass", "pass")},
	{"ok", same("pass", "pass"), same("pass", "pass"), same("pass", "pass")},
}

func TestRetryMatrix(t *testing.T) {
	if len(matrix) != len(outcomes) {
		t.Fatalf("matrix rows %d != outcomes %d", len(matrix), len(outcomes))
	}
	for _, r := range matrix {
		o, ok := outcomes[r.outcome]
		if !ok {
			t.Fatalf("unknown outcome %s", r.outcome)
		}
		for _, c := range []struct {
			class tgapi.Class
			want  [2]string
		}{{tgapi.Safe, r.safe}, {tgapi.Semi, r.semi}, {tgapi.Unsafe, r.unsafe}} {
			for i, attempt := range []int{1, 3} {
				got := describe(router.Decide(c.class, o, attempt, maxAtt))
				if got != c.want[i] {
					t.Errorf("%s/%s/attempt %d: got %q want %q", c.class, r.outcome, attempt, got, c.want[i])
				}
			}
		}
	}
}

func TestBackoffByAttempt(t *testing.T) {
	o := outcomes["tg-5xx"]
	want := map[int]time.Duration{1: 500 * time.Millisecond, 2: time.Second}
	for a, w := range want {
		d := router.Decide(tgapi.Safe, o, a, 4)
		if !d.Retry || d.Backoff != w {
			t.Errorf("attempt %d: %+v", a, d)
		}
	}
	if d := router.Decide(tgapi.Safe, o, 3, 5); d.Backoff != 2*time.Second {
		t.Errorf("attempt 3: %+v", d)
	}
	if d := router.Decide(tgapi.Safe, o, 4, 9); d.Backoff != 2*time.Second {
		t.Errorf("clamp high: %+v", d)
	}
	if d := router.Decide(tgapi.Safe, o, 0, 9); d.Backoff != 500*time.Millisecond {
		t.Errorf("clamp low: %+v", d)
	}
}

func TestMiddleAttemptRetries(t *testing.T) {
	for _, name := range []string{"dial", "write"} {
		d := router.Decide(tgapi.Safe, outcomes[name], 2, maxAtt)
		if !d.Retry {
			t.Errorf("%s attempt 2: %+v", name, d)
		}
	}
	if d := router.Decide(tgapi.Semi, outcomes["tg-5xx"], 2, maxAtt); d.Backoff != time.Second {
		t.Errorf("%+v", d)
	}
}

func TestCanceled(t *testing.T) {
	for _, class := range []tgapi.Class{tgapi.Safe, tgapi.Semi, tgapi.Unsafe} {
		for _, name := range []string{"dial", "write", "tg-5xx", "ok"} {
			o := outcomes[name]
			o.Canceled = true
			d := router.Decide(class, o, 1, maxAtt)
			if d.Retry || d.Final == nil || d.Final.Status != 499 || d.Final.Desc != router.DescCanceled {
				t.Errorf("%s/%s: %+v", class, name, d)
			}
		}
	}
}

func TestNotFoundDelete(t *testing.T) {
	o := tgOut(400, "Bad Request: message to delete not found")
	if got := describe(router.Decide(tgapi.Safe, o, 2, maxAtt)); got != "pass+success" {
		t.Errorf("retry attempt: %s", got)
	}
	if got := describe(router.Decide(tgapi.Safe, o, 1, maxAtt)); got != "pass" {
		t.Errorf("first attempt is a genuine error: %s", got)
	}
	if got := describe(router.Decide(tgapi.Unsafe, o, 2, maxAtt)); got != "pass" {
		t.Errorf("unsafe: %s", got)
	}
	nm := outcomes["tg-400-not-modified"]
	if got := describe(router.Decide(tgapi.Safe, nm, 2, maxAtt)); got != "pass" {
		t.Errorf("safe+not modified: %s", got)
	}
	nilEnv := router.Outcome{Kind: router.OutcomeTelegram, Status: 400}
	if got := describe(router.Decide(tgapi.Semi, nilEnv, 2, maxAtt)); got != "pass" {
		t.Errorf("nil env: %s", got)
	}
}

func TestUnknownPhaseIsConservative(t *testing.T) {
	o := router.Outcome{Kind: router.OutcomeTransport}
	if got := describe(router.Decide(tgapi.Unsafe, o, 1, maxAtt)); got != fUnknown {
		t.Errorf("unsafe: %s", got)
	}
	if got := describe(router.Decide(tgapi.Safe, o, 1, maxAtt)); got != "retry" {
		t.Errorf("safe: %s", got)
	}
	// NotSent без фазы тоже считается «не ушло»
	ns := router.Outcome{Kind: router.OutcomeTransport, NotSent: true}
	if got := describe(router.Decide(tgapi.Unsafe, ns, 1, maxAtt)); got != "retry" {
		t.Errorf("notSent: %s", got)
	}
}

func TestFromTransport(t *testing.T) {
	env := &tgapi.Envelope{ErrorCode: 429}
	cases := []struct {
		in   transport.Outcome
		want router.Outcome
	}{
		{transport.Outcome{Kind: transport.KindOK}, router.Outcome{Kind: router.OutcomeOK}},
		{transport.Outcome{Kind: transport.KindTelegramError}, router.Outcome{Kind: router.OutcomeTelegram, Status: 429, Env: env}},
		{transport.Outcome{Kind: transport.KindTransport, Phase: tgapi.PhaseDial, NotSent: true},
			router.Outcome{Kind: router.OutcomeTransport, Phase: tgapi.PhaseDial, NotSent: true}},
		{transport.Outcome{Kind: transport.KindTransport, Canceled: true},
			router.Outcome{Kind: router.OutcomeTransport, Canceled: true}},
	}
	for i, c := range cases {
		if got := router.FromTransport(c.in, 429, env); got != c.want {
			t.Errorf("case %d: %+v != %+v", i, got, c.want)
		}
	}
	_ = http.StatusOK
}
