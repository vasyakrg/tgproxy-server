package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func hdr(source, phase string) http.Header {
	h := http.Header{}
	if source != "" {
		h.Set(tgapi.HeaderSource, source)
	}
	if phase != "" {
		h.Set(tgapi.HeaderErrorPhase, phase)
	}
	return h
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyRaw(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	tests := []struct {
		name    string
		resp    *http.Response
		err     error
		written bool
		kind    Kind
		phase   string
		notSent bool
	}{
		{"dial error", nil, dialErr, false, KindTransport, tgapi.PhaseDial, true},
		{"dial error wrapped", nil, fmt.Errorf("x: %w", dialErr), true, KindTransport, tgapi.PhaseDial, true},
		{"dns", nil, &net.DNSError{Name: "x"}, false, KindTransport, tgapi.PhaseDial, true},
		{"remote tls alert", nil, errors.New("remote error: tls: bad certificate"), true, KindTransport, tgapi.PhaseTLS, true},
		{"remote tls internal error is not handshake", nil, errors.New("remote error: tls: internal error"), true, KindTransport, tgapi.PhaseWrite, false},
		{"eof before write", nil, errors.New("EOF"), false, KindTransport, tgapi.PhasePreSend, true},
		{"eof after write", nil, errors.New("EOF"), true, KindTransport, tgapi.PhaseWrite, false},
		{"timeout after write", nil, context.DeadlineExceeded, true, KindTransport, tgapi.PhaseTimeout, false},
		{"net timeout after write", nil, timeoutErr{}, true, KindTransport, tgapi.PhaseTimeout, false},
		{"timeout before write", nil, context.DeadlineExceeded, false, KindTransport, tgapi.PhasePreSend, true},
		{"body read error", &http.Response{StatusCode: 200}, errors.New("unexpected EOF"), true, KindTransport, tgapi.PhaseRead, false},
		{"body read timeout", &http.Response{StatusCode: 200}, context.DeadlineExceeded, true, KindTransport, tgapi.PhaseTimeout, false},
		{"phase error passthrough", nil, &PhaseError{Phase: tgapi.PhaseTLS, Source: SourceServerAgent, Err: errors.New("x")}, true, KindTransport, tgapi.PhaseTLS, true},
		{"nil response", nil, nil, false, KindTransport, tgapi.PhaseRead, false},
		{"agent ok", &http.Response{StatusCode: 200, Header: hdr(tgapi.SourceAgent, "")}, nil, true, KindOK, "", false},
		{"agent unknown phase", &http.Response{StatusCode: 502, Header: hdr(tgapi.SourceAgent, "weird")}, nil, true, KindTransport, tgapi.PhaseRead, false},
		{"agent error without phase", &http.Response{StatusCode: 503, Header: hdr(tgapi.SourceAgent, "")}, nil, true, KindTransport, tgapi.PhaseRead, false},
		{"no source 502", &http.Response{StatusCode: 502, Header: hdr("", "")}, nil, true, KindTransport, tgapi.PhaseRead, false},
		{"tg 429", &http.Response{StatusCode: 429, Header: hdr(tgapi.SourceTelegram, "")}, nil, true, KindTelegramError, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.resp, tc.err, tc.written)
			if got.Kind != tc.kind || got.Phase != tc.phase || got.NotSent != tc.notSent {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestClassifyCanceled(t *testing.T) {
	out := Classify(nil, fmt.Errorf("w: %w", context.Canceled), true)
	if !out.Canceled || out.NotSent || out.Phase != "" {
		t.Fatalf("%+v", out)
	}
}

func TestPhaseErrorRedactsAndUnwraps(t *testing.T) {
	inner := errors.New(`Post "https://x/tg/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage": EOF`)
	pe := &PhaseError{Phase: tgapi.PhaseWrite, Source: SourceServerAgent, Err: inner}
	if strings.Contains(pe.Error(), "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw") {
		t.Fatalf("token leaked: %s", pe.Error())
	}
	if !errors.Is(pe, inner) {
		t.Fatal("Unwrap")
	}
	if !strings.Contains((&PhaseError{Phase: "x", Source: "y"}).Error(), "<nil>") {
		t.Fatal("nil Err")
	}
}

func TestKindString(t *testing.T) {
	for k, w := range map[Kind]string{KindOK: "ok", KindTelegramError: "telegram_error", KindTransport: "transport", Kind(9): "unknown"} {
		if k.String() != w {
			t.Fatalf("%d", k)
		}
	}
}
