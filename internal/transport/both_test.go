package transport

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

type fakeTr struct {
	err    error
	trips  int
	status *AgentStatus
}

func (f *fakeTr) RoundTrip(context.Context, AgentRef, *http.Request) (*http.Response, error) {
	f.trips++
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func (f *fakeTr) Status(context.Context, AgentRef) (*AgentStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.status, nil
}

func TestBothFallsBackToReverseOnlyWhenNotSent(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/x", http.NoBody)
	notSent := &PhaseError{Phase: tgapi.PhaseDial, Source: SourceServerAgent, Err: errors.New("refused")}
	sent := &PhaseError{Phase: tgapi.PhaseRead, Source: SourceServerAgent, Err: errors.New("reset")}

	d, r := &fakeTr{err: notSent}, &fakeTr{}
	resp, err := Both{Dial: d, Reverse: r}.RoundTrip(context.Background(), AgentRef{ID: "a"}, req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if err != nil || resp.StatusCode != 200 || r.trips != 1 {
		t.Fatalf("fallback: %v %v reverse trips=%d", resp, err, r.trips)
	}

	d, r = &fakeTr{err: sent}, &fakeTr{}
	if _, err := (Both{Dial: d, Reverse: r}).RoundTrip(context.Background(), AgentRef{ID: "a"}, req); err == nil || r.trips != 0 { //nolint:bodyclose // ошибка: тела нет
		t.Fatalf("request that may have reached the agent must not be replayed: %v trips=%d", err, r.trips)
	}

	d = &fakeTr{err: notSent}
	r = &fakeTr{err: &PhaseError{Phase: tgapi.PhaseDial, Source: SourceServerAgent, Err: ErrNoReverseConn}}
	if _, err := (Both{Dial: d, Reverse: r}).RoundTrip(context.Background(), AgentRef{ID: "a"}, req); !errors.Is(err, notSent) { //nolint:bodyclose // ошибка: тела нет
		t.Fatalf("want dial error, got %v", err)
	}

	d, r = &fakeTr{err: errors.New("down")}, &fakeTr{status: &AgentStatus{Version: "v1"}}
	if st, err := (Both{Dial: d, Reverse: r}).Status(context.Background(), AgentRef{ID: "a"}); err != nil || st.Version != "v1" {
		t.Fatalf("status fallback: %v %v", st, err)
	}
}
