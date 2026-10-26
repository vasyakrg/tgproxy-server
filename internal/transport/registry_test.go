package transport

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

type fake struct {
	rt, st, closed int
}

func (f *fake) RoundTrip(context.Context, AgentRef, *http.Request) (*http.Response, error) {
	f.rt++
	return &http.Response{StatusCode: 204}, nil
}

func (f *fake) Status(context.Context, AgentRef) (*AgentStatus, error) {
	f.st++
	return &AgentStatus{Version: "v"}, nil
}
func (f *fake) Close() error { f.closed++; return nil }

func TestRegistry(t *testing.T) {
	dial := &fake{}
	r := NewRegistry(map[config.AgentMode]AgentTransport{config.AgentModeDial: dial})
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/x", nil)

	if _, err := r.RoundTrip( //nolint:bodyclose // фейковый ответ без тела
		ctx, AgentRef{Mode: config.AgentModeDial}, req); err != nil || dial.rt != 1 {
		t.Fatal(err)
	}
	if st, err := r.Status(ctx, AgentRef{Mode: config.AgentModeDial}); err != nil || st.Version != "v" {
		t.Fatal(err)
	}
	ref := AgentRef{ID: "a", Mode: config.AgentModeReverse}
	if _, err := r.RoundTrip( //nolint:bodyclose // фейковый ответ без тела
		ctx, ref, req); !errors.Is(err, ErrModeUnsupported) {
		t.Fatalf("%v", err)
	}
	if _, err := r.Status(ctx, ref); !errors.Is(err, ErrModeUnsupported) {
		t.Fatalf("%v", err)
	}
	rev := &fake{}
	r.Register(config.AgentModeReverse, rev) // M5-T8: без изменения интерфейса
	if _, err := r.RoundTrip(                //nolint:bodyclose // фейковый ответ без тела
		ctx, ref, req); err != nil || rev.rt != 1 {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil || dial.closed != 1 || rev.closed != 1 {
		t.Fatal(err)
	}
}
