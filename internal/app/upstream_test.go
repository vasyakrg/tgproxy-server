package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

type fakeTransport struct {
	got transport.AgentRef
	fn  func(req *http.Request) (*http.Response, error)
}

func (f *fakeTransport) RoundTrip(_ context.Context, a transport.AgentRef, req *http.Request) (*http.Response, error) {
	f.got = a
	return f.fn(req)
}

func (f *fakeTransport) Status(context.Context, transport.AgentRef) (*transport.AgentStatus, error) {
	return &transport.AgentStatus{}, nil
}

type mapRefs map[string]transport.AgentRef

func (m mapRefs) Ref(id string) (transport.AgentRef, bool) { ref, ok := m[id]; return ref, ok }

func TestUpstreamMapsAgentAndRejectsUnknown(t *testing.T) {
	ft := &fakeTransport{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}}
	u, _ := url.Parse("https://127.0.0.1:1")
	up := NewUpstream(ft, mapRefs{"a1": {ID: "a1", URL: u, Mode: config.AgentModeDial}})
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/tg/x", nil)
	resp, err := up.RoundTrip(context.Background(), "a1", req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if ft.got.ID != "a1" || ft.got.Mode != config.AgentModeDial || ft.got.URL.Host != "127.0.0.1:1" {
		t.Fatalf("ref: %+v", ft.got)
	}
	resp, err = up.RoundTrip(context.Background(), "nope", req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("unknown agent must fail")
	}
}

type errBody struct{ n int }

func (b *errBody) Read(p []byte) (int, error) {
	if b.n == 0 {
		return 0, &http.MaxBytesError{Limit: 10}
	}
	b.n--
	return copy(p, "x"), nil
}

// MaxBytesError из тела запроса должен проходить через реальный Dial-транспорт
// до вызывающего (роутер отдаёт по нему 413).
func TestUpstreamPropagatesMaxBytesErrorThroughDial(t *testing.T) {
	env := newE2E(t, e2eOpts{})
	up := NewUpstream(env.dial, env.srv.reg)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/tg/bot"+testToken+"/sendDocument",
		io.NopCloser(&errBody{n: 3}))
	req.ContentLength = -1
	resp, err := up.RoundTrip(context.Background(), "local", req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	var mb *http.MaxBytesError
	if !errors.As(err, &mb) {
		t.Fatalf("want *http.MaxBytesError in chain, got %v", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatal("token leaked in error")
	}
}
