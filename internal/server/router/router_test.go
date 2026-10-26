package router

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

const tok = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

type fake struct {
	agent string
	req   *http.Request
	body  string
	dl    time.Duration
	fn    func(ctx context.Context, req *http.Request) (*http.Response, error)
}

func (f *fake) RoundTrip(ctx context.Context, agent string, req *http.Request) (*http.Response, error) {
	f.agent, f.req = agent, req
	if dl, ok := ctx.Deadline(); ok {
		f.dl = time.Until(dl)
	}
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		f.body = string(b)
	}
	if f.fn != nil {
		return f.fn(ctx, req)
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func cfg(agents ...string) *config.ServerConfig {
	c := config.DefaultServer()
	c.Agents = nil
	for _, a := range agents {
		c.Agents = append(c.Agents, config.AgentEndpoint{ID: a})
	}
	return c
}

func newReq(method, target, ct, body string) (*http.Request, tgapi.Route) {
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	rt, err := tgapi.ParsePath(r.URL.EscapedPath())
	if err != nil {
		panic(err)
	}
	return r, rt
}

func lg() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestDoBuildsRequest(t *testing.T) {
	f := &fake{}
	rt := New(cfg("a1", "a2"), f, lg())
	r, route := newReq("POST", "/k/secret/bot"+tok+"/sendMessage?x=1", "application/json", `{"a":1}`)
	resp, err := rt.Do(context.Background(), r, route)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if f.agent != "a1" || f.req.URL.Path != "/tg/bot"+tok+"/sendMessage" || f.req.URL.RawQuery != "x=1" {
		t.Fatalf("%s %s", f.agent, f.req.URL)
	}
	if f.body != `{"a":1}` {
		t.Fatal(f.body)
	}
	if f.req.Header.Get(tgapi.HeaderAttempt) != "1" || f.req.Header.Get(tgapi.HeaderTimeoutMs) != "25000" {
		t.Fatal(f.req.Header)
	}
	if strings.Contains(f.req.URL.String(), "secret") {
		t.Fatal("client key leaked")
	}
}

func TestTimeouts(t *testing.T) {
	cases := []struct {
		name, method, target, ct, body string
		want                           time.Duration
	}{
		{"plain", "POST", "/bot" + tok + "/getMe", "", "", 25 * time.Second},
		{"poll 50", "GET", "/bot" + tok + "/getUpdates?timeout=50", "", "", 65 * time.Second},
		{"poll 5", "GET", "/bot" + tok + "/getUpdates?timeout=5", "", "", 20 * time.Second},
		{"poll 100 capped", "GET", "/bot" + tok + "/getUpdates?timeout=100", "", "", 65 * time.Second},
		{"poll none", "GET", "/bot" + tok + "/getUpdates", "", "", 15 * time.Second},
		{"poll bad", "GET", "/bot" + tok + "/getUpdates?timeout=x", "", "", 15 * time.Second},
		{"poll json", "POST", "/bot" + tok + "/getUpdates", "application/json", `{"timeout":30,"offset":1}`, 45 * time.Second},
		{"poll form", "POST", "/bot" + tok + "/getUpdates", "application/x-www-form-urlencoded", "offset=1&timeout=10", 25 * time.Second},
		{"poll bad json", "POST", "/bot" + tok + "/getUpdates", "application/json", `{`, 15 * time.Second},
		{"poll bad form", "POST", "/bot" + tok + "/getUpdates", "application/x-www-form-urlencoded", "%zz", 15 * time.Second},
		{"poll multipart", "POST", "/bot" + tok + "/getUpdates", "multipart/form-data; boundary=x", "--x--", 15 * time.Second},
		{"file", "GET", "/file/bot" + tok + "/a/b.jpg", "", "", 65 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fake{}
			rt := New(cfg("a1"), f, lg())
			r, route := newReq(tc.method, tc.target, tc.ct, tc.body)
			resp, err := rt.Do(context.Background(), r, route)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if f.dl > tc.want || f.dl < tc.want-2*time.Second {
				t.Fatalf("deadline %v want %v", f.dl, tc.want)
			}
			if tc.body != "" && f.body != tc.body {
				t.Fatalf("body not restored: %q", f.body)
			}
		})
	}
}

func TestNoAgents(t *testing.T) {
	rt := New(cfg(), &fake{}, lg())
	r, route := newReq("GET", "/bot"+tok+"/getMe", "", "")
	_, err := rt.Do(context.Background(), r, route) //nolint:bodyclose
	var e *Error
	if !errors.As(err, &e) || e.Status != 502 || e.Desc != DescNoAgents || e.HTTPStatus() != 502 || e.Description() != DescNoAgents {
		t.Fatal(err)
	}
	_ = e.Error()
}

func TestUpstreamErrors(t *testing.T) {
	r, route := newReq("GET", "/bot"+tok+"/getMe", "", "")
	f := &fake{fn: func(context.Context, *http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: https://x/bot" + tok + "/getMe refused")
	}}
	_, err := New(cfg("a"), f, lg()).Do(context.Background(), r, route) //nolint:bodyclose
	var e *Error
	if !errors.As(err, &e) || e.Status != 502 || strings.Contains(e.Error(), tok) {
		t.Fatalf("%v", err)
	}

	f = &fake{fn: func(_ context.Context, _ *http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	}}
	_, err = New(cfg("a"), f, lg()).Do(context.Background(), r, route) //nolint:bodyclose
	if !errors.As(err, &e) || e.Status != 504 {
		t.Fatalf("%v", err)
	}

	f = &fake{fn: func(context.Context, *http.Request) (*http.Response, error) { return nil, context.Canceled }}
	_, err = New(cfg("a"), f, lg()).Do(context.Background(), r, route) //nolint:bodyclose
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}

	mb := &http.MaxBytesError{Limit: 1}
	f = &fake{fn: func(context.Context, *http.Request) (*http.Response, error) { return nil, mb }}
	_, err = New(cfg("a"), f, lg()).Do(context.Background(), r, route) //nolint:bodyclose
	if !errors.Is(err, mb) {
		t.Fatalf("%v", err)
	}
}

func TestDeadlineEnforced(t *testing.T) {
	c := cfg("a")
	c.Router.Budget = 50 * time.Millisecond
	f := &fake{fn: func(ctx context.Context, _ *http.Request) (*http.Response, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	r, route := newReq("GET", "/bot"+tok+"/getMe", "", "")
	_, err := New(c, f, lg()).Do(context.Background(), r, route) //nolint:bodyclose
	var e *Error
	if !errors.As(err, &e) || e.Status != 504 {
		t.Fatalf("%v", err)
	}
}

func TestBodyCloseCancels(t *testing.T) {
	var ctx0 context.Context
	f := &fake{fn: func(ctx context.Context, _ *http.Request) (*http.Response, error) {
		ctx0 = ctx
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("x"))}, nil
	}}
	r, route := newReq("GET", "/bot"+tok+"/getMe", "", "")
	resp, err := New(cfg("a"), f, lg()).Do(context.Background(), r, route)
	if err != nil {
		t.Fatal(err)
	}
	if ctx0.Err() != nil {
		t.Fatal("canceled early")
	}
	_ = resp.Body.Close()
	if ctx0.Err() == nil {
		t.Fatal("not canceled")
	}
}
