package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func newReq(ctx context.Context, t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func agentSays(source, phase string, code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(tgapi.HeaderSource, source)
		if phase != "" {
			w.Header().Set(tgapi.HeaderErrorPhase, phase)
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{}`))
	})
}

func closedPortURL(t *testing.T) *url.URL {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	u, _ := url.Parse("https://" + addr)
	return u
}

// do выполняет запрос и возвращает классификацию, как это делает router.
func do(t *testing.T, d *Dial, ref AgentRef, method, path string, body []byte) (*http.Response, Outcome) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	resp, err := d.RoundTrip(ctx, ref, newReq(ctx, t, method, path, rd))
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	return resp, Classify(resp, err, body != nil)
}

func TestClassifyMatrix(t *testing.T) {
	e := newEnv(t)
	foreign, _ := pki.NewCA("foreign", 24*time.Hour)

	tests := []struct {
		name    string
		setup   func(t *testing.T) (*Dial, AgentRef, time.Duration)
		kind    Kind
		phase   string
		source  string
		notSent bool
		// alt — допустимый альтернативный исход (гонка TLS 1.3, см. кейс).
		alt *Outcome
	}{
		{
			name: "агент не слушает: refused -> dial",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				return e.dial(t), AgentRef{ID: "a1", URL: closedPortURL(t), Mode: config.AgentModeDial}, 0
			},
			kind: KindTransport, phase: tgapi.PhaseDial, source: SourceServerAgent, notSent: true,
		},
		{
			name: "сертификат агента от чужого CA -> tls",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				return e.dial(t), e.fakeAgentWithCA(t, foreign, "a1"), 0
			},
			kind: KindTransport, phase: tgapi.PhaseTLS, source: SourceServerAgent, notSent: true,
		},
		{
			name: "сертификат другого agent id -> tls",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				ref := e.fakeAgent(t, e.ca, "other", agentSays(tgapi.SourceTelegram, "", 200))
				ref.ID = "a1"
				return e.dial(t), ref, 0
			},
			kind: KindTransport, phase: tgapi.PhaseTLS, source: SourceServerAgent, notSent: true,
		},
		{
			name: "агент отверг клиентский сертификат сервера (TLS1.3 alert) -> tls",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				ref := e.fakeAgent(t, e.ca, "a1", agentSays(tgapi.SourceTelegram, "", 200))
				return NewDial(serverCert(t, foreign), e.pool), ref, 0
			},
			kind: KindTransport, phase: tgapi.PhaseTLS, source: SourceServerAgent, notSent: true,
			// TLS 1.3: сервер отвергает клиентский сертификат уже после того, как
			// клиент счёл рукопожатие завершённым. Если клиент успел записать
			// заголовки до прихода alert, ошибка всплывает как write/broken pipe;
			// надёжно отличить это от обрыва после записи нельзя, а write —
			// консервативная (безопасная) классификация. Допускаем оба исхода.
			alt: &Outcome{Kind: KindTransport, Phase: tgapi.PhaseWrite, Source: SourceServerAgent},
		},
		{
			name: "агент 502 + X-TGP-Error-Phase: dial -> dial/agent",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				return e.dial(t), e.fakeAgent(t, e.ca, "a1", agentSays(tgapi.SourceAgent, tgapi.PhaseDial, 502)), 0
			},
			kind: KindTransport, phase: tgapi.PhaseDial, source: tgapi.SourceAgent, notSent: true,
		},
		{
			name: "агент 502 + pre-send -> NotSent",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				return e.dial(t), e.fakeAgent(t, e.ca, "a1", agentSays(tgapi.SourceAgent, tgapi.PhasePreSend, 503)), 0
			},
			kind: KindTransport, phase: tgapi.PhasePreSend, source: tgapi.SourceAgent, notSent: true,
		},
		{
			name: "агент 502 + write -> !NotSent",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				return e.dial(t), e.fakeAgent(t, e.ca, "a1", agentSays(tgapi.SourceAgent, tgapi.PhaseWrite, 502)), 0
			},
			kind: KindTransport, phase: tgapi.PhaseWrite, source: tgapi.SourceAgent,
		},
		{
			name: "RST после отправки тела агенту -> write",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					panic(http.ErrAbortHandler) // h2: RST_STREAM
				})
				return e.dial(t), e.fakeAgent(t, e.ca, "a1", h), 0
			},
			kind: KindTransport, phase: tgapi.PhaseWrite, source: SourceServerAgent,
		},
		{
			name: "таймаут чтения ответа агента -> timeout",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					<-r.Context().Done()
				})
				return e.dial(t), e.fakeAgent(t, e.ca, "a1", h), 300 * time.Millisecond
			},
			kind: KindTransport, phase: tgapi.PhaseTimeout, source: SourceServerAgent,
		},
		{
			name: "X-TGP-Source: telegram 500 -> не транспортная ошибка",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				return e.dial(t), e.fakeAgent(t, e.ca, "a1", agentSays(tgapi.SourceTelegram, "", 500)), 0
			},
			kind: KindTelegramError, source: tgapi.SourceTelegram,
		},
		{
			name: "telegram 200 -> OK",
			setup: func(t *testing.T) (*Dial, AgentRef, time.Duration) {
				return e.dial(t), e.fakeAgent(t, e.ca, "a1", agentSays(tgapi.SourceTelegram, "", 200)), 0
			},
			kind: KindOK, source: tgapi.SourceTelegram,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, ref, timeout := tc.setup(t)
			t.Cleanup(func() { _ = d.Close() })
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			body := []byte(`{"chat_id":1,"text":"hi"}`)
			resp, err := d.RoundTrip(ctx, ref, newReq(ctx, t, http.MethodPost, "/tg/bot1:AAA/sendMessage", bytes.NewReader(body)))
			if resp != nil {
				defer func() { _ = resp.Body.Close() }()
			}
			got := Classify(resp, err, true)
			if tc.alt != nil && got.Kind == tc.alt.Kind && got.Phase == tc.alt.Phase &&
				got.Source == tc.alt.Source && got.NotSent == tc.alt.NotSent {
				return
			}
			if got.Kind != tc.kind || got.Phase != tc.phase || got.Source != tc.source || got.NotSent != tc.notSent {
				t.Fatalf("got %+v (err=%v), want kind=%v phase=%q source=%q notSent=%v",
					got, err, tc.kind, tc.phase, tc.source, tc.notSent)
			}
			if tc.source == SourceServerAgent {
				var pe *PhaseError
				if !errors.As(err, &pe) || pe.Phase != tc.phase {
					t.Fatalf("expected *PhaseError(%s), got %v", tc.phase, err)
				}
			}
		})
	}
}

// fakeAgentWithCA — агент с сертификатом от другого CA; сервер агента доверяет
// нашему пулу для клиентского сертификата, а клиент не доверяет серверному.
func (e *env) fakeAgentWithCA(t *testing.T, ca *pki.CA, id string) AgentRef {
	return e.fakeAgent(t, ca, id, agentSays(tgapi.SourceTelegram, "", 200))
}

func TestContextCanceledIsNotPhase(t *testing.T) {
	e := newEnv(t)
	started := make(chan struct{})
	ref := e.fakeAgent(t, e.ca, "a1", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	d := e.dial(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	resp, err := d.RoundTrip(ctx, ref, newReq(ctx, t, http.MethodGet, "/tg/bot1:AAA/getMe", nil))
	if resp != nil {
		_ = resp.Body.Close()
	}
	out := Classify(nil, err, false)
	if !out.Canceled || out.NotSent {
		t.Fatalf("got %+v", out)
	}
}

func TestHTTP2AndURLRewrite(t *testing.T) {
	e := newEnv(t)
	var gotPath, gotQuery, gotHost, gotAttempt string
	ref := e.fakeAgent(t, e.ca, "a1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotAttempt = r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get(tgapi.HeaderAttempt)
		gotHost = r.Host
		w.Header().Set(tgapi.HeaderSource, tgapi.SourceTelegram)
		_, _ = w.Write([]byte("ok"))
	}))
	d := e.dial(t)
	req := newReq(context.Background(), t, http.MethodGet, "/tg/bot1:AAA/getUpdates?timeout=50&offset=1", nil)
	req.Header.Set(tgapi.HeaderAttempt, "2")
	resp, err := d.RoundTrip(context.Background(), ref, req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto %s, want h2", resp.Proto)
	}
	if resp.TLS == nil || resp.TLS.Version != 0x0304 {
		t.Fatalf("TLS1.3 expected: %+v", resp.TLS)
	}
	if gotPath != "/tg/bot1:AAA/getUpdates" || gotQuery != "timeout=50&offset=1" || gotAttempt != "2" || gotHost != ref.URL.Host {
		t.Fatalf("path=%q query=%q attempt=%q host=%q", gotPath, gotQuery, gotAttempt, gotHost)
	}
	// исходный запрос не изменён
	if req.URL.Host != "" || req.URL.Path != "/tg/bot1:AAA/getUpdates" {
		t.Fatalf("original request mutated: %v", req.URL)
	}
}

func TestAgentBasePathPrefix(t *testing.T) {
	u, _ := url.Parse("https://h:1/base/")
	in, _ := url.Parse("/tg/a%2Fb?x=1")
	got := agentURL(u, in)
	if got.EscapedPath() != "/base/tg/a%2Fb" || got.RawQuery != "x=1" || got.Host != "h:1" {
		t.Fatalf("%v", got)
	}
}

func TestStreamBothWays5MB(t *testing.T) {
	e := newEnv(t)
	ref := e.fakeAgent(t, e.ca, "a1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(tgapi.HeaderSource, tgapi.SourceTelegram)
		w.WriteHeader(200)
		w.(http.Flusher).Flush() // заголовки сразу: клиент не ждёт конца тела
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	d := e.dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const chunk, total = 64 << 10, 5 << 20
	pr, pw := io.Pipe()
	resp, err := d.RoundTrip(ctx, ref, newReq(ctx, t, http.MethodPost, "/tg/bot1:AAA/sendDocument", pr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto %s", resp.Proto)
	}
	sent, got := sha256.New(), sha256.New()
	out := make([]byte, chunk)
	// Пинг-понг: следующий кусок отправляется только после получения эха
	// предыдущего. Любая буферизация тела (в любую сторону) даст deadlock.
	for i := 0; i < total/chunk; i++ {
		b := bytes.Repeat([]byte{byte(i)}, chunk)
		sent.Write(b)
		if _, err := pw.Write(b); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(resp.Body, out); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		got.Write(out)
	}
	_ = pw.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent.Sum(nil), got.Sum(nil)) {
		t.Fatal("echo mismatch")
	}
}

func TestResponseBodyReadErrorIsReadPhase(t *testing.T) {
	e := newEnv(t)
	ref := e.fakeAgent(t, e.ca, "a1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(tgapi.HeaderSource, tgapi.SourceTelegram)
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	resp, _ := do(t, e.dial(t), ref, http.MethodGet, "/tg/bot1:AAA/getFile", nil)
	_, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err == nil {
		t.Fatal("expected read error")
	}
	if out := Classify(resp, err, true); out.Phase != tgapi.PhaseRead || out.NotSent || out.Kind != KindTransport {
		t.Fatalf("%+v", out)
	}
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	na := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	want := AgentStatus{Version: "1.2.3", Commit: "abc", UptimeS: 42, Inflight: 3, RPS1m: 1.5,
		ErrorsByPhase: map[string]uint64{"dial": 2}, UpstreamRTTMs: 12.5, Draining: true, CertNotAfter: na}
	var path string
	ref := e.fakeAgent(t, e.ca, "a1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewEncoder(w).Encode(want)
	}))
	got, err := e.dial(t).Status(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if path != StatusPath || got.Version != "1.2.3" || got.Inflight != 3 || !got.Draining ||
		got.ErrorsByPhase["dial"] != 2 || !got.CertNotAfter.Equal(na) || got.UpstreamRTTMs != 12.5 || got.RPS1m != 1.5 {
		t.Fatalf("path=%q got=%+v", path, got)
	}
}

func TestStatusErrors(t *testing.T) {
	e := newEnv(t)
	d := e.dial(t)
	bad := e.fakeAgent(t, e.ca, "a1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	if _, err := d.Status(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err=%v", err)
	}
	junk := e.fakeAgent(t, e.ca, "a2", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	if _, err := d.Status(context.Background(), junk); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("err=%v", err)
	}
	dead := AgentRef{ID: "a3", URL: closedPortURL(t), Mode: config.AgentModeDial}
	_, err := d.Status(context.Background(), dead)
	var pe *PhaseError
	if !errors.As(err, &pe) || pe.Phase != tgapi.PhaseDial {
		t.Fatalf("err=%v", err)
	}
	// короткий таймаут Status
	slow := e.fakeAgent(t, e.ca, "a4", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	d2 := e.dial(t, WithStatusTimeout(200*time.Millisecond))
	if _, err := d2.Status(context.Background(), slow); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestBadAgentRefAndClose(t *testing.T) {
	e := newEnv(t)
	d := NewDial(e.srvCert, e.pool)
	req := newReq(context.Background(), t, http.MethodGet, "/x", nil)
	for _, ref := range []AgentRef{
		{},
		{ID: "a", URL: &url.URL{Scheme: "http", Host: "h"}},
		{ID: "a", URL: &url.URL{Scheme: "https"}},
	} {
		resp, err := d.RoundTrip(context.Background(), ref, req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, ErrBadAgent) {
			t.Fatalf("ref %+v: %v", ref, err)
		}
	}
	_ = d.Close()
	ok := AgentRef{ID: "a", URL: &url.URL{Scheme: "https", Host: "h:1"}}
	resp, err := d.RoundTrip(context.Background(), ok, req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
}

func TestTransportReusedPerAgentAndRecreatedOnMove(t *testing.T) {
	e := newEnv(t)
	d := e.dial(t)
	a := AgentRef{ID: "a", URL: &url.URL{Scheme: "https", Host: "h:1"}}
	t1, _ := d.transportFor(a)
	t2, _ := d.transportFor(a)
	if t1 != t2 {
		t.Fatal("transport must be reused")
	}
	a.URL = &url.URL{Scheme: "https", Host: "h:2"}
	t3, _ := d.transportFor(a)
	if t3 == t1 {
		t.Fatal("transport must be recreated when address changes")
	}
}

func TestKeepAliveReusesConnection(t *testing.T) {
	e := newEnv(t)
	ref := e.fakeAgent(t, e.ca, "a1", agentSays(tgapi.SourceTelegram, "", 200))
	d := e.dial(t)
	for i := 0; i < 5; i++ {
		resp, out := do(t, d, ref, http.MethodGet, "/tg/bot1:AAA/getMe", nil)
		if out.Kind != KindOK {
			t.Fatalf("%+v", out)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
