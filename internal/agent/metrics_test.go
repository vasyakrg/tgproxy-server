//nolint:bodyclose // тела ответов закрываются в t.Cleanup внутри env.do
package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

type fakeRec struct {
	mu       sync.Mutex
	requests []string
	durs     int
	inflight []int
	bytes    map[string]int
	dial     []string
}

func newFakeRec() *fakeRec { return &fakeRec{bytes: map[string]int{}} }

func (f *fakeRec) Request(c, p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, c+"/"+p)
}
func (f *fakeRec) UpstreamDuration(time.Duration) { f.mu.Lock(); f.durs++; f.mu.Unlock() }
func (f *fakeRec) SetInflight(n int)              { f.mu.Lock(); f.inflight = append(f.inflight, n); f.mu.Unlock() }
func (f *fakeRec) UpstreamBytes(d string, n int)  { f.mu.Lock(); f.bytes[d] += n; f.mu.Unlock() }
func (f *fakeRec) DialError(k string)             { f.mu.Lock(); f.dial = append(f.dial, k); f.mu.Unlock() }

// waitRequests ждёт записи Request (она идёт после отправки ответа клиенту).
func (f *fakeRec) waitRequests(t *testing.T, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.requests)
		f.mu.Unlock()
		if n >= len(want) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.requests, ",") != strings.Join(want, ",") {
		t.Fatalf("requests %v, want %v", f.requests, want)
	}
}

func recEnv(t *testing.T, tg http.Handler) (*env, *fakeRec) {
	t.Helper()
	rec := newFakeRec()
	e := newEnv(t, tg)
	upPool := x509.NewCertPool()
	upPool.AddCert(e.upstream.Certificate())
	e.startAgent(t, WithUpstreamRootCAs(upPool), WithRecorder(rec))
	return e, rec
}

func TestMetricsSuccessAndBytes(t *testing.T) {
	e, rec := recEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	resp := e.do(t, http.MethodPost, "/tg/bot1:a/sendMessage", nil, strings.NewReader("12345"))
	if got := string(readAll(t, resp.Body)); got != `{"ok":true}` {
		t.Fatalf("body %q", got)
	}
	rec.waitRequests(t, "2xx/")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.bytes[DirUp] != 5 || rec.bytes[DirDown] != len(`{"ok":true}`) {
		t.Fatalf("bytes %v", rec.bytes)
	}
	if rec.durs != 1 || len(rec.dial) != 0 {
		t.Fatalf("durs=%d dial=%v", rec.durs, rec.dial)
	}
	if len(rec.inflight) != 2 || rec.inflight[0] != 1 || rec.inflight[1] != 0 {
		t.Fatalf("inflight %v", rec.inflight)
	}
}

func TestMetricsTelegram4xx(t *testing.T) {
	e, rec := recEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil)
	rec.waitRequests(t, "4xx/")
}

func TestMetricsDialRefused(t *testing.T) {
	e, rec := recEnv(t, okHandler)
	e.upstream.Close()
	e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil)
	rec.waitRequests(t, "proxy_err/dial")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.dial) != 1 || rec.dial[0] != DialRefused {
		t.Fatalf("dial %v", rec.dial)
	}
}

func TestMetricsTLS(t *testing.T) {
	rec := newFakeRec()
	e := newEnv(t, okHandler)
	e.startAgent(t, WithRecorder(rec)) // без доверия к фейковому Telegram
	e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil)
	rec.waitRequests(t, "proxy_err/tls")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.dial) != 1 || rec.dial[0] != DialTLS {
		t.Fatalf("dial %v", rec.dial)
	}
}

func TestMetricsReadTimeoutNotDialError(t *testing.T) {
	release := make(chan struct{})
	e, rec := recEnv(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release) })
	e.do(t, http.MethodGet, "/tg/bot1:a/getUpdates", map[string]string{tgapi.HeaderTimeoutMs: "200"}, nil)
	rec.waitRequests(t, "proxy_err/timeout")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.dial) != 0 {
		t.Fatalf("dial %v", rec.dial)
	}
}

func TestMetricsDraining(t *testing.T) {
	e, rec := recEnv(t, okHandler)
	e.agent.SetDraining(true)
	e.do(t, http.MethodGet, "/tg/bot1:a/getMe", nil, nil)
	rec.waitRequests(t, "proxy_err/pre-send")
}

func TestDefaultRecorderNoop(*testing.T) {
	var r Recorder = noopRecorder{}
	r.Request("2xx", "")
	r.UpstreamDuration(time.Second)
	r.SetInflight(1)
	r.UpstreamBytes(DirUp, 1)
	r.DialError(DialOther)
	WithRecorder(nil)(&Agent{}) // nil не затирает рекордер
}

func TestDialErrorKind(t *testing.T) {
	for _, c := range []struct {
		name  string
		err   error
		phase string
		want  string
	}{
		{"dns", &net.DNSError{Err: "no such host"}, tgapi.PhaseDial, DialDNS},
		{"refused", syscall.ECONNREFUSED, tgapi.PhaseDial, DialRefused},
		{"deadline", context.DeadlineExceeded, tgapi.PhaseTimeout, DialTimeout},
		{"neterr", &net.OpError{Err: timeoutErr{}}, tgapi.PhaseDial, DialTimeout},
		{"tls", errors.New("x509"), tgapi.PhaseTLS, DialTLS},
		{"other", errors.New("boom"), tgapi.PhaseDial, DialOther},
	} {
		if got := dialErrorKind(c.err, c.phase); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "timeout" }
func (timeoutErr) Timeout() bool { return true }

func TestMetricsWriter(t *testing.T) {
	w1 := &metricsWriter{ResponseWriter: httptest.NewRecorder()}
	w1.WriteHeader(http.StatusContinue) // 1xx не фиксирует статус
	if w1.status != 0 {
		t.Fatalf("status %d", w1.status)
	}
	rr := httptest.NewRecorder()
	w := &metricsWriter{ResponseWriter: rr}
	w.Flush()
	if _, err := w.Write([]byte("abc")); err != nil || w.status != 200 || w.n != 3 {
		t.Fatalf("status=%d n=%d err=%v", w.status, w.n, err)
	}
	if w.Unwrap() != rr {
		t.Fatal("unwrap")
	}
	// ResponseWriter без Flusher не паникует.
	(&metricsWriter{ResponseWriter: nonFlusher{}}).Flush()
}

type nonFlusher struct{ http.ResponseWriter }
