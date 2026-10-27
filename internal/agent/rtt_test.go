package agent

import (
	"net/http"
	"testing"
	"time"
)

const rttTestToken = "1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func get(t *testing.T, e *env, path string) {
	t.Helper()
	resp := e.do(t, http.MethodGet, path, nil, nil)
	defer func() { _ = resp.Body.Close() }()
	_ = readAll(t, resp.Body)
}

func TestClassifyTG(t *testing.T) {
	cases := []struct {
		path string
		want tgKind
	}{
		{"/tg/bot" + rttTestToken + "/getUpdates", tgKind{longPoll: true}},
		{"/tg/bot" + rttTestToken + "/GETUPDATES", tgKind{longPoll: true}},
		{"/tg/bot" + rttTestToken + "/test/getUpdates", tgKind{longPoll: true}},
		{"/tg/bot" + rttTestToken + "/getMe", tgKind{}},
		{"/tg/bot" + rttTestToken + "/sendMessage", tgKind{}},
		{"/tg/file/bot" + rttTestToken + "/photos/x.jpg", tgKind{file: true}},
		{"/tg/garbage", tgKind{}},
	}
	for _, c := range cases {
		if got := classifyTG(c.path); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.path, got, c.want)
		}
	}
	if !(tgKind{longPoll: true}).skipRTT() || !(tgKind{file: true}).skipRTT() || (tgKind{}).skipRTT() {
		t.Fatal("skipRTT")
	}
}

func TestRTTExcludesLongPollAndFiles(t *testing.T) {
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(30 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	for _, p := range []string{
		"/tg/bot" + rttTestToken + "/getUpdates",
		"/tg/bot" + rttTestToken + "/getupdates",
		"/tg/file/bot" + rttTestToken + "/photos/x.jpg",
	} {
		get(t, e, p)
	}
	if e.agent.stats.rttInit || e.agent.stats.upstreamRTT() != 0 {
		t.Fatalf("rtt учёл long-poll/файл: %v", e.agent.stats.upstreamRTT())
	}
	if e.agent.stats.rps1m() == 0 {
		t.Fatal("rps должен учитывать все запросы")
	}
	get(t, e, "/tg/bot"+rttTestToken+"/getMe")
	if e.agent.stats.upstreamRTT() <= 0 {
		t.Fatal("обычный метод должен попасть в rtt")
	}
}

func TestInflightLongPollSplit(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := newStats(func() time.Time { return now })
	s.begin(true)
	s.begin(false)
	if s.inflight.Load() != 2 || s.inflightLP.Load() != 1 {
		t.Fatalf("inflight=%d lp=%d", s.inflight.Load(), s.inflightLP.Load())
	}
	s.end(true)
	if s.inflight.Load() != 1 || s.inflightLP.Load() != 0 {
		t.Fatalf("inflight=%d lp=%d", s.inflight.Load(), s.inflightLP.Load())
	}
}

func TestStatusInflightLongPoll(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := e.client.Get("https://" + e.addr + "/tg/bot" + rttTestToken + "/getUpdates") //nolint:noctx
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for e.agent.stats.inflightLP.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	resp := e.do(t, http.MethodGet, "/_agent/status", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	st := readJSON(t, resp)
	if st["inflight"].(float64) != 1 || st["inflight_longpoll"].(float64) != 1 {
		t.Fatalf("status %v", st)
	}
	close(release)
	<-done
}
