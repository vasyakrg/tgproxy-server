package router_test

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/router"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func env429(sec int) *tgapi.Envelope {
	return &tgapi.Envelope{ErrorCode: 429, Description: "Too Many Requests", Parameters: &tgapi.ResponseParameters{RetryAfter: sec}}
}

func TestWindowBlocksOnlyBotChat(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	w := router.NewWindows(nil, clk.now)
	if _, blocked := w.Check(1, "100"); blocked {
		t.Fatal("blocked before any 429")
	}
	w.Observe(1, "100", env429(7))
	left, blocked := w.Check(1, "100")
	if !blocked || left != 7*time.Second {
		t.Fatalf("left=%v blocked=%v", left, blocked)
	}
	if _, b := w.Check(1, "200"); b {
		t.Fatal("other chat must not be blocked")
	}
	if _, b := w.Check(2, "100"); b {
		t.Fatal("other bot must not be blocked")
	}
	if _, b := w.Check(1, ""); b {
		t.Fatal("chat-less key must not be blocked")
	}
	clk.add(3 * time.Second)
	if left, b := w.Check(1, "100"); !b || left != 4*time.Second {
		t.Fatalf("left=%v blocked=%v", left, b)
	}
	clk.add(4 * time.Second)
	if _, b := w.Check(1, "100"); b {
		t.Fatal("window must expire at deadline")
	}
}

func TestObserveIgnoresIrrelevant(t *testing.T) {
	w := router.NewWindows(nil, nil)
	for _, e := range []*tgapi.Envelope{
		nil,
		{OK: true},
		{ErrorCode: 400, Parameters: &tgapi.ResponseParameters{RetryAfter: 5}},
		{ErrorCode: 429},
		{ErrorCode: 429, Parameters: &tgapi.ResponseParameters{}},
		{ErrorCode: 429, Parameters: &tgapi.ResponseParameters{RetryAfter: -3}},
	} {
		w.Observe(1, "1", e)
		if _, b := w.Check(1, "1"); b {
			t.Fatalf("window opened by %+v", e)
		}
	}
}

func TestObserveCapAndExtend(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	w := router.NewWindows(nil, clk.now)
	w.Observe(1, "1", env429(10*24*3600))
	if left, _ := w.Check(1, "1"); left != time.Hour {
		t.Fatalf("cap: %v", left)
	}
	w.Observe(1, "1", env429(5))
	if left, _ := w.Check(1, "1"); left != 5*time.Second {
		t.Fatalf("latest wins: %v", left)
	}
}

func TestMemStoreExpiryAndSweep(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s := router.NewMemStore(clk.now)
	s.Set("a", clk.now().Add(time.Second), time.Second)
	if _, ok := s.Get("a"); !ok {
		t.Fatal("want hit")
	}
	clk.add(2 * time.Second)
	if _, ok := s.Get("a"); ok {
		t.Fatal("want expired")
	}
	if _, ok := s.Get("missing"); ok {
		t.Fatal("want miss")
	}
	// массовая запись запускает очистку истёкших
	for i := range 1100 {
		s.Set(strings.Repeat("k", 1)+string(rune('A'+i%26))+string(rune('a'+i/26%26)), clk.now().Add(-time.Second), 0)
	}
	if router.NewMemStore(nil) == nil {
		t.Fatal("nil clock must default")
	}
}

func ramBody(t *testing.T, data string) router.Replayable {
	t.Helper()
	cfg := cfgBuf(t, 1<<20, 10<<20)
	b, err := router.Wrap(bufReq(io.NopCloser(strings.NewReader(data)), int64(len(data))), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func chatReq(target, ct string) *http.Request {
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, target, nil)
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	return r
}

const lim = 1 << 20

func TestExtractChatID(t *testing.T) {
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	_ = mw.WriteField("text", "hi")
	_ = mw.WriteField("chat_id", " -1001234 ")
	fw, _ := mw.CreateFormFile("photo", "a.jpg")
	_, _ = fw.Write([]byte("JPEGDATA"))
	_ = mw.Close()
	mpCT := mw.FormDataContentType()

	var mpFile bytes.Buffer
	mw2 := multipart.NewWriter(&mpFile)
	fw2, _ := mw2.CreateFormFile("chat_id", "x.txt") // файл с таким именем — не поле
	_, _ = fw2.Write([]byte("999"))
	_ = mw2.Close()

	cases := []struct {
		name, target, ct, body, want string
	}{
		{"query", "http://x/sendMessage?chat_id=42", "", "", "42"},
		{"query beats body", "http://x/m?chat_id=42", "application/json", `{"chat_id":7}`, "42"},
		{"json number", "http://x/m", "application/json", `{"text":"a","chat_id":-100123}`, "-100123"},
		{"json string", "http://x/m", "application/json; charset=utf-8", `{"chat_id":"@chan"}`, "@chan"},
		{"json no chat", "http://x/m", "application/json", `{"text":"a"}`, ""},
		{"json null", "http://x/m", "application/json", `{"chat_id":null}`, ""},
		{"json object", "http://x/m", "application/json", `{"chat_id":{"a":1}}`, ""},
		{"json bad string", "http://x/m", "application/json", `{"chat_id":"\uZZ"}`, ""},
		{"json broken", "http://x/m", "application/json", `{"chat_id":`, ""},
		{"form", "http://x/m", "application/x-www-form-urlencoded", "text=a&chat_id=55", "55"},
		{"form bad", "http://x/m", "application/x-www-form-urlencoded", "chat_id=%zz", ""},
		{"multipart", "http://x/m", mpCT, mp.String(), "-1001234"},
		{"multipart file part", "http://x/m", mw2.FormDataContentType(), mpFile.String(), ""},
		{"multipart no boundary", "http://x/m", "multipart/form-data", mp.String(), ""},
		{"multipart broken", "http://x/m", mpCT, "garbage", ""},
		{"unknown ct", "http://x/m", "text/plain", "chat_id=1", ""},
		{"no ct", "http://x/m", "", `{"chat_id":1}`, ""},
		{"bad ct", "http://x/m", "///;;", `{"chat_id":1}`, ""},
		{"too long", "http://x/m", "application/json", `{"chat_id":"` + strings.Repeat("9", 200) + `"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := router.ExtractChatID(chatReq(c.target, c.ct), ramBody(t, c.body), lim)
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestExtractChatIDGuards(t *testing.T) {
	if got := router.ExtractChatID(chatReq("http://x/m", "application/json"), nil, lim); got != "" {
		t.Fatal("nil body")
	}
	b := ramBody(t, `{"chat_id":5}`)
	if got := router.ExtractChatID(chatReq("http://x/m", "application/json"), b, 0); got != "" {
		t.Fatal("zero limit")
	}
	_ = b.Close()
	if got := router.ExtractChatID(chatReq("http://x/m", "application/json"), b, lim); got != "" {
		t.Fatal("closed body")
	}
}

func TestExtractChatIDRefusesOverLimit(t *testing.T) {
	big := `{"pad":"` + strings.Repeat("x", 2000) + `","chat_id":5}`
	b := ramBody(t, big)
	if got := router.ExtractChatID(chatReq("http://x/m", "application/json"), b, 1000); got != "" {
		t.Fatalf("json over limit parsed: %q", got)
	}
	if b.BytesConsumed() != 0 {
		t.Fatalf("over-limit body must not be read, consumed %d", b.BytesConsumed())
	}
	form := "pad=" + strings.Repeat("x", 2000) + "&chat_id=5"
	if got := router.ExtractChatID(chatReq("http://x/m", "application/x-www-form-urlencoded"), ramBody(t, form), 1000); got != "" {
		t.Fatalf("form over limit parsed: %q", got)
	}
	// неизвестная длина (chunked, превысил DiskMax) — не воспроизводимо, не читаем
	cfg := config.BufferConfig{RAMMax: 4, DiskMax: 8, TmpDir: t.TempDir()}
	nb, err := router.Wrap(bufReq(io.NopCloser(strings.NewReader(`{"chat_id":5,"pad":"xxxxxxxxxx"}`)), -1), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nb.Close() }()
	if got := router.ExtractChatID(chatReq("http://x/m", "application/json"), nb, lim); got != "" || nb.BytesConsumed() != 0 {
		t.Fatalf("non-replayable touched: %q consumed=%d", got, nb.BytesConsumed())
	}
}

func TestExtractChatIDMultipartBounded(t *testing.T) {
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	_ = mw.WriteField("chat_id", "321")
	fw, _ := mw.CreateFormFile("document", "big.bin")
	_, _ = fw.Write(bytes.Repeat([]byte("z"), 5000))
	_ = mw.Close()
	b := ramBody(t, mp.String())
	if got := router.ExtractChatID(chatReq("http://x/m", mw.FormDataContentType()), b, 500); got != "321" {
		t.Fatalf("got %q", got)
	}
	if b.BytesConsumed() > 500+4096 { // bufio внутри multipart читает блоком, но не более limit
		t.Fatalf("consumed %d", b.BytesConsumed())
	}
	if b.BytesConsumed() > 500 {
		t.Fatalf("read past limit: %d", b.BytesConsumed())
	}

	// chat_id после файла за пределами лимита — не найден
	var late bytes.Buffer
	mw2 := multipart.NewWriter(&late)
	fw2, _ := mw2.CreateFormFile("document", "big.bin")
	_, _ = fw2.Write(bytes.Repeat([]byte("z"), 5000))
	_ = mw2.WriteField("chat_id", "321")
	_ = mw2.Close()
	if got := router.ExtractChatID(chatReq("http://x/m", mw2.FormDataContentType()), ramBody(t, late.String()), 500); got != "" {
		t.Fatalf("got %q", got)
	}
}
