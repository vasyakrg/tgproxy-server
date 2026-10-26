package router_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/server/router"
)

func FuzzExtractChatID(f *testing.F) {
	f.Add("http://x/m", "application/json", `{"chat_id":-100123,"text":"a"}`)
	f.Add("http://x/m", "application/json", `{"chat_id":"@chan"}`)
	f.Add("http://x/m?chat_id=42", "", "")
	f.Add("http://x/m", "application/x-www-form-urlencoded", "text=a&chat_id=55")
	f.Add("http://x/m", "multipart/form-data; boundary=B", "--B\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n77\r\n--B--\r\n")
	f.Add("http://x/m", "///;;", "garbage")
	f.Fuzz(func(t *testing.T, target, ct, body string) {
		if _, err := url.Parse(target); err != nil || !strings.HasPrefix(target, "http://x/") {
			target = "http://x/m"
		}
		got := router.ExtractChatID(chatReq(target, ct), ramBody(t, body), lim)
		if len(got) > 128 || got != strings.TrimSpace(got) {
			t.Fatalf("unclean chat id %q", got)
		}
	})
}
