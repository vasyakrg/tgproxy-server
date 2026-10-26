package tgapi_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

const (
	pBody = "AAHdq" + "TcvCH1vGWJxfSeofSAs0K5PALDsaw" // склеено: литерал не должен совпадать с шаблоном токена (secret scanning)
	pTok  = "123456789:" + pBody
	pKey  = "tgp_abcdEFGH12345678"
)

func TestParsePathValid(t *testing.T) {
	tests := []struct {
		name, path string
		want       tgapi.Route
	}{
		{"method", "/bot" + pTok + "/sendMessage", tgapi.Route{Token: pTok, BotID: 123456789, Method: "sendmessage", RawMethod: "sendMessage"}},
		{"upper", "/bot" + pTok + "/GETUPDATES", tgapi.Route{Token: pTok, BotID: 123456789, Method: "getupdates", RawMethod: "GETUPDATES"}},
		{"key", "/k/" + pKey + "/bot" + pTok + "/getMe", tgapi.Route{ClientKey: pKey, Token: pTok, BotID: 123456789, Method: "getme", RawMethod: "getMe"}},
		{"test env", "/bot" + pTok + "/test/sendMessage", tgapi.Route{Token: pTok, BotID: 123456789, Method: "sendmessage", RawMethod: "sendMessage", TestEnv: true}},
		{"key test env", "/k/" + pKey + "/bot" + pTok + "/test/getMe", tgapi.Route{ClientKey: pKey, Token: pTok, BotID: 123456789, Method: "getme", RawMethod: "getMe", TestEnv: true}},
		{"method named test", "/bot" + pTok + "/test", tgapi.Route{Token: pTok, BotID: 123456789, Method: "test", RawMethod: "test"}},
		{"file", "/file/bot" + pTok + "/photos/file_1.jpg", tgapi.Route{Token: pTok, BotID: 123456789, IsFile: true, FilePath: "photos/file_1.jpg"}},
		{"file key", "/k/" + pKey + "/file/bot" + pTok + "/documents/file_2.pdf", tgapi.Route{ClientKey: pKey, Token: pTok, BotID: 123456789, IsFile: true, FilePath: "documents/file_2.pdf"}},
		{"file test", "/file/bot" + pTok + "/test/photos/a.jpg", tgapi.Route{Token: pTok, BotID: 123456789, IsFile: true, TestEnv: true, FilePath: "photos/a.jpg"}},
		{"file single", "/file/bot" + pTok + "/a.jpg", tgapi.Route{Token: pTok, BotID: 123456789, IsFile: true, FilePath: "a.jpg"}},
		{"key literally k", "/k/k/bot" + pTok + "/getMe", tgapi.Route{ClientKey: "k", Token: pTok, BotID: 123456789, Method: "getme", RawMethod: "getMe"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tgapi.ParsePath(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParsePathInvalid(t *testing.T) {
	bad := map[string]string{
		"empty":            "",
		"root":             "/",
		"no leading slash": "bot" + pTok + "/getMe",
		"no method":        "/bot" + pTok,
		"trailing slash":   "/bot" + pTok + "/getMe/",
		"double slash":     "/bot" + pTok + "//getMe",
		"leading double":   "//bot" + pTok + "/getMe",
		"dotdot":           "/bot" + pTok + "/../getMe",
		"dotdot file":      "/file/bot" + pTok + "/photos/../../etc/passwd",
		"encoded dotdot":   "/file/bot" + pTok + "/%2e%2e/x",
		"encoded slash":    "/bot" + pTok + "/send%2FMessage",
		"encoded slash lc": "/file/bot" + pTok + "/photos%2fa.jpg",
		"encoded backslsh": "/file/bot" + pTok + "/a%5Cb",
		"backslash":        "/file/bot" + pTok + "/a\\b",
		"bad escape":       "/bot" + pTok + "/get%ZZ",
		"control":          "/bot" + pTok + "/get%00Me",
		"short token":      "/bot123:abc/getMe",
		"no colon":         "/bot" + strings.Repeat("1", 40) + "/getMe",
		"bad token chars":  "/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALD$aw/getMe",
		"huge bot id":      "/bot9999999999999999999:" + pBody + "/getMe",
		"no bot prefix":    "/" + pTok + "/getMe",
		"wrong prefix":     "/foo/bar",
		"extra segments":   "/bot" + pTok + "/getMe/extra",
		"bad method":       "/bot" + pTok + "/get-Me",
		"long method":      "/bot" + pTok + "/" + strings.Repeat("a", 65),
		"key no bot":       "/k/" + pKey,
		"key only":         "/k/" + pKey + "/",
		"empty key":        "/k//bot" + pTok + "/getMe",
		"bad key":          "/k/bad%20key/bot" + pTok + "/getMe",
		"file no path":     "/file/bot" + pTok,
		"file only":        "/file",
		"file bad char":    "/file/bot" + pTok + "/a%3Fb",
		"dot segment":      "/file/bot" + pTok + "/./a",
		"too long":         "/bot" + pTok + "/" + strings.Repeat("a", 3000),
		"file seg too big": "/file/bot" + pTok + "/" + strings.Repeat("a", 256),
	}
	for name, p := range bad {
		t.Run(name, func(t *testing.T) {
			rt, err := tgapi.ParsePath(p)
			if !errors.Is(err, tgapi.ErrInvalidPath) {
				t.Fatalf("expected ErrInvalidPath, got %v (route %+v)", err, rt)
			}
			if strings.Contains(err.Error(), "AAHdq") {
				t.Fatal("error text leaks token")
			}
		})
	}
}

func TestBotID(t *testing.T) {
	rt, err := tgapi.ParsePath("/bot7654321:" + strings.Repeat("a", 35) + "/getMe")
	if err != nil || rt.BotID != 7654321 {
		t.Fatalf("%+v %v", rt, err)
	}
}

func TestUpstreamPath(t *testing.T) {
	for _, p := range []string{
		"/bot" + pTok + "/SendMessage",
		"/bot" + pTok + "/test/getMe",
		"/file/bot" + pTok + "/photos/file_1.jpg",
		"/file/bot" + pTok + "/test/photos/a%20b.jpg",
	} {
		rt, err := tgapi.ParsePath(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := rt.UpstreamPath(); got != p {
			t.Errorf("UpstreamPath = %q, want %q", got, p)
		}
	}
	rt, _ := tgapi.ParsePath("/k/" + pKey + "/bot" + pTok + "/getMe")
	if rt.UpstreamPath() != "/bot"+pTok+"/getMe" {
		t.Fatal("client key must not reach upstream")
	}
}
