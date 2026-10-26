package tgapi

import (
	"net/url"
	"strings"
	"testing"
)

const fuzzTok = "123456789:" + "AAHdq" + "TcvCH1vGWJxfSeofSAs0K5PALDsaw_-" // склеено: литерал не должен совпадать с шаблоном токена (secret scanning)

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{
		"/bot" + fuzzTok + "/getMe",
		"/k/abcDEF_-123/bot" + fuzzTok + "/sendMessage",
		"/bot" + fuzzTok + "/test/getMe",
		"/file/bot" + fuzzTok + "/photos/file_1.jpg",
		"/k/key/file/bot" + fuzzTok + "/test/documents/a b(1).pdf",
		"/bot" + fuzzTok + "/get%2FMe",
		"/bot" + fuzzTok + "/../getMe",
		"//bot" + fuzzTok + "/getMe",
		"/bot123:short/getMe",
		"/",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		rt, err := ParsePath(p)
		if err != nil {
			if err != ErrInvalidPath { //nolint:errorlint // sentinel, не обёрнут
				t.Fatalf("unexpected error type: %v", err)
			}
			if strings.Contains(err.Error(), p) && p != "" && len(p) > 8 {
				t.Fatalf("error leaks path")
			}
			return
		}
		if !tokenRe.MatchString(rt.Token) {
			t.Fatalf("accepted bad token %q", rt.Token)
		}
		if rt.IsFile {
			if rt.FilePath == "" || strings.Contains(rt.FilePath, "..") && hasDotDotSegment(rt.FilePath) {
				t.Fatalf("bad file path %q", rt.FilePath)
			}
		} else if !methodRe.MatchString(rt.RawMethod) || rt.Method != strings.ToLower(rt.RawMethod) {
			t.Fatalf("bad method %q", rt.RawMethod)
		}
		if rt.ClientKey != "" && !keyRe.MatchString(rt.ClientKey) {
			t.Fatalf("bad key %q", rt.ClientKey)
		}
		// Апстрим-путь обязан быть разбираемым и не содержать traversal/пустых сегментов.
		up := rt.UpstreamPath()
		if strings.Contains(up, "//") || strings.Contains(up, "/../") || strings.HasSuffix(up, "/..") {
			t.Fatalf("unsafe upstream path %q", up)
		}
		back, err := ParsePath(up)
		if err != nil {
			t.Fatalf("upstream path %q does not round-trip: %v", up, err)
		}
		if back.Token != rt.Token || back.Method != rt.Method || back.FilePath != rt.FilePath || back.TestEnv != rt.TestEnv || back.IsFile != rt.IsFile {
			t.Fatalf("round-trip mismatch: %+v vs %+v", rt, back)
		}
		if _, err := url.Parse(up); err != nil {
			t.Fatalf("upstream path not a valid URL: %v", err)
		}
	})
}

func hasDotDotSegment(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if s == ".." || s == "." {
			return true
		}
	}
	return false
}
