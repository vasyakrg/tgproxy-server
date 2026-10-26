package tgapi

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ErrInvalidPath is returned for any path that is not a valid Bot API route.
// Its text never contains the offending path (it may hold a token).
var ErrInvalidPath = errors.New("tgapi: invalid bot api path")

// Route is a parsed proxy request path.
type Route struct {
	ClientKey string // from /k/<key>/..., empty if absent
	Token     string // full bot token
	BotID     int64
	Method    string // lower-cased method (empty for file routes)
	RawMethod string // method exactly as the client sent it, for upstream
	IsFile    bool
	FilePath  string // decoded path of /file/bot<token>/<path>
	TestEnv   bool   // /bot<token>/test/<method> or /file/bot<token>/test/<path>
}

// UpstreamPath returns the path to request from api.telegram.org.
func (r Route) UpstreamPath() string {
	var b strings.Builder
	if r.IsFile {
		b.WriteString("/file")
	}
	b.WriteString("/bot")
	b.WriteString(r.Token)
	if r.TestEnv {
		b.WriteString("/test")
	}
	b.WriteByte('/')
	if r.IsFile {
		b.WriteString(r.FilePath)
	} else {
		b.WriteString(r.RawMethod)
	}
	return (&url.URL{Path: b.String()}).EscapedPath()
}

var (
	tokenRe  = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,128}$`)
	keyRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	methodRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
)

// ParsePath parses the escaped URL path (url.URL.EscapedPath), so that an
// encoded slash can be told apart from a real separator:
//
//	[/k/<key>]/bot<token>/<method>
//	[/k/<key>]/bot<token>/test/<method>
//	[/k/<key>]/file/bot<token>/<path...>
//	[/k/<key>]/file/bot<token>/test/<path...>
func ParsePath(p string) (Route, error) {
	var rt Route
	if len(p) < 2 || p[0] != '/' || len(p) > 2048 {
		return rt, ErrInvalidPath
	}
	raw := strings.Split(p[1:], "/")
	segs := make([]string, len(raw))
	for i, s := range raw {
		if s == "" {
			return rt, ErrInvalidPath // empty segment, trailing or double slash
		}
		if strings.ContainsAny(s, "\\") {
			return rt, ErrInvalidPath
		}
		d, err := url.PathUnescape(s)
		if err != nil || d == "." || d == ".." || strings.ContainsAny(d, "/\\") {
			return rt, ErrInvalidPath
		}
		for j := 0; j < len(d); j++ {
			if d[j] < 0x20 || d[j] == 0x7f {
				return rt, ErrInvalidPath
			}
		}
		segs[i] = d
	}

	if segs[0] == "k" {
		if len(segs) < 3 || !keyRe.MatchString(segs[1]) {
			return rt, ErrInvalidPath
		}
		rt.ClientKey = segs[1]
		segs = segs[2:]
	}
	if segs[0] == "file" {
		rt.IsFile = true
		segs = segs[1:]
		if len(segs) == 0 {
			return rt, ErrInvalidPath
		}
	}
	if !strings.HasPrefix(segs[0], "bot") {
		return rt, ErrInvalidPath
	}
	token := segs[0][3:]
	if !tokenRe.MatchString(token) {
		return rt, ErrInvalidPath
	}
	id, err := strconv.ParseInt(token[:strings.IndexByte(token, ':')], 10, 64)
	if err != nil {
		return rt, ErrInvalidPath
	}
	rt.Token, rt.BotID = token, id
	rest := segs[1:]
	if len(rest) == 0 {
		return rt, ErrInvalidPath
	}
	if len(rest) > 1 && rest[0] == "test" {
		rt.TestEnv = true
		rest = rest[1:]
	}
	if rt.IsFile {
		for _, s := range rest {
			if !isFileSegment(s) {
				return Route{}, ErrInvalidPath
			}
		}
		rt.FilePath = strings.Join(rest, "/")
		return rt, nil
	}
	if len(rest) != 1 || !methodRe.MatchString(rest[0]) {
		return Route{}, ErrInvalidPath
	}
	rt.RawMethod = rest[0]
	rt.Method = strings.ToLower(rest[0])
	return rt, nil
}

// isFileSegment allows the conservative character set of Telegram file paths.
func isFileSegment(s string) bool {
	if len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '.', c == ' ', c == '(', c == ')', c == '+', c == '=', c == '@', c == ',':
		default:
			return false
		}
	}
	return true
}
