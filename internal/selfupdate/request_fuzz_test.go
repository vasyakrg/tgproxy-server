package selfupdate

import (
	"strings"
	"testing"
)

func FuzzParseRequest(f *testing.F) {
	for _, s := range []string{
		`{"version":"1.2.3","component":"server"}`,
		`{"version":"0.1.0-rc.1","component":"agent"}`,
		`{"version":"1.2.3","component":"server"} {}`,
		`{"version":"1.2.3","component":"server","x":1}`,
		`{"version":"../../etc","component":"agent"}`,
		`{"version":"1.2.3"}`, `[]`, `null`, ``,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		req, err := ParseRequest(strings.NewReader(s))
		if err != nil {
			return
		}
		if !versionRe.MatchString(req.Version) {
			t.Fatalf("accepted bad version %q", req.Version)
		}
		if strings.ContainsAny(req.Version, "/\\\x00 ") {
			t.Fatalf("version with path chars %q", req.Version)
		}
		if req.Component != ComponentServer && req.Component != ComponentAgent {
			t.Fatalf("accepted component %q", req.Component)
		}
	})
}
