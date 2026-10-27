package access

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func h(k string) []byte { s := sha256.Sum256([]byte(k)); return s[:] }

func req(remote, xff, key string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if key != "" {
		r.Header.Set(tgapi.HeaderProxyKey, key)
	}
	return r
}

func pf(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestCheck(t *testing.T) {
	rules := []config.AccessRule{
		{Name: "net", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}, RPS: 5},
		{Name: "key", KeySHA256: "x", KeyHash: h("k1")},
		{Name: "both", CIDRs: []netip.Prefix{pf("192.168.0.0/16")}, KeySHA256: "x", KeyHash: h("k2")},
	}
	c, err := NewStatic(rules, []netip.Prefix{pf("172.16.0.0/12")})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote, xff, hdrKey, pathKey string
		want                               string
		reason                             Reason // для отказа
	}{
		{"net no key", "10.1.1.1:1", "", "", "", "net", ""},
		{"foreign net no key", "8.8.8.8:1", "", "", "", "", ReasonKeyRequired},
		{"key anywhere", "8.8.8.8:1", "", "", "k1", "key", ""},
		{"header key", "8.8.8.8:1", "", "k1", "", "key", ""},
		{"wrong key", "10.1.1.1:1", "", "", "bad", "", ReasonBadKey},
		{"both ok", "192.168.1.1:1", "", "", "k2", "both", ""},
		{"both wrong net", "8.8.8.8:1", "", "", "k2", "", ReasonNoRule},
		{"xff untrusted ignored", "8.8.8.8:1", "10.1.1.1", "", "", "", ReasonKeyRequired},
		{"xff trusted used", "172.16.0.1:1", "8.8.8.8, 10.1.1.1", "", "", "net", ""},
		{"xff trusted outside", "172.16.0.1:1", "10.1.1.1, 8.8.8.8", "", "", "", ReasonKeyRequired},
		{"xff garbage", "172.16.0.1:1", "zzz", "", "", "", ReasonKeyRequired},
		{"bad remote", "garbage", "", "", "", "", ReasonKeyRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := c.Check(req(tc.remote, tc.xff, tc.hdrKey), tgapi.Route{ClientKey: tc.pathKey})
			if tc.want == "" {
				if !errors.Is(err, ErrDenied) || ReasonOf(err) != tc.reason {
					t.Fatalf("want denied(%s), got %v %v", tc.reason, info, err)
				}
				return
			}
			if err != nil || info.Name != tc.want {
				t.Fatalf("got %v %v want %s", info, err, tc.want)
			}
		})
	}
	if info, _ := c.Check(req("10.1.1.1:1", "", ""), tgapi.Route{}); info.RPS != 5 {
		t.Fatalf("rps %v", info.RPS)
	}
}

func TestSpecificity(t *testing.T) {
	c, _ := NewStatic([]config.AccessRule{
		{Name: "key", KeySHA256: "x", KeyHash: h("k")},
		{Name: "both", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}, KeySHA256: "x", KeyHash: h("k")},
	}, nil)
	info, err := c.Check(req("10.0.0.1:1", "", ""), tgapi.Route{ClientKey: "k"})
	if err != nil || info.Name != "both" {
		t.Fatal(info, err)
	}
}

func TestNewStaticOpenRule(t *testing.T) {
	if _, err := NewStatic([]config.AccessRule{{Name: "open"}}, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestNewStaticKeyWithoutHash(t *testing.T) {
	if _, err := NewStatic([]config.AccessRule{{Name: "k", KeySHA256: "x"}}, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestIPv4Mapped(t *testing.T) {
	c, _ := NewStatic([]config.AccessRule{{Name: "n", CIDRs: []netip.Prefix{pf("10.0.0.0/8")}}}, nil)
	if _, err := c.Check(req("[::ffff:10.1.1.1]:1", "", ""), tgapi.Route{}); err != nil {
		t.Fatal(err)
	}
}

// Причины отказа в сценарии «сеть И ключ»: клиент из своей сети без ключа — key_required,
// с чужим ключом — bad_key, из чужой сети — no_rule. Ответ клиенту для всех один и тот же.
func TestDenyReasonsNetworkAndKey(t *testing.T) {
	c, err := NewStatic([]config.AccessRule{
		{Name: "both", CIDRs: []netip.Prefix{pf("192.168.0.0/16")}, KeySHA256: "x", KeyHash: h("secret")},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote, key string
		want              Reason
	}{
		{"net without key", "192.168.1.1:1", "", ReasonKeyRequired},
		{"net wrong key", "192.168.1.1:1", "nope", ReasonBadKey},
		{"foreign net without key", "8.8.8.8:1", "", ReasonNoRule},
		{"foreign net right key", "8.8.8.8:1", "secret", ReasonNoRule},
		{"foreign net wrong key", "8.8.8.8:1", "nope", ReasonBadKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Check(req(tc.remote, "", tc.key), tgapi.Route{})
			if !errors.Is(err, ErrDenied) || ReasonOf(err) != tc.want {
				t.Fatalf("got %v (%q), want %s", err, ReasonOf(err), tc.want)
			}
			if tc.key != "" && (strings.Contains(err.Error(), tc.key) || strings.Contains(err.Error(), "secret")) {
				t.Fatalf("error leaks key: %v", err)
			}
		})
	}
	if _, err := c.Check(req("192.168.1.1:1", "", "secret"), tgapi.Route{}); err != nil {
		t.Fatal(err)
	}
}

func TestReasonHelpers(t *testing.T) {
	for _, r := range []Reason{ReasonNoRule, ReasonKeyRequired, ReasonBadKey} {
		if !r.CountsForBan() || !r.Valid() {
			t.Fatalf("%s must count for ban", r)
		}
	}
	for _, r := range []Reason{ReasonRateLimited, ReasonBanned} {
		if r.CountsForBan() || !r.Valid() {
			t.Fatalf("%s must not count for ban", r)
		}
	}
	if Reason("x").Valid() || ReasonOf(errors.New("x")) != "" || ReasonOf(&RateLimitedError{}) != ReasonRateLimited {
		t.Fatal("reason helpers")
	}
}
