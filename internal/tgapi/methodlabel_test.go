package tgapi_test

import (
	"math/rand"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func knownList(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, m := range []string{"sendMessage", "sendChatAction", "getMe", "forwardMessage", "copyMessage", "createForumTopic", "refundStarPayment"} {
		out = append(out, tgapi.MethodLabel(m))
	}
	return out
}

func TestMethodLabel(t *testing.T) {
	cases := map[string]string{
		"sendMessage": "sendmessage", "SENDMESSAGE": "sendmessage", "getUpdates": "getupdates",
		"nope": "other", "": "other", "test": "other",
	}
	for in, want := range cases {
		if got := tgapi.MethodLabel(in); got != want {
			t.Errorf("MethodLabel(%q) = %q, want %q", in, got, want)
		}
	}
	long := make([]byte, 100)
	for i := range long {
		long[i] = 'a'
	}
	if tgapi.MethodLabel(string(long)) != "other" {
		t.Error("long input must collapse")
	}
	if tgapi.KnownMethodCount() < 150 {
		t.Errorf("expected >=150 known methods, got %d", tgapi.KnownMethodCount())
	}
}

func TestMethodLabelCardinality(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	seen := map[string]struct{}{}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"
	for range 10000 {
		b := make([]byte, 1+rng.Intn(20))
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		seen[tgapi.MethodLabel(string(b))] = struct{}{}
	}
	if len(seen) > tgapi.KnownMethodCount()+1 {
		t.Fatalf("%d labels", len(seen))
	}
}
