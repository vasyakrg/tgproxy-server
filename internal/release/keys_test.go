package release

import (
	"strings"
	"testing"
)

func TestEmbeddedPubKeys(t *testing.T) {
	ks, err := EmbeddedPubKeys()
	if err != nil || len(ks) != 1 {
		t.Fatalf("ks=%d err=%v", len(ks), err)
	}
	old := pubKeysCSV
	defer func() { pubKeysCSV = old }()
	pubKeysCSV = testPubKey + " , " + testPubKey + ",,"
	if ks, err = EmbeddedPubKeys(); err != nil || len(ks) != 2 {
		t.Fatalf("ks=%d err=%v", len(ks), err)
	}
	pubKeysCSV = "bad"
	if _, err = EmbeddedPubKeys(); err == nil || !strings.Contains(err.Error(), "pubkeys[0]") {
		t.Fatalf("err=%v", err)
	}
}
