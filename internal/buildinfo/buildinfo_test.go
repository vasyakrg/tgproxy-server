package buildinfo_test

import (
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
)

func TestDefaults(t *testing.T) {
	if buildinfo.Version != "dev" {
		t.Errorf("Version = %q, want dev", buildinfo.Version)
	}
	if buildinfo.Commit != "none" {
		t.Errorf("Commit = %q, want none", buildinfo.Commit)
	}
	if buildinfo.Date != "unknown" {
		t.Errorf("Date = %q, want unknown", buildinfo.Date)
	}
}
