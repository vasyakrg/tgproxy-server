package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
)

func TestVersionCommand(t *testing.T) {
	oldV, oldC, oldD := buildinfo.Version, buildinfo.Commit, buildinfo.Date
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit, buildinfo.Date = oldV, oldC, oldD })
	buildinfo.Version, buildinfo.Commit, buildinfo.Date = "v1.2.3", "abc1234", "2026-10-26T00:00:00Z"

	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"v1.2.3", "abc1234", "2026-10-26T00:00:00Z",
		runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q does not contain %q", got, want)
		}
	}
}
