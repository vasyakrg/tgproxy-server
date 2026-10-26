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

func TestStubCommandsNotImplemented(t *testing.T) {
	for _, name := range []string{"server", "agent"} {
		cmd := newRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{name})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not implemented") {
			t.Errorf("%s: err = %v, want not implemented", name, err)
		}
	}
}
