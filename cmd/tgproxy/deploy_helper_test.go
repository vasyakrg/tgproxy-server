package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/vasyakrg/tgproxy-server/internal/deployhelper"
)

func TestDeployHelperCommandExitCodes(t *testing.T) {
	mk := func(euid int) func(*cobra.Command) *deployhelper.Helper {
		return func(cmd *cobra.Command) *deployhelper.Helper {
			h := deployhelper.New(cmd.OutOrStdout(), cmd.ErrOrStderr())
			h.EUID = func() int { return euid }
			h.Run = func(context.Context, io.Writer, io.Writer, string, ...string) error { return nil }
			return h
		}
	}
	for _, tc := range []struct {
		euid int
		args []string
		code int
	}{
		{0, []string{"unit", "status"}, 0},
		{0, []string{"unit", "link"}, 2},
		{0, []string{"install", "1.0.0 /tmp/evil.deb"}, 2},
		{0, []string{"--force", "unit", "status"}, 2}, // флаги не разбираются
		{1000, []string{"unit", "status"}, 1},
	} {
		cmd := newDeployHelperCmdWith(mk(tc.euid))
		cmd.SetArgs(tc.args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		err := cmd.Execute()
		code, isExit := exitCode(err)
		if tc.code == 0 && err != nil || tc.code != 0 && (!isExit || code != tc.code) {
			t.Errorf("%v euid=%d: err=%v code=%d, want %d", tc.args, tc.euid, err, code, tc.code)
		}
	}
}

func TestDeployHelperRegisteredAndHidden(t *testing.T) {
	out, err := run(t, "deploy-helper", "unit", "link")
	if _, ok := exitCode(err); !ok && os.Geteuid() == 0 {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if err == nil {
		t.Fatal("ожидался ненулевой код")
	}
	help, _ := run(t, "--help")
	if strings.Contains(help, "deploy-helper") {
		t.Fatal("хелпер не должен светиться в help")
	}
	if (exitError{3}).Error() != "exit status 3" {
		t.Fatal("Error()")
	}
}
