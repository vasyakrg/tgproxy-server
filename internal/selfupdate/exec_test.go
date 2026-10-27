package selfupdate

import (
	"bytes"
	"context"
	"testing"
)

func TestSystemExecutorDpkgForceAllowlist(t *testing.T) {
	var out bytes.Buffer
	ex := SystemExecutor{Stdout: &out, Stderr: &out}
	for _, bad := range []string{"--force-all", "--force-depends", "--force-confnew"} {
		if err := ex.Run(context.Background(), "dpkg", bad, "-i", "/x.deb"); err == nil {
			t.Errorf("%s должен быть отклонён", bad)
		}
	}
	if err := checkDpkgArgs([]string{"--force-confdef", "--force-confold", "-i", "/x.deb"}); err != nil {
		t.Fatal(err)
	}
}
