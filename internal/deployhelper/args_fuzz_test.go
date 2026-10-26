package deployhelper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// FuzzArgs: любой ввод не паникует, а внешние команды — только dpkg/systemctl
// с фиксированным набором аргументов (никаких данных из args в argv).
func FuzzArgs(f *testing.F) {
	for _, s := range []string{
		"install\x001.2.3", "stage\x00x\x001.2.3", "unit\x00status", "unit\x00enable-update",
		"install\x00../1.0.0", "unit\x00link", "stage\x00../../etc/passwd\x001.0.0", "", "bogus",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, joined string) {
		d := t.TempDir()
		var out, errb bytes.Buffer
		h := New(&out, &errb)
		h.PackagesDir, h.IncomingDir = d, d
		h.EUID = func() int { return 0 }
		h.Verifier = failVerifier{errors.New("fuzz")}
		h.Run = func(_ context.Context, _, _ io.Writer, name string, args ...string) error {
			if name != dpkgPath && name != systemctlPath {
				t.Fatalf("unexpected command %q", name)
			}
			for _, a := range args {
				if strings.Contains(joined, "\x00") && len(a) > 0 && strings.Contains(a, "/") && !strings.HasPrefix(a, "--") &&
					!strings.HasPrefix(a, "/usr/") && !strings.HasPrefix(a, "/var/") && !strings.HasPrefix(a, "/run/") {
					t.Fatalf("argv has attacker-controlled path %q", a)
				}
			}
			return errors.New("fuzz: no exec")
		}
		_ = h.Main(context.Background(), strings.Split(joined, "\x00"))
	})
}
