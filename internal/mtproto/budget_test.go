package mtproto

import (
	"strings"
	"testing"
)

func TestFDBudgetWarning(t *testing.T) {
	cases := []struct {
		name     string
		maxConns int
		limit    uint64
		warn     bool
	}{
		{"запас достаточен", 20000, 65536, false},
		{"впритык", 20000, 20000*2 + 16384, false},
		{"не хватает 1", 20000, 20000*2 + 16383, true},
		{"мало", 20000, 1024, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := fdBudgetCheck(c.maxConns, c.limit)
			if (msg != "") != c.warn {
				t.Fatalf("msg=%q, warn=%v", msg, c.warn)
			}
			if c.warn && !strings.Contains(msg, "RLIMIT_NOFILE") {
				t.Fatalf("сообщение без RLIMIT_NOFILE: %q", msg)
			}
		})
	}
}

func TestCheckFDBudgetUsesRlimit(t *testing.T) {
	if CheckFDBudget(1) != "" {
		t.Fatal("maxConns=1 не должен давать предупреждение при нормальном rlimit")
	}
	if _, ok := nofileLimit(); ok && CheckFDBudget(1<<40) == "" {
		t.Fatal("огромный maxConns должен давать предупреждение")
	}
}
