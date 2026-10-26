package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAgentConnection(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.yaml")
	src := baseAgent + "# keep me\nmode: dial # tail\n"
	if err := os.WriteFile(p, []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SaveAgentConnection(p, AgentModeReverse, "https://srv:8444"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	for _, w := range []string{"mode: reverse", "server_url: https://srv:8444", "# keep me", "ca_file: ca.crt"} {
		if !strings.Contains(string(got), w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Errorf("perm = %v", st.Mode().Perm())
	}
	// пустой server_url не затирает прежний
	if err := SaveAgentConnection(p, AgentModeDial, ""); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(p)
	if !strings.Contains(string(got), "mode: dial") || !strings.Contains(string(got), "server_url: https://srv:8444") {
		t.Errorf("after dial:\n%s", got)
	}
	// результат остаётся валидным конфигом
	if _, err := parseAgent(t, string(got)); err != nil {
		t.Errorf("saved config does not load: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".agent-config-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestSaveAgentConnectionEmptyAndErrors(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.yaml")
	_ = os.WriteFile(empty, nil, 0o600)
	if err := SaveAgentConnection(empty, AgentModeBoth, "https://h"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(empty); !strings.Contains(string(b), "mode: both") {
		t.Errorf("empty:\n%s", b)
	}
	if err := SaveAgentConnection("", AgentModeDial, ""); err == nil {
		t.Error("empty path")
	}
	if err := SaveAgentConnection(filepath.Join(dir, "none.yaml"), AgentModeDial, ""); err == nil {
		t.Error("missing file")
	}
	bad := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(bad, []byte("a: [\n"), 0o600)
	if err := SaveAgentConnection(bad, AgentModeDial, ""); err == nil {
		t.Error("bad yaml")
	}
	seq := filepath.Join(dir, "seq.yaml")
	_ = os.WriteFile(seq, []byte("- a\n"), 0o600)
	if err := SaveAgentConnection(seq, AgentModeDial, ""); err == nil {
		t.Error("non-mapping root")
	}
	ro := filepath.Join(dir, "ro")
	_ = os.Mkdir(ro, 0o700)
	rp := filepath.Join(ro, "a.yaml")
	_ = os.WriteFile(rp, []byte("mode: dial\n"), 0o600)
	_ = os.Chmod(ro, 0o500)
	defer func() { _ = os.Chmod(ro, 0o700) }()
	if os.Geteuid() != 0 {
		if err := SaveAgentConnection(rp, AgentModeReverse, "https://h"); err == nil {
			t.Error("read-only dir must fail")
		}
	}
}

func TestLoadAgentSetsPathAndBoth(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	_ = os.WriteFile(p, []byte(baseAgent+"mode: both\nserver_url: https://srv:8444\n"), 0o600)
	c, err := LoadAgent(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Path() != p || c.Mode != AgentModeBoth {
		t.Fatalf("path=%q mode=%q", c.Path(), c.Mode)
	}
	if _, err := LoadAgent(filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("missing file")
	}
	if _, err := parseAgent(t, baseAgent+"mode: both\n"); err == nil {
		t.Fatal("both without server_url must fail")
	}
}
