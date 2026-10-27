package selfupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// showExec — fakeExec с `systemctl show`: ответы выбираются по числу выполненных dpkg -i
// (1 — новая версия, 2 — откат) и номеру опроса.
type showExec struct {
	*fakeExec
	pmu   sync.Mutex
	polls map[int]int
	reply func(dpkgs, poll int) string
}

func (s *showExec) Output(_ context.Context, name string, args ...string) (string, error) {
	if name != "systemctl" || len(args) == 0 || args[0] != "show" {
		return "", fmt.Errorf("unexpected %s %v", name, args)
	}
	dpkgs := 0
	s.mu.Lock()
	for _, c := range s.calls {
		if strings.HasPrefix(c, "dpkg --force-confdef --force-confold -i") {
			dpkgs++
		}
	}
	s.mu.Unlock()
	s.pmu.Lock()
	s.polls[dpkgs]++
	n := s.polls[dpkgs]
	s.pmu.Unlock()
	return s.reply(dpkgs, n), nil
}

func show(state string, restarts int, enter int) string {
	return fmt.Sprintf("ActiveState=%s\nNRestarts=%d\nActiveEnterTimestampMonotonic=%d\n", state, restarts, enter)
}

func agentEnv(t *testing.T, reply func(dpkgs, poll int) string) (*env, *Applier) {
	t.Helper()
	e := newEnv(t)
	e.write("updates/staged/request", []byte(`{"version":"0.2.0","component":"agent"}`), 0o644)
	e.ex = &fakeExec{fail: map[string]error{}}
	a := e.applier()
	a.c.Exec = &showExec{fakeExec: e.ex, polls: map[int]int{}, reply: reply}
	a.c.HealthTimeout = 400 * time.Millisecond
	a.c.AgentStableFor = 80 * time.Millisecond
	return e, a
}

// Агент «active → failed → active» (NRestarts растёт, Restart=on-failure): is-active в какой-то
// момент успешен, но стабильного окна нет — откат на prev.
func TestAgentCrashLoopRollsBack(t *testing.T) {
	e, a := agentEnv(t, func(dpkgs, poll int) string {
		switch {
		case dpkgs >= 2:
			return show("active", 0, 100) // после отката — стабильно
		case poll%3 == 0:
			return show("failed", poll/3, 0)
		default:
			return show("active", poll/3+1, poll*10) // NRestarts и enter-timestamp меняются
		}
	})
	err := a.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "health") {
		t.Fatalf("err = %v", err)
	}
	if r := e.result(); r.OK || !r.RolledBack {
		t.Fatalf("result = %+v", r)
	}
}

func TestAgentStableAcceptedAfterWindow(t *testing.T) {
	e, a := agentEnv(t, func(int, int) string { return show("active", 0, 100) })
	start := time.Now()
	if err := a.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 80*time.Millisecond {
		t.Errorf("принято без окна стабильности (%s)", time.Since(start))
	}
	if r := e.result(); !r.OK || r.RolledBack {
		t.Fatalf("result = %+v", r)
	}
}

func TestAgentRestartResetsWindow(t *testing.T) {
	// единственный рестарт посреди окна: отсчёт идёт заново, но дальше стабильно — успех
	e, a := agentEnv(t, func(_, poll int) string {
		if poll < 5 {
			return show("active", 0, 100)
		}
		return show("active", 1, 900)
	})
	if err := a.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.result().OK {
		t.Fatalf("result = %+v", e.result())
	}
}

func TestApplyCleansStagedAndFailedCache(t *testing.T) {
	e := newEnv(t)
	e.probe = func(context.Context, string) error { return fmt.Errorf("down") }
	e.ex.fail["dpkg -i "+filepath.Join(e.work, "prev.deb")] = nil
	if err := e.applier().Apply(context.Background()); err == nil {
		t.Fatal("ожидался провал health")
	}
	if _, err := os.Stat(filepath.Join(e.data, "packages/0.2.0")); !os.IsNotExist(err) {
		t.Errorf("каталог неудачной версии остался в root-кэше: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.data, "updates/staged")); !os.IsNotExist(err) {
		t.Errorf("staged не очищен: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.data, "updates/result.json")); err != nil {
		t.Errorf("result.json должен остаться: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.data, "packages/0.1.0")); err != nil {
		t.Errorf("кэш прежней версии удалён: %v", err)
	}
}

func TestAgentHealthURL(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:9443": "http://127.0.0.1:9443/healthz", ":9443": "http://127.0.0.1:9443/healthz",
		"0.0.0.0:9443": "http://127.0.0.1:9443/healthz", "localhost:9443": "http://localhost:9443/healthz",
		"[::1]:9443": "http://[::1]:9443/healthz", "10.0.0.5:9443": "", "": "", "garbage": "",
	} {
		if got := AgentHealthURL(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
