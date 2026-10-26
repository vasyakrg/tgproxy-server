package auth

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestLoadUsersFields(t *testing.T) {
	e := newEnv(t, false)
	u, ok := e.users.Get("alice")
	if !ok || u.DisplayName != "Alice" || u.Email != "alice@example.test" || u.TOTPSecretEnc == "" {
		t.Fatalf("%+v", u)
	}
	if c, _ := e.users.Get("carol"); !c.Disabled {
		t.Fatal("carol must be disabled")
	}
	if _, ok := e.users.Get("nobody"); ok {
		t.Fatal("unexpected user")
	}
	if got := e.users.Names(); !reflect.DeepEqual(got, []string{"alice", "bob", "carol"}) {
		t.Fatalf("names: %v", got)
	}
}

func TestLoadUsersDevFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "u.yml")
	writeUsers(t, path, "users:\n  admin:\n    displayname: Dev Admin\n    password: '"+devHash+"'\n    telegram_id: 42\n    groups: [admins]\n", 0o600)
	u, err := LoadUsers(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := u.Get("admin")
	if a.TelegramID != 42 || !reflect.DeepEqual(a.Groups, []string{"admins"}) {
		t.Fatalf("%+v", a)
	}
}

func TestLoadUsersRejects(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		body string
		mode uint32
	}{
		"wide perms": {"users: {}\n", 0o644},
		"group w":    {"users: {}\n", 0o660},
		"bad yaml":   {"users: [\n", 0o640},
		"bad hash":   {"users:\n  a:\n    password: nope\n", 0o640},
		"empty name": {"users:\n  '':\n    password: '" + devHash + "'\n", 0o640},
	}
	for name, c := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		writeUsers(t, p, c.body, 0o600)
		if err := chmod(p, c.mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadUsers(p, discard()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadUsers(filepath.Join(dir, "missing"), nil); err == nil {
		t.Error("missing accepted")
	}
	if _, err := LoadUsers(dir, nil); err == nil {
		t.Error("dir accepted")
	}
	empty := filepath.Join(dir, "empty")
	writeUsers(t, empty, "", 0o640)
	if u, err := LoadUsers(empty, nil); err != nil || len(u.Names()) != 0 {
		t.Errorf("empty file: %v", err)
	}
}

func TestReloadAppliesAndKeepsOldOnBroken(t *testing.T) {
	e := newEnv(t, false)
	var mu sync.Mutex
	var changed []string
	e.users.OnChange(func(n []string) { mu.Lock(); changed = append(changed, n...); mu.Unlock() })

	// Ломаем файл: остаётся старая версия.
	writeUsers(t, e.path, "users: [\n", 0o640)
	if err := e.users.Reload(); err == nil {
		t.Fatal("broken file reloaded")
	}
	if _, ok := e.users.Get("alice"); !ok {
		t.Fatal("old version lost")
	}
	// Файл удалён: тоже остаётся старая.
	// Права шире 0640: ошибка, версия прежняя.
	writeUsers(t, e.path, "users: {}\n", 0o644)
	if err := e.users.Reload(); err == nil {
		t.Fatal("wide perms reloaded")
	}
	if _, ok := e.users.Get("alice"); !ok {
		t.Fatal("old version lost")
	}
	// Валидный новый файл: alice и bob удалены/отключены, dave добавлен.
	writeUsers(t, e.path, "users:\n  bob:\n    password: '"+fastHash(t, "x")+"'\n    disabled: true\n  dave:\n    password: '"+devHash+"'\n", 0o640)
	if err := e.users.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.users.Get("alice"); ok {
		t.Fatal("alice must be gone")
	}
	if _, ok := e.users.Get("dave"); !ok {
		t.Fatal("dave missing")
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(changed, []string{"alice", "bob", "carol"}) {
		t.Fatalf("changed: %v", changed)
	}
}

func TestWatchReloadsWithoutRestart(t *testing.T) {
	e := newEnv(t, false)
	e.users.debounce = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.users.Watch(ctx) }()
	time.Sleep(100 * time.Millisecond) // дать watcher'у подписаться

	writeUsers(t, e.path, "users:\n  erin:\n    password: '"+devHash+"'\n", 0o640)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := e.users.Get("erin"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("file change not applied")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWatchBadDir(t *testing.T) {
	u := &Users{path: filepath.Join(t.TempDir(), "nope", "u.yml"), log: discard()}
	if err := u.Watch(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestDiffUsersNilOld(t *testing.T) {
	if diffUsers(nil, &UsersFile{}) != nil {
		t.Fatal("expected nil")
	}
}
