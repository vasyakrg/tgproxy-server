package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/sqlite"
	"github.com/vasyakrg/tgproxy-server/internal/store/storetest"
)

func open(t *testing.T, path string) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		return open(t, filepath.Join(t.TempDir(), "db", "tgproxy.db"))
	})
}

func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tgproxy.db")
	s := open(t, path)
	ctx := context.Background()
	if _, err := s.Agents().Create(ctx, store.Agent{ID: "a1", Name: "n", URL: "https://x", Mode: store.ModeDial}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := open(t, path) // повторное применение на существующей БД
	if _, err := s2.Agents().Get(ctx, "a1"); err != nil {
		t.Fatalf("data lost after reopen: %v", err)
	}
	db := rawDB(t, path)
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM goose_db_version WHERE version_id = 1 AND is_applied = 1`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("migration 1 applied %d times, err=%v", n, err)
	}
	for _, idx := range []string{"error_events_phase", "error_events_code", "error_events_request", "error_events_method"} {
		if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, idx).Scan(&n); err != nil || n != 1 {
			t.Fatalf("index %s missing, err=%v", idx, err)
		}
	}
	for _, tbl := range []string{"agents", "agent_hostkeys", "certs", "cert_denylist", "access_rules", "sessions",
		"rate_windows", "outbox", "audit_log", "samples_10s", "samples_5m", "error_events", "enrollments",
		"install_jobs", "install_job_events", "releases", "pki_ca", "versions"} {
		if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+tbl).Scan(&n); err != nil {
			t.Errorf("table %s: %v", tbl, err)
		}
	}
}

func TestPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tgproxy.db")
	s := open(t, path)
	_ = s
	db := rawDB(t, path)
	var mode string
	if err := db.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, err=%v", mode, err)
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "tgproxy.db")
	s := open(t, path)
	if _, err := s.Agents().Create(context.Background(), store.Agent{ID: "a", Name: "n", URL: "https://x", Mode: store.ModeDial}); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, err=%v", di.Mode(), err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && p != path {
				continue
			}
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", filepath.Base(p), fi.Mode().Perm())
		}
	}
}

func TestConcurrentWritesNoBusy(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "tgproxy.db"))
	ctx := context.Background()
	const workers, each = 50, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := range workers {
		wg.Go(func() {
			for i := range each {
				id := "w" + string(rune('A'+w%26)) + string(rune('a'+w/26)) + string(rune('0'+i))
				if _, err := s.Agents().Create(ctx, store.Agent{ID: id, Name: id, URL: "https://x", Mode: store.ModeDial}); err != nil {
					errs <- err
				}
				if _, err := s.RateState().Incr(ctx, "shared", 1e12); err != nil {
					errs <- err
				}
				if _, err := s.Agents().List(ctx); err != nil {
					errs <- err
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent op: %v", err)
	}
	list, _ := s.Agents().List(ctx)
	if len(list) != workers*each {
		t.Fatalf("agents = %d, want %d", len(list), workers*each)
	}
	w, err := s.RateState().Get(ctx, "shared")
	if err != nil || string(w.Value) != "500" {
		t.Fatalf("counter = %q, err=%v", w.Value, err)
	}
}

func TestAccessRuleCheckConstraint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tgproxy.db")
	_ = open(t, path)
	db := rawDB(t, path)
	// в обход Go-валидации: CHECK в самой БД обязан отклонить правило без сети и ключа
	_, err := db.ExecContext(context.Background(), `INSERT INTO access_rules (name, cidrs, created_at) VALUES ('open', '[]', 0)`)
	if err == nil {
		t.Fatal("rule without cidrs and key must be rejected by CHECK")
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO access_rules (name, cidrs, created_at) VALUES ('net', '["10.0.0.0/8"]', 0)`); err != nil {
		t.Fatalf("network-only rule rejected: %v", err)
	}
}

func TestVersionVisibleAcrossProcesses(t *testing.T) {
	// Version растёт триггерами, поэтому запись «из CLI» (другое соединение) видна серверу.
	path := filepath.Join(t.TempDir(), "tgproxy.db")
	s := open(t, path)
	ctx := context.Background()
	v0, _ := s.AccessRules().Version(ctx)
	db := rawDB(t, path)
	if _, err := db.ExecContext(context.Background(), `INSERT INTO access_rules (name, cidrs, created_at) VALUES ('cli', '["10.0.0.0/8"]', 0)`); err != nil {
		t.Fatal(err)
	}
	v1, _ := s.AccessRules().Version(ctx)
	if v1 <= v0 {
		t.Fatalf("version %d -> %d", v0, v1)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := sqlite.Open(context.Background(), ""); err == nil {
		t.Fatal("empty path must fail")
	}
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlite.Open(context.Background(), filepath.Join(f, "sub", "db")); err == nil {
		t.Fatal("path under a file must fail")
	}
}
