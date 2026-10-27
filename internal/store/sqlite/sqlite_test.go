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
	"time"

	"github.com/pressly/goose/v3"

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

// Миграция 0004 расширяет CHECK режима до both и не теряет агентов и триггер версии.
func TestMigration0004AgentModeBoth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db := rawDB(t, path)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id,name,url,mode,weight,draining,created_at,updated_at) VALUES ('a1','a1','https://x','dial',7,1,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id,name,url,mode,created_at,updated_at) VALUES ('x','x','','both',1,1)`); err == nil {
		t.Fatal("old schema accepted mode both")
	}
	var before int64
	if err := db.QueryRowContext(ctx, `SELECT v FROM versions WHERE name='agents'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	var w, d int
	if err := db.QueryRowContext(ctx, `SELECT weight, draining FROM agents WHERE id='a1'`).Scan(&w, &d); err != nil || w != 7 || d != 1 {
		t.Fatalf("agent lost: %d %d %v", w, d, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id,name,url,mode,created_at,updated_at) VALUES ('b','b','https://y','both',1,1)`); err != nil {
		t.Fatalf("both rejected: %v", err)
	}
	var after int64
	if err := db.QueryRowContext(ctx, `SELECT v FROM versions WHERE name='agents'`).Scan(&after); err != nil || after <= before+1 {
		t.Fatalf("version trigger: %d -> %d %v", before, after, err)
	}
}

// Миграция 0007 добавляет ssh_host/ssh_port и заполняет их из успешных задач установки.
func TestMigration0007AgentSSHTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db := rawDB(t, path)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 6); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO agents (id,name,url,mode,created_at,updated_at) VALUES ('a1','a1','https://x','dial',1,1)`,
		`INSERT INTO agents (id,name,url,mode,created_at,updated_at) VALUES ('a2','a2','https://y','dial',1,1)`,
		`INSERT INTO agents (id,name,url,mode,created_at,updated_at) VALUES ('a3','a3','https://z','dial',1,1)`,
		`INSERT INTO agents (id,name,url,mode,created_at,updated_at) VALUES ('r1','r1','','reverse',1,1)`,
		`INSERT INTO install_jobs (id,agent_id,host,kind,state,created_at) VALUES ('j1','a1','203.0.113.5:2222','install','done',1)`,
		`INSERT INTO install_jobs (id,agent_id,host,kind,state,created_at) VALUES ('j2','a2','[2001:db8::1]:22','install','done',1)`,
		`INSERT INTO install_jobs (id,agent_id,host,kind,state,created_at) VALUES ('j3','a3','203.0.113.7:22','install','failed',1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		host string
		port int
	}{"a1": {"203.0.113.5", 2222}, "a2": {"2001:db8::1", 22}, "a3": {"", 0}, "r1": {"", 0}}
	for id, w := range want {
		var h sql.NullString
		var pt sql.NullInt64
		if err := db.QueryRowContext(ctx, `SELECT ssh_host, ssh_port FROM agents WHERE id=?`, id).Scan(&h, &pt); err != nil {
			t.Fatal(err)
		}
		if h.String != w.host || int(pt.Int64) != w.port {
			t.Errorf("%s: ssh target = %q:%d, want %q:%d", id, h.String, pt.Int64, w.host, w.port)
		}
	}
}

// Миграция 0009: up поверх прод-схемы 0008 сохраняет данные, down возвращает схему.
func TestMigration0009MTProto(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db := rawDB(t, path)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 8); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id,name,url,mode,created_at,updated_at) VALUES ('a1','a1','https://x','dial',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `SELECT 1 FROM mtproto_secrets`); err == nil {
		t.Fatal("mtproto_secrets exists before 0009")
	}
	if _, err := p.UpTo(ctx, 9); err != nil {
		t.Fatal(err)
	}
	var v int64
	if err := db.QueryRowContext(ctx, `SELECT v FROM versions WHERE name='mtproto_secrets'`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("initial version = %d, %v", v, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mtproto_secrets (name,secret_enc,prefix,created_at) VALUES ('s',x'00ff','aabbccdd',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE mtproto_secrets SET max_conns = 3`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT v FROM versions WHERE name='mtproto_secrets'`).Scan(&v); err != nil || v != 3 {
		t.Fatalf("version after insert+update = %d, %v", v, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO mtproto_secrets (name,secret_enc,prefix,created_at) VALUES ('s',x'00','p',1)`); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, err := p.DownTo(ctx, 8); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"mtproto_secrets", "mtproto_sessions"} {
		if _, err := db.ExecContext(ctx, `SELECT 1 FROM `+tbl); err == nil {
			t.Errorf("%s survived down", tbl)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM versions WHERE name='mtproto_secrets'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("version row after down: %d %v", n, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("agents lost: %d %v", n, err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("re-up: %v", err)
	}
}

// Пачка из 10k сессий пишется одной транзакцией быстрее 200 мс.
func TestMTProtoSessionsBatch10k(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "tgproxy.db"))
	ctx := context.Background()
	now := time.Now()
	batch := make([]store.MTProtoSession, 10000)
	for i := range batch {
		batch[i] = store.MTProtoSession{StartedAt: now, EndedAt: now, ClientIP: "203.0.113.1", SecretID: 1, DC: 2, AgentID: "a1", BytesIn: 1, BytesOut: 2, CloseReason: "eof"}
	}
	start := time.Now()
	if err := s.MTProtoSessions().InsertBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 200*time.Millisecond*raceSlowdown {
		t.Fatalf("batch 10k took %v, want < 200ms (x%d under -race)", d, raceSlowdown)
	}
	got, err := s.MTProtoSessions().List(ctx, store.MTProtoSessionQuery{Limit: 20000})
	if err != nil || len(got) != 10000 {
		t.Fatalf("stored %d, err %v", len(got), err)
	}
}
