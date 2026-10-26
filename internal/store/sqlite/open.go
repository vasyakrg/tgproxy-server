// Package sqlite — SQLite-реализация store.Store (modernc.org/sqlite, без CGO).
//
// Два пула соединений: writer (SetMaxOpenConns(1), BEGIN IMMEDIATE) сериализует
// все записи внутри процесса, reader (query_only) обслуживает чтение параллельно
// благодаря WAL. Записи из других процессов (CLI) разруливает busy_timeout.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/pressly/goose/v3"
	msqlite "modernc.org/sqlite"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const (
	dirPerm  = 0o700
	filePerm = 0o600
)

// Store — SQLite-хранилище.
type Store struct {
	w *sql.DB // writer: 1 соединение
	r *sql.DB // reader: query_only

	agents      agentRepo
	accessRules accessRuleRepo
	sessions    sessionRepo
	outbox      outboxRepo
	rateState   rateStateRepo
	history     historyRepo
	audit       auditRepo
	hostKeys    hostKeyRepo
	certs       certRepo
	enrollments enrollmentRepo
	errors      errorRepo
	installJobs installJobRepo
	settings    settingsRepo
	rollouts    rolloutRepo
}

var _ store.Store = (*Store)(nil)

// dsn собирает DSN: pragma из plan §0.1, время в RFC3339Nano (_time_format=sqlite).
func dsn(path string, writer bool) string {
	u := url.URL{Scheme: "file", Path: path}
	pragmas := []string{
		"busy_timeout(5000)",
		"journal_mode(WAL)",
		"synchronous(NORMAL)",
		"foreign_keys(1)",
	}
	if !writer {
		pragmas = append(pragmas, "query_only(1)")
	}
	q := "_time_format=sqlite"
	for _, p := range pragmas {
		q += "&_pragma=" + p
	}
	if writer {
		q += "&_txlock=immediate"
	}
	return u.String() + "?" + q
}

// Open создаёт каталог (0700) и файл БД (0600), открывает пулы и применяет миграции.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("sqlite: empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("sqlite: abs path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), dirPerm); err != nil {
		return nil, fmt.Errorf("sqlite: mkdir: %w", err)
	}
	// Создаём файл заранее с 0600: SQLite копирует права основного файла на -wal/-shm.
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, filePerm) // #nosec G304 -- путь из конфигурации администратора
	if err != nil {
		return nil, fmt.Errorf("sqlite: create db file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("sqlite: close db file: %w", err)
	}

	// DSN частично приходит из конфигурации: запрещаем многооператорные _pragma.
	msqlite.StrictPragmas(true)

	w, err := sql.Open("sqlite", dsn(abs, true))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open writer: %w", err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)

	if err := w.PingContext(ctx); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("sqlite: ping writer: %w", err)
	}
	if err := migrate(ctx, w); err != nil {
		_ = w.Close()
		return nil, err
	}

	r, err := sql.Open("sqlite", dsn(abs, false))
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("sqlite: open reader: %w", err)
	}
	n := max(4, runtime.GOMAXPROCS(0))
	r.SetMaxOpenConns(n)
	r.SetMaxIdleConns(n)
	if err := r.PingContext(ctx); err != nil {
		_ = w.Close()
		_ = r.Close()
		return nil, fmt.Errorf("sqlite: ping reader: %w", err)
	}

	s := &Store{w: w, r: r}
	s.agents = agentRepo{s}
	s.accessRules = accessRuleRepo{s}
	s.sessions = sessionRepo{s}
	s.outbox = outboxRepo{s}
	s.rateState = rateStateRepo{s}
	s.history = historyRepo{s}
	s.audit = auditRepo{s}
	s.hostKeys = hostKeyRepo{s}
	s.certs = certRepo{s}
	s.enrollments = enrollmentRepo{s}
	s.errors = errorRepo{s}
	s.installJobs = installJobRepo{s}
	s.settings = settingsRepo{s}
	s.rollouts = rolloutRepo{s}
	return s, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("sqlite: migrations fs: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		return fmt.Errorf("sqlite: goose provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("sqlite: migrate: %w", err)
	}
	return nil
}

// Close закрывает оба пула.
func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

// Agents — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Agents() store.AgentRepo { return s.agents }

// AccessRules — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) AccessRules() store.AccessRuleRepo { return s.accessRules }

// Sessions — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Sessions() store.SessionRepo { return s.sessions }

// Outbox — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Outbox() store.OutboxRepo { return s.outbox }

// RateState — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) RateState() store.RateStateRepo { return s.rateState }

// History — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) History() store.HistoryRepo { return s.history }

// Audit — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Audit() store.AuditRepo { return s.audit }

// HostKeys — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) HostKeys() store.HostKeyRepo { return s.hostKeys }

// Certs — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Certs() store.CertRepo { return s.certs }

// Enrollments — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Enrollments() store.EnrollmentRepo { return s.enrollments }

// Errors — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Errors() store.ErrorEventRepo { return s.errors }

// InstallJobs — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) InstallJobs() store.InstallJobRepo { return s.installJobs }

// Settings — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Settings() store.SettingsRepo { return s.settings }

// Rollouts — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Rollouts() store.RolloutRepo { return s.rollouts }

// mapErr переводит ошибки драйвера в sentinel-ошибки store.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	var se *msqlite.Error
	if errors.As(err, &se) {
		const (
			constraint = 19
			unique     = 2067
			primaryKey = 1555
			check      = 275
		)
		switch code := se.Code(); {
		case code == unique || code == primaryKey:
			return fmt.Errorf("%w: %s", store.ErrConflict, se.Error())
		case code == check:
			return fmt.Errorf("%w: %s", store.ErrInvalid, se.Error())
		case code&0xff == constraint:
			return fmt.Errorf("%w: %s", store.ErrConflict, se.Error())
		}
	}
	return err
}
