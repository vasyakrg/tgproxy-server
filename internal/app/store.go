package app

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/redis"
	"github.com/vasyakrg/tgproxy-server/internal/store/sqlite"
)

// OpenSQLite открывает SQLite из конфигурации сервера (для CLI и тестов).
func OpenSQLite(ctx context.Context, cfg *config.ServerConfig) (store.Store, error) {
	st, err := sqlite.Open(ctx, cfg.Store.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("app: open sqlite: %w", redact.Error(err))
	}
	return st, nil
}

// openStore открывает SQLite и, при driver=redis, подменяет сессии и rate-state
// на Redis. distributed=true — rate-state общий между инстансами.
func openStore(ctx context.Context, cfg *config.ServerConfig) (st store.Store, distributed bool, err error) {
	base, err := OpenSQLite(ctx, cfg)
	if err != nil {
		return nil, false, err
	}
	if cfg.Store.Driver != config.StoreRedis {
		return base, false, nil
	}
	var roots *x509.CertPool
	if cfg.Store.RedisCAFile != "" {
		pem, rerr := os.ReadFile(cfg.Store.RedisCAFile) //nolint:gosec // путь из конфигурации
		if rerr != nil {
			_ = base.Close()
			return nil, false, fmt.Errorf("app: read redis ca: %w", redact.Error(rerr))
		}
		if roots, rerr = pki.PoolFromPEM(pem); rerr != nil {
			_ = base.Close()
			return nil, false, fmt.Errorf("app: redis ca: %w", rerr)
		}
	}
	eph, err := redis.Open(ctx, redis.Options{URL: cfg.Store.RedisURL, Password: cfg.Store.RedisPassword.Reveal(), RootCAs: roots})
	if err != nil {
		_ = base.Close()
		return nil, false, fmt.Errorf("app: open redis: %w", redact.Error(err))
	}
	return store.WithEphemeral(base, eph), true, nil
}
