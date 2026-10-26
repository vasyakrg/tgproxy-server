//go:build integration

package redis_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/redis"
	"github.com/vasyakrg/tgproxy-server/internal/store/sqlite"
	"github.com/vasyakrg/tgproxy-server/internal/store/storetest"
)

// Запуск (после `make redis-up`):
//
//	TGP_TEST_REDIS_URL=rediss://tgproxy@127.0.0.1:6380/0 TGP_TEST_REDIS_PASSWORD=<dev-redis-password> \
//	TGP_TEST_REDIS_CA=dev/tls/redis/ca.crt go test -tags integration ./internal/store/redis/...
func TestContract(t *testing.T) {
	url := os.Getenv("TGP_TEST_REDIS_URL")
	if url == "" {
		t.Skip("TGP_TEST_REDIS_URL not set (run `make redis-up`)")
	}
	var pool *x509.CertPool
	if ca := os.Getenv("TGP_TEST_REDIS_CA"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			t.Fatal(err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatal("bad CA pem")
		}
	}
	storetest.Run(t, func(t *testing.T) store.Store {
		ctx := context.Background()
		base, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "tgproxy.db"))
		if err != nil {
			t.Fatal(err)
		}
		var rnd [6]byte
		_, _ = rand.Read(rnd[:])
		eph, err := redis.Open(ctx, redis.Options{
			URL: url, Password: os.Getenv("TGP_TEST_REDIS_PASSWORD"), RootCAs: pool,
			KeyPrefix: "tgproxy:test-" + hex.EncodeToString(rnd[:]) + ":", // ACL: ~tgproxy:*
		})
		if err != nil {
			_ = base.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = eph.FlushPrefix(ctx) })
		s := store.WithEphemeral(base, eph)
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
