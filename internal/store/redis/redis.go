// Package redis — опциональный Redis-бэкенд эфемерных данных (architecture §7):
// только Sessions() и RateState(). Остальное хранилище остаётся в SQLite;
// композиция — store.WithEphemeral(sqliteStore, ephemeral).
//
// Старт запрещён, если URL не rediss:// (TLS обязателен) или не задан ACL-пользователь с паролем.
package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// DefaultKeyPrefix — префикс ключей; ACL-пользователь ограничивается `~tgproxy:*`.
const DefaultKeyPrefix = "tgproxy:"

// Options — параметры подключения.
type Options struct {
	URL       string         // rediss://user[:password]@host:port/db
	Password  string         // из store.redis_password_file; приоритетнее пароля в URL
	RootCAs   *x509.CertPool // nil — системные корни
	KeyPrefix string         // пусто → DefaultKeyPrefix
}

// ErrInsecure — конфигурация не удовлетворяет требованиям безопасности (§7, §8).
var ErrInsecure = errors.New("redis: insecure configuration")

// ParseOptions проверяет требования безопасности и строит опции go-redis.
func ParseOptions(o Options) (*goredis.Options, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Scheme != "rediss" || u.Host == "" {
		return nil, fmt.Errorf("%w: url must be rediss://user:password@host:port/db", ErrInsecure)
	}
	user := u.User.Username()
	if user == "" || strings.EqualFold(user, "default") {
		return nil, fmt.Errorf("%w: a dedicated ACL user is required (not %q)", ErrInsecure, user)
	}
	opt, err := goredis.ParseURL(o.URL)
	if err != nil {
		return nil, fmt.Errorf("redis: parse url: %w", err)
	}
	if o.Password != "" {
		opt.Password = o.Password
	}
	if opt.Password == "" {
		return nil, fmt.Errorf("%w: ACL user needs a password", ErrInsecure)
	}
	if opt.TLSConfig == nil { // ParseURL создаёт его для rediss, но не полагаемся на это
		opt.TLSConfig = &tls.Config{ServerName: u.Hostname()}
	}
	opt.TLSConfig.MinVersion = tls.VersionTLS13
	opt.TLSConfig.InsecureSkipVerify = false
	if o.RootCAs != nil {
		opt.TLSConfig.RootCAs = o.RootCAs
	}
	return opt, nil
}

// Ephemeral — Redis-реализация store.Ephemeral.
type Ephemeral struct {
	rdb    *goredis.Client
	prefix string
	sess   sessionRepo
	rate   rateRepo
}

var _ store.Ephemeral = (*Ephemeral)(nil)

// Open подключается и проверяет доступность (PING).
func Open(ctx context.Context, o Options) (*Ephemeral, error) {
	opt, err := ParseOptions(o)
	if err != nil {
		return nil, err
	}
	rdb := goredis.NewClient(opt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	prefix := o.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	e := &Ephemeral{rdb: rdb, prefix: prefix}
	e.sess = sessionRepo{e}
	e.rate = rateRepo{e}
	return e, nil
}

// Sessions — доступ к репозиторию/ресурсу хранилища (store.Ephemeral).
func (e *Ephemeral) Sessions() store.SessionRepo { return e.sess }

// RateState — доступ к репозиторию/ресурсу хранилища (store.Ephemeral).
func (e *Ephemeral) RateState() store.RateStateRepo { return e.rate }

// Close закрывает клиент.
func (e *Ephemeral) Close() error { return e.rdb.Close() }

// FlushPrefix удаляет все ключи под префиксом (для тестов). SCAN+DEL, без KEYS/FLUSHALL.
func (e *Ephemeral) FlushPrefix(ctx context.Context) error {
	iter := e.rdb.Scan(ctx, 0, e.prefix+"*", 200).Iterator()
	for iter.Next(ctx) {
		if err := e.rdb.Del(ctx, iter.Val()).Err(); err != nil {
			return err
		}
	}
	return iter.Err()
}
