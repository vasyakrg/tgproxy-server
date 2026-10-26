package redis_test

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/store/redis"
)

func TestParseOptionsRejectsInsecure(t *testing.T) {
	cases := map[string]redis.Options{
		"plain redis://":     {URL: "redis://tgproxy:pw@localhost:6380/0"},
		"no scheme":          {URL: "localhost:6380"},
		"no host":            {URL: "rediss://tgproxy:pw@"},
		"no user":            {URL: "rediss://localhost:6380/0", Password: "pw"},
		"password only":      {URL: "rediss://:pw@localhost:6380/0"},
		"default user":       {URL: "rediss://default:pw@localhost:6380/0"},
		"default user upper": {URL: "rediss://DEFAULT:pw@localhost:6380/0"},
		"no password":        {URL: "rediss://tgproxy@localhost:6380/0"},
		"garbage":            {URL: "://"},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := redis.ParseOptions(o); err == nil {
				t.Fatal("must be rejected")
			}
		})
	}
	if _, err := redis.ParseOptions(redis.Options{URL: "redis://u:p@h:1"}); !errors.Is(err, redis.ErrInsecure) {
		t.Fatalf("err = %v, want ErrInsecure", err)
	}
}

func TestParseOptionsAccepts(t *testing.T) {
	opt, err := redis.ParseOptions(redis.Options{URL: "rediss://tgproxy@redis.internal:6380/2", Password: "from-file"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Username != "tgproxy" || opt.Password != "from-file" || opt.DB != 2 || opt.Addr != "redis.internal:6380" {
		t.Fatalf("opts: %+v", opt)
	}
	if opt.TLSConfig == nil || opt.TLSConfig.MinVersion != tls.VersionTLS13 || opt.TLSConfig.InsecureSkipVerify {
		t.Fatalf("tls: %+v", opt.TLSConfig)
	}
	if opt.TLSConfig.ServerName != "redis.internal" {
		t.Fatalf("server name %q", opt.TLSConfig.ServerName)
	}
	// пароль в URL тоже допустим
	if _, err := redis.ParseOptions(redis.Options{URL: "rediss://tgproxy:pw@h:6380"}); err != nil {
		t.Fatal(err)
	}
}
