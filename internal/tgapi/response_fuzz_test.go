package tgapi

import (
	"bytes"
	"errors"
	"testing"
)

func FuzzParseEnvelope(f *testing.F) {
	for _, s := range []string{
		`{"ok":true,"result":{"id":1}}`,
		`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 5","parameters":{"retry_after":5}}`,
		`{"ok":false,"error_code":400,"description":"Bad Request: message is not modified"}`,
		`{"ok":false,"parameters":{"migrate_to_chat_id":-100123}}`,
		`[]`, `null`, `{`, ``,
	} {
		f.Add([]byte(s), int64(1024))
	}
	f.Fuzz(func(t *testing.T, data []byte, limit int64) {
		if limit > 1<<20 {
			limit = 1 << 20
		}
		env, err := ParseEnvelope(bytes.NewReader(data), limit)
		if err != nil {
			if env != nil {
				t.Fatal("non-nil envelope with error")
			}
			return
		}
		if limit >= 0 && int64(len(data)) > limit {
			t.Fatalf("accepted %d bytes over limit %d", len(data), limit)
		}
		if env == nil {
			t.Fatal("nil envelope without error")
		}
		_ = IsNotModified(env)
		_ = IsNotFound(env)
	})
	_ = errors.Is
}
