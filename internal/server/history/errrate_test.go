package history

import (
	"context"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/sqlite"
)

func TestAgentErrorRate(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(ctx, t.TempDir()+"/h.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Unix(1_700_000_000, 0).UTC()
	err = st.History().Append(ctx, store.Res10s, []store.Sample{
		{At: now.Add(-30 * time.Second), AgentID: "a1", OK: 90, Err: 10},
		{At: now.Add(-20 * time.Second), AgentID: "a1", OK: 90, Err: 10, RateLimited: 50},
		{At: now.Add(-10 * time.Second), AgentID: "a2", OK: 10, Err: 0},
		{At: now.Add(-time.Hour), AgentID: "a1", Err: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := &Query{History: st.History(), Now: func() time.Time { return now }}
	if r, n := q.AgentErrorRate("a1", 5*time.Minute); n != 200 || r != 0.1 {
		t.Fatalf("a1: rate=%v n=%d", r, n)
	}
	if r, n := q.AgentErrorRate("a2", 5*time.Minute); n != 10 || r != 0 {
		t.Fatalf("a2: rate=%v n=%d", r, n)
	}
	if r, n := q.AgentErrorRate("zz", 5*time.Minute); n != 0 || r != 0 {
		t.Fatalf("zz: rate=%v n=%d", r, n)
	}
}
