package mtproto

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type fakeSessRepo struct {
	mu      sync.Mutex
	batches [][]store.MTProtoSession
	fail    atomic.Bool
	pruned  []time.Time
	block   chan struct{}
}

func (f *fakeSessRepo) InsertBatch(_ context.Context, b []store.MTProtoSession) error {
	if f.block != nil {
		<-f.block
	}
	if f.fail.Load() {
		return errors.New("db down")
	}
	f.mu.Lock()
	f.batches = append(f.batches, b)
	f.mu.Unlock()
	return nil
}

func (f *fakeSessRepo) List(context.Context, store.MTProtoSessionQuery) ([]store.MTProtoSession, error) {
	return nil, nil
}

func (f *fakeSessRepo) Prune(_ context.Context, before time.Time) (int, error) {
	f.mu.Lock()
	f.pruned = append(f.pruned, before)
	f.mu.Unlock()
	return 0, nil
}

func (f *fakeSessRepo) total() (n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func TestJournalSessionFields(t *testing.T) {
	repo := &fakeSessRepo{}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	j := NewJournal(repo, nil)
	j.Now = func() time.Time { return now }
	j.Start(7, "s1", netip.MustParseAddr("1.2.3.4"))
	j.ConnectedToDC(7, "s1", 4)
	j.Traffic(7, "s1", 100, false)
	j.Traffic(7, "s1", 250, true)
	if j.ActiveConns() != 1 {
		t.Fatalf("active=%d", j.ActiveConns())
	}
	now = now.Add(3 * time.Second)
	j.Finish(7, "s1", "upstream_eof", "kz1")
	j.Finish(7, "s1", "client_eof", "") // повторный Finish безвреден
	if j.ActiveConns() != 0 {
		t.Fatalf("active=%d", j.ActiveConns())
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	got := repo.batches[0][0]
	want := store.MTProtoSession{
		StartedAt: now.Add(-3 * time.Second), EndedAt: now, ClientIP: "1.2.3.4",
		SecretID: 7, DC: 4, AgentID: "kz1", BytesIn: 100, BytesOut: 250, CloseReason: "upstream_eof",
	}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if in, out := j.TotalBytes(); in != 100 || out != 250 {
		t.Fatalf("totals %d/%d", in, out)
	}
}

func TestJournal10kOneBatch(t *testing.T) {
	repo := &fakeSessRepo{}
	j := NewJournal(repo, nil)
	for i := range 10_000 {
		id := fmt.Sprint(i)
		j.Start(1, id, netip.MustParseAddr("10.0.0.1"))
		j.Finish(1, id, "", "")
	}
	if err := j.FlushNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(repo.batches) != 1 || len(repo.batches[0]) != 10_000 {
		t.Fatalf("batches=%d", len(repo.batches))
	}
}

func TestJournalOverflowDoesNotBlock(t *testing.T) {
	repo := &fakeSessRepo{block: make(chan struct{})} // запись зависла
	j := NewJournal(repo, nil)
	j.QueueCap = 10
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 100 {
			id := fmt.Sprint(i)
			j.Start(1, id, netip.Addr{})
			j.Finish(1, id, "", "")
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Finish заблокирован")
	}
	if j.Pending() != 10 || j.Dropped() != 90 {
		t.Fatalf("pending=%d dropped=%d", j.Pending(), j.Dropped())
	}
	close(repo.block)
}

func TestJournalFailedFlushRequeues(t *testing.T) {
	repo := &fakeSessRepo{}
	repo.fail.Store(true)
	j := NewJournal(repo, nil)
	j.QueueCap = 3
	for i := range 3 {
		id := fmt.Sprint(i)
		j.Start(1, id, netip.Addr{})
		j.Finish(1, id, "", "")
	}
	if err := j.FlushNow(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if j.Pending() != 3 || j.Dropped() != 0 {
		t.Fatalf("pending=%d dropped=%d", j.Pending(), j.Dropped())
	}
	repo.fail.Store(false)
	if err := j.FlushNow(context.Background()); err != nil || repo.total() != 3 {
		t.Fatalf("err=%v total=%d", err, repo.total())
	}
}

func TestJournalRunFlushesPeriodicallyAndOnStop(t *testing.T) {
	repo := &fakeSessRepo{}
	j := NewJournal(repo, nil)
	j.Flush = 10 * time.Millisecond
	j.PruneEvery = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { j.Run(ctx); close(done) }()

	j.Start(1, "a", netip.Addr{})
	j.Finish(1, "a", "", "")
	deadline := time.Now().Add(2 * time.Second)
	for repo.total() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if repo.total() != 1 {
		t.Fatal("периодический сброс не сработал")
	}
	j.Start(1, "b", netip.Addr{})
	j.Finish(1, "b", "", "")
	cancel()
	<-done
	if repo.total() != 2 {
		t.Fatalf("финальный сброс: total=%d", repo.total())
	}
	repo.mu.Lock()
	np := len(repo.pruned)
	repo.mu.Unlock()
	if np == 0 {
		t.Fatal("prune не вызывался")
	}
}

func TestJournalPruneRetention(t *testing.T) {
	repo := &fakeSessRepo{}
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	j := NewJournal(repo, nil)
	j.Now = func() time.Time { return now }
	if _, err := j.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(-DefaultJournalMaxAge); !repo.pruned[0].Equal(want) {
		t.Fatalf("prune before=%v want %v", repo.pruned[0], want)
	}
	j.MaxAge = time.Hour
	_, _ = j.Prune(context.Background())
	if !repo.pruned[1].Equal(now.Add(-time.Hour)) {
		t.Fatalf("custom age: %v", repo.pruned[1])
	}
}

func TestJournalConcurrentRace(t *testing.T) {
	repo := &fakeSessRepo{}
	j := NewJournal(repo, nil)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				id := fmt.Sprintf("%d-%d", w, i)
				j.Start(int64(w), id, netip.Addr{})
				j.ConnectedToDC(int64(w), id, 2)
				j.Traffic(int64(w), id, 10, i%2 == 0)
				_ = j.FlushNow(context.Background())
				j.Finish(int64(w), id, "", "")
			}
		}()
	}
	wg.Wait()
	_ = j.Close()
	if repo.total()+int(j.Dropped()) != 4000 || j.ActiveConns() != 0 {
		t.Fatalf("total=%d dropped=%d active=%d", repo.total(), j.Dropped(), j.ActiveConns())
	}
}
