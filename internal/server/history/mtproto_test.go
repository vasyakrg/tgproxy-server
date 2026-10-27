package history_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type fakeMT struct{ conns, in, out atomic.Int64 }

func (f *fakeMT) ActiveConns() int64         { return f.conns.Load() }
func (f *fakeMT) TotalBytes() (int64, int64) { return f.in.Load(), f.out.Load() }

func aggregate(t *testing.T, ss []store.Sample) store.Sample {
	t.Helper()
	for _, s := range ss {
		if s.AgentID == history.AggregateID {
			return s
		}
	}
	t.Fatal("нет агрегата")
	return store.Sample{}
}

func TestMTProtoSeriesDrain(t *testing.T) {
	c := history.NewCollector()
	if a := aggregate(t, c.Drain()); a.MTConns != 0 || a.MTBytesIn != 0 {
		t.Fatalf("без источника ряды нулевые: %+v", a)
	}
	src := &fakeMT{}
	src.in.Store(1000) // до подключения
	c.SetMTProto(src)
	src.conns.Store(5)
	src.in.Store(1500)
	src.out.Store(700)
	a := aggregate(t, c.Drain())
	if a.MTConns != 5 || a.MTBytesIn != 500 || a.MTBytesOut != 700 {
		t.Fatalf("первое окно: %+v", a)
	}
	src.conns.Store(2)
	src.in.Store(1600)
	a = aggregate(t, c.Drain())
	if a.MTConns != 5 || a.MTBytesIn != 100 || a.MTBytesOut != 0 {
		t.Fatalf("пик из прошлого снимка должен сохраниться: %+v", a)
	}
	a = aggregate(t, c.Drain())
	if a.MTConns != 2 || a.MTBytesIn != 0 {
		t.Fatalf("третье окно: %+v", a)
	}
}

func TestMTProtoSeriesRollup10sTo5m(t *testing.T) {
	st := memtest.New()
	ctx := context.Background()
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	var in []store.Sample
	for i, conns := range []int64{3, 9, 4} {
		in = append(in, store.Sample{
			At: base.Add(time.Duration(i) * history.Step10s), AgentID: history.AggregateID,
			MTConns: conns, MTBytesIn: 100, MTBytesOut: 10,
		})
	}
	if err := st.History().Append(ctx, store.Res10s, in); err != nil {
		t.Fatal(err)
	}
	r := history.NewRoller(st.History())
	if err := r.Step(ctx, base.Add(history.Step5m+time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := st.History().Range(ctx, store.Res5m, history.AggregateID, base, base.Add(history.Step5m))
	if err != nil || len(got) != 1 {
		t.Fatalf("err=%v got=%d", err, len(got))
	}
	if got[0].MTConns != 9 || got[0].MTBytesIn != 300 || got[0].MTBytesOut != 30 {
		t.Fatalf("rollup: %+v", got[0])
	}
}

func TestMTProtoSeriesSamplerPersists(t *testing.T) {
	st := memtest.New()
	c := history.NewCollector()
	src := &fakeMT{}
	c.SetMTProto(src)
	src.conns.Store(4)
	src.in.Store(42)
	s := &history.Sampler{Collector: c, Repo: st.History()}
	now := time.Date(2026, 3, 1, 12, 0, 10, 0, time.UTC)
	if err := s.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	got, _ := st.History().Range(context.Background(), store.Res10s, history.AggregateID, now.Add(-time.Minute), now)
	if len(got) != 1 || got[0].MTConns != 4 || got[0].MTBytesIn != 42 {
		t.Fatalf("%+v", got)
	}
}
