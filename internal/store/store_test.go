package store_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

func TestValidate(t *testing.T) {
	h := make([]byte, store.HashLen)
	net := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	bad := []error{
		store.AccessRule{Name: "x"}.Validate(),
		store.AccessRule{Name: "", CIDRs: net}.Validate(),
		store.AccessRule{Name: "x", KeyHash: []byte{1}}.Validate(),
		store.AccessRule{Name: "x", CIDRs: []netip.Prefix{{}}}.Validate(),
		store.AccessRule{Name: "x", CIDRs: net, RPS: -1}.Validate(),
		store.Agent{}.Validate(),
		store.Agent{ID: "a", Name: "n", Mode: store.ModeDial}.Validate(),
		store.Agent{ID: "a", Name: "n", Mode: "x"}.Validate(),
		store.Agent{ID: "a", Name: "n", Mode: store.ModeReverse, Weight: -1}.Validate(),
		store.Session{}.Validate(),
		store.Session{ID: "i", User: "u", Kind: "x"}.Validate(),
		store.ErrorEvent{}.Validate(),
		store.OutboxItem{}.Validate(),
		store.OutboxItem{DedupKey: "k", Type: "t", State: "x"}.Validate(),
		store.Enrollment{}.Validate(),
	}
	for i, err := range bad {
		if !errors.Is(err, store.ErrInvalid) {
			t.Errorf("case %d: err = %v, want ErrInvalid", i, err)
		}
	}
	good := []error{
		store.AccessRule{Name: "x", CIDRs: net}.Validate(),
		store.AccessRule{Name: "x", KeyHash: h}.Validate(),
		store.Agent{ID: "a", Name: "n", Mode: store.ModeReverse}.Validate(),
		store.Session{ID: "i", User: "u", Kind: "pending"}.Validate(),
		store.ErrorEvent{Outcome: store.OutcomeRetried}.Validate(),
		store.Enrollment{ID: "e", TokenHash: h, Name: "n"}.Validate(),
	}
	for i, err := range good {
		if err != nil {
			t.Errorf("good case %d: %v", i, err)
		}
	}
}

type eph struct {
	store.Store
	closed bool
}

func (e *eph) Close() error { e.closed = true; return nil }

func TestWithEphemeral(t *testing.T) {
	base, other := memtest.New(), &eph{Store: memtest.New()}
	s := store.WithEphemeral(base, other)
	if s.Sessions() == base.Sessions() || s.RateState() == base.RateState() {
		t.Fatal("sessions/ratestate must come from ephemeral backend")
	}
	if s.Agents() == nil {
		t.Fatal("agents must come from base")
	}
	if err := s.Close(); err != nil || !other.closed {
		t.Fatalf("close: %v closed=%v", err, other.closed)
	}
}
