package memtest_test

import (
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
	"github.com/vasyakrg/tgproxy-server/internal/store/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s := memtest.New()
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
