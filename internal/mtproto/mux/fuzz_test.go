package mux

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/mtproto/faketls"
)

// FuzzFirstRecord — путь первой записи в Listener.handle на произвольных байтах:
// ReadFirstRecord → Parse → Match без паник; прочитанное — префикс входа и
// побайтно воспроизводится replayConn (для fallthrough).
func FuzzFirstRecord(f *testing.F) {
	key := [16]byte{1, 2, 3}
	now := time.Unix(1_700_000_000, 0)
	f.Add(helloFor(key, testDomain, now))
	f.Add(helloFor(key, "other.example", now))
	f.Add([]byte{0x16, 3, 1, 0xff, 0xff})
	f.Add([]byte{0x16, 3, 1, 0, 0})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{})
	keys := [][16]byte{key, {9}}
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := faketls.ReadFirstRecord(bytes.NewReader(data), faketls.MaxRecord)
		if len(rec) > len(data) || !bytes.HasPrefix(data, rec) {
			t.Fatalf("прочитанное не префикс входа: rec=%d data=%d", len(rec), len(data))
		}
		rc := newReplayConn(nil, rec)
		got := make([]byte, len(rec))
		if _, rerr := io.ReadFull(rc, got); rerr != nil || !bytes.Equal(got, rec) {
			t.Fatal("replayConn исказил префикс")
		}
		if err != nil {
			return
		}
		if h, perr := faketls.Parse(rec); perr == nil {
			faketls.Match(h, keys, testDomain, now, 2*time.Minute)
		}
	})
}
