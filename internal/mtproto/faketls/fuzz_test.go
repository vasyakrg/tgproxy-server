package faketls

import (
	"bytes"
	"testing"
	"time"
)

func FuzzParseClientHello(f *testing.F) {
	for _, names := range [][]string{{dom}, {"a", dom}, nil} {
		f.Add(buildHello(genOpts{key: k0[:], sni: names, timestamp: now, sessionID: sid()}))
	}
	f.Add([]byte{0x16, 3, 1, 0, 0})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{})
	keys := [][16]byte{k0, k1}
	f.Fuzz(func(t *testing.T, data []byte) {
		// ReadFirstRecord не паникует и не читает больше max.
		if rec, err := ReadFirstRecord(bytes.NewReader(data), MaxRecord); err == nil && len(rec) > recordHeaderLen+MaxRecord {
			t.Fatalf("запись %d больше лимита", len(rec))
		}
		h, err := Parse(data)
		if err != nil {
			return
		}
		if len(h.Raw) != len(data) || len(h.SessionID) > 255 {
			t.Fatalf("несогласованный Hello: raw=%d sid=%d", len(h.Raw), len(h.SessionID))
		}
		Match(h, keys, dom, time.Unix(0, 0), time.Minute) // не паникует
	})
}
