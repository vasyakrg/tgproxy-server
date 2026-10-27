package agent

import (
	"bytes"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"testing"
)

type fakeMTRec struct {
	noopRecorder
	mu      sync.Mutex
	streams map[int]int
	peak    int
	dialErr map[string]int
	bytes   map[string]int
}

func newFakeMTRec() *fakeMTRec {
	return &fakeMTRec{streams: map[int]int{}, dialErr: map[string]int{}, bytes: map[string]int{}}
}

func (r *fakeMTRec) MTProtoStreams(dc, d int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streams[dc] += d
	r.peak = max(r.peak, r.streams[dc])
}

func (r *fakeMTRec) MTProtoDialError(dc int, kind string) {
	r.mu.Lock()
	r.dialErr[kind]++
	r.mu.Unlock()
	_ = dc
}

func (r *fakeMTRec) MTProtoBytes(dir string, n int) {
	r.mu.Lock()
	r.bytes[dir] += n
	r.mu.Unlock()
}

func (r *fakeMTRec) get() (streams, peak, in, out int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streams[2], r.peak, r.bytes["in"], r.bytes["out"]
}

func TestMTProtoRecorderStreamsAndBytes(t *testing.T) {
	dc := newFakeDC(t, echoDC)
	e := newMTEnv(t, dc.addr)
	rec := newFakeMTRec()
	e.agent.rec = rec

	s, code := openStream(t, e, "/_agent/mtproto/dc/2", nil)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	payload := bytes.Repeat([]byte{7}, 4096)
	go func() { _, _ = s.Write(payload); s.CloseWrite() }()
	if got, err := io.ReadAll(s.resp.Body); err != nil || len(got) != len(payload) {
		t.Fatalf("echo: %d bytes, err=%v", len(got), err)
	}
	waitStreams(t, e.agent, 0)
	cur, peak, in, out := rec.get()
	if cur != 0 || peak != 1 {
		t.Fatalf("streams cur=%d peak=%d, want 0/1", cur, peak)
	}
	if in != len(payload) || out != len(payload) {
		t.Fatalf("bytes in=%d out=%d, want %d", in, out, len(payload))
	}
}

func TestMTProtoRecorderDialError(t *testing.T) {
	e := newMTEnv(t, netip.MustParseAddrPort(closedAddr(t)))
	rec := newFakeMTRec()
	e.agent.rec = rec
	resp := e.do(t, http.MethodPost, "/_agent/mtproto/dc/2", nil, nil)
	_ = resp.Body.Close()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.dialErr[DialRefused] != 1 {
		t.Fatalf("dialErr = %v, want refused=1", rec.dialErr)
	}
	if rec.streams[2] != 0 {
		t.Fatalf("streams = %d", rec.streams[2])
	}
}
