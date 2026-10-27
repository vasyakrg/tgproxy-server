package upstream

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

type recMetrics struct {
	mu      sync.Mutex
	streams map[string]int
	errs    []string
	bytes   map[string]int
}

func newRecMetrics() *recMetrics {
	return &recMetrics{streams: map[string]int{}, bytes: map[string]int{}}
}

func (m *recMetrics) MTProtoStreams(a string, dc, d int) {
	m.mu.Lock()
	m.streams[a+"/"+string(rune('0'+dc))] += d
	m.mu.Unlock()
}

func (m *recMetrics) MTProtoUpstreamError(a string, dc int, phase string) {
	m.mu.Lock()
	m.errs = append(m.errs, a+"/"+string(rune('0'+dc))+"/"+phase)
	m.mu.Unlock()
}

func (m *recMetrics) MTProtoBytes(a, dir string, n int) {
	m.mu.Lock()
	m.bytes[a+"/"+dir] += n
	m.mu.Unlock()
}

func newMetricNet(t *testing.T, p Picker, s Streams, m Metrics) *Network {
	t.Helper()
	n, err := New(Options{Picker: p, Streams: s, Resolve: resolve, Metrics: m})
	req.NoError(t, err)
	return n
}

func TestMetrics_StreamsAndBytesPerAgent(t *testing.T) {
	m := newRecMetrics()
	client, server := net.Pipe()
	p := &fakePicker{agents: []string{"a"}}
	n := newMetricNet(t, p, &fakeStreams{conn: func() net.Conn { return client }}, m)

	c, err := n.Dial("tcp", dc2Addr)
	req.NoError(t, err)
	req.Equal(t, 1, m.streams["a/2"])

	go func() { _, _ = server.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	_, err = c.Read(buf)
	req.NoError(t, err)
	go func() { _, _ = server.Read(make([]byte, 3)) }()
	_, err = c.Write([]byte("abc"))
	req.NoError(t, err)

	req.NoError(t, c.Close())
	_ = c.Close()
	_ = server.Close()
	req.Equal(t, 0, m.streams["a/2"], "-1 ровно один раз")
	req.Equal(t, 5, m.bytes["a/out"])
	req.Equal(t, 3, m.bytes["a/in"])
}

func TestMetrics_ErrorPhases(t *testing.T) {
	m := newRecMetrics()
	// неизвестный адрес
	n := newMetricNet(t, &fakePicker{agents: []string{"a"}}, &fakeStreams{}, m)
	_, _ = n.Dial("tcp", "1.2.3.4:443")
	// нет кандидатов
	n = newMetricNet(t, &fakePicker{}, &fakeStreams{}, m)
	_, _ = n.Dial("tcp", dc2Addr)
	// агент не резолвится
	n = newMetricNet(t, &fakePicker{agents: []string{"ghost"}}, &fakeStreams{}, m)
	_, _ = n.Dial("tcp", dc2Addr)
	// dial и timeout
	s := &fakeStreams{fail: map[string]error{"a": errors.New("boom")}}
	n = newMetricNet(t, &fakePicker{agents: []string{"a"}}, s, m)
	_, _ = n.Dial("tcp", dc2Addr)
	s.fail["a"] = context.DeadlineExceeded
	n = newMetricNet(t, &fakePicker{agents: []string{"a"}}, s, m)
	_, _ = n.Dial("tcp", dc2Addr)
	// отмена — не ошибка
	s.fail["a"] = context.Canceled
	n = newMetricNet(t, &fakePicker{agents: []string{"a"}}, s, m)
	_, _ = n.Dial("tcp", dc2Addr)

	req.Equal(t, []string{"none/0/unknown_dc", "none/2/no_agent", "ghost/2/no_agent", "a/2/dial", "a/2/timeout"}, m.errs)
	req.Zero(t, m.streams["a/2"])
}
