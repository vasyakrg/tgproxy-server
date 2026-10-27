package mtproto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/mtglib"
)

const (
	testFrontHost  = "front.example.test"
	testClientAddr = "203.0.113.7:54321"
	testTimeout    = 5 * time.Second
)

// --- conn с подменой RemoteAddr -------------------------------------------

// addrConn подменяет RemoteAddr: реальный сокет — loopback, а mtg должен
// видеть «клиентский» *net.TCPAddr (так же поступит наш replayConn).
type addrConn struct {
	essentials.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// --- Network ---------------------------------------------------------------

type dialRecord struct{ Network, Address string }

type httpBanTransport struct{ t *testing.T }

func (b httpBanTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b.t.Errorf("mtg выполнил HTTP-запрос %s (AutoUpdate/doppelganger должны быть выключены)", r.URL)
	return nil, errors.New("http banned")
}

// fakeNetwork — mtglib.Network: Dial к DC уходит на локальный fake-DC,
// NativeDialer (domain fronting) — обычный net.Dialer.
type fakeNetwork struct {
	t      *testing.T
	dcAddr string

	mu        sync.Mutex
	dials     []dialRecord
	failFirst int // первые N Dial возвращают ошибку
	failAll   bool

	dialCtxCalls     atomic.Int32
	httpClientCalls  atomic.Int32
	nativeDialerCall atomic.Int32
}

func (n *fakeNetwork) Dial(network, address string) (essentials.Conn, error) {
	return n.dial(context.Background(), network, address)
}

func (n *fakeNetwork) dial(ctx context.Context, network, address string) (essentials.Conn, error) {
	n.mu.Lock()
	n.dials = append(n.dials, dialRecord{network, address})
	fail := n.failAll || len(n.dials) <= n.failFirst
	n.mu.Unlock()
	if fail {
		return nil, errors.New("fake dial error")
	}
	c, err := (&net.Dialer{Timeout: testTimeout}).DialContext(ctx, "tcp", n.dcAddr)
	if err != nil {
		return nil, err
	}
	return essentials.WrapNetConn(c), nil
}

func (n *fakeNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
	n.dialCtxCalls.Add(1)
	return n.dial(ctx, network, address)
}

func (n *fakeNetwork) MakeHTTPClient(func(ctx context.Context, network, address string) (essentials.Conn, error)) *http.Client {
	n.httpClientCalls.Add(1)
	return &http.Client{Transport: httpBanTransport{n.t}}
}

func (n *fakeNetwork) NativeDialer() *net.Dialer {
	n.nativeDialerCall.Add(1)
	return &net.Dialer{Timeout: testTimeout}
}

func (n *fakeNetwork) dialLog() []dialRecord {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.dials)
}

// --- журнал событий --------------------------------------------------------

type eventLog struct {
	mu  sync.Mutex
	evs []mtglib.Event
}

func (e *eventLog) Send(_ context.Context, ev mtglib.Event) {
	e.mu.Lock()
	e.evs = append(e.evs, ev)
	e.mu.Unlock()
}

func (e *eventLog) snapshot() []mtglib.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.evs)
}

func (e *eventLog) waitFor(t *testing.T, what string, cond func([]mtglib.Event) bool) []mtglib.Event {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		evs := e.snapshot()
		if cond(evs) {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("не дождались событий: %s; есть: %s", what, describeEvents(evs))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func describeEvents(evs []mtglib.Event) string {
	var parts []string
	for _, ev := range evs {
		parts = append(parts, fmt.Sprintf("%T", ev))
	}
	return strings.Join(parts, ",")
}

func hasEvent[T mtglib.Event](evs []mtglib.Event) bool {
	for _, ev := range evs {
		if _, ok := ev.(T); ok {
			return true
		}
	}
	return false
}

func findEvent[T mtglib.Event](evs []mtglib.Event) (T, bool) {
	for _, ev := range evs {
		if v, ok := ev.(T); ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}

// --- логгер ----------------------------------------------------------------

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *logSink) add(line string) {
	s.mu.Lock()
	s.lines = append(s.lines, line)
	s.mu.Unlock()
}

func (s *logSink) all() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

type testLogger struct {
	sink  *logSink
	name  string
	bound string
}

func (l testLogger) with(k, v string) testLogger {
	l.bound += " " + k + "=" + v
	return l
}

func (l testLogger) emit(level, msg string, err error) {
	line := level + " " + l.name + " " + msg + l.bound
	if err != nil {
		line += " err=" + err.Error()
	}
	l.sink.add(line)
}

func (l testLogger) Named(name string) mtglib.Logger { l.name += "/" + name; return l }
func (l testLogger) BindInt(n string, v int) mtglib.Logger {
	return l.with(n, fmt.Sprint(v))
}
func (l testLogger) BindStr(n, v string) mtglib.Logger  { return l.with(n, v) }
func (l testLogger) BindJSON(n, v string) mtglib.Logger { return l.with(n, v) }
func (l testLogger) Printf(f string, a ...any)          { l.emit("P", fmt.Sprintf(f, a...), nil) }
func (l testLogger) Info(m string)                      { l.emit("I", m, nil) }
func (l testLogger) InfoError(m string, e error)        { l.emit("I", m, e) }
func (l testLogger) Warning(m string)                   { l.emit("W", m, nil) }
func (l testLogger) WarningError(m string, e error)     { l.emit("W", m, e) }
func (l testLogger) Debug(m string)                     { l.emit("D", m, nil) }
func (l testLogger) DebugError(m string, e error)       { l.emit("D", m, e) }

// --- anti-replay и blocklist -----------------------------------------------

type countingCache struct {
	inner mtglib.AntiReplayCache

	mu    sync.Mutex
	calls [][]byte
}

func (c *countingCache) SeenBefore(data []byte) bool {
	c.mu.Lock()
	c.calls = append(c.calls, bytes.Clone(data))
	c.mu.Unlock()
	return c.inner.SeenBefore(data)
}

func (c *countingCache) callList() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// blockAll — blocklist, который «банит» всех: ServeConn обязан его игнорировать.
type blockAll struct{}

func (blockAll) Contains(net.IP) bool { return true }
func (blockAll) Run(time.Duration)    {}
func (blockAll) Shutdown()            {}

// --- fake-DC ---------------------------------------------------------------

// dcConn — одно принятое fake-DC соединение (obfuscated2-сервер без секрета, эхо).
type dcConn struct {
	dc     int // номер DC из handshake (после abs() у mtg)
	closed chan struct{}

	mu       sync.Mutex
	received []byte
}

type fakeDC struct {
	ln       net.Listener
	accepted chan *dcConn
}

func newFakeDC(t *testing.T) *fakeDC {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDC{ln: ln, accepted: make(chan *dcConn, 64)}
	go d.loop()
	t.Cleanup(func() { _ = ln.Close() })
	return d
}

func (d *fakeDC) loop() {
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		go d.handle(c)
	}
}

func (d *fakeDC) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	var frame [64]byte
	c.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	if _, err := io.ReadFull(c, frame[:]); err != nil {
		return
	}
	c.SetReadDeadline(time.Time{}) //nolint:errcheck

	// Сервер Telegram: ключ/IV читаются из открытых байт 8..56 (секрета нет).
	recv := newCTR(frame[8:40], frame[40:56])
	var dec [64]byte
	recv.XORKeyStream(dec[:], frame[:])
	if !bytes.Equal(dec[56:60], []byte{0xdd, 0xdd, 0xdd, 0xdd}) {
		return
	}
	rev := slices.Clone(frame[8:56])
	slices.Reverse(rev)
	send := newCTR(rev[0:32], rev[32:48])

	dc := &dcConn{
		dc:     int(int16(binary.LittleEndian.Uint16(dec[60:62]))),
		closed: make(chan struct{}),
	}
	defer close(dc.closed)
	d.accepted <- dc

	buf := make([]byte, 32*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			recv.XORKeyStream(buf[:n], buf[:n])
			dc.mu.Lock()
			dc.received = append(dc.received, buf[:n]...)
			dc.mu.Unlock()
			out := make([]byte, n)
			send.XORKeyStream(out, buf[:n])
			if _, werr := c.Write(out); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (d *fakeDC) waitConn(t *testing.T) *dcConn {
	t.Helper()
	select {
	case c := <-d.accepted:
		return c
	case <-time.After(testTimeout):
		t.Fatal("fake-DC не получил соединение")
		return nil
	}
}

func newCTR(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCTR(block, iv)
}

// --- FakeTLS-клиент (минимальный; позже заменяется probe из M10-T6) --------

type helloOpts struct {
	key       []byte
	sni       string
	timestamp time.Time
	sessionID []byte
}

func be16(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }

// buildClientHello собирает одну TLS-запись ClientHello с FakeTLS-HMAC:
// random = HMAC-SHA256(key, запись с нулевым random), последние 4 байта XOR LE-timestamp.
func buildClientHello(o helloOpts) []byte {
	name := []byte(o.sni)
	entry := append([]byte{0}, be16(len(name))...)
	entry = append(entry, name...)
	list := append(be16(len(entry)), entry...)
	ext := append(append(be16(0), be16(len(list))...), list...)
	exts := append(be16(len(ext)), ext...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...) // random — позже
	body = append(body, byte(len(o.sessionID)))
	body = append(body, o.sessionID...)
	body = append(body, be16(4)...)
	body = append(body, 0x0a, 0x0a, 0x13, 0x01) // GREASE + TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, be16(len(hs))...)
	rec = append(rec, hs...)

	const randomOffset = 11
	mac := hmac.New(sha256.New, o.key)
	mac.Write(rec)
	random := mac.Sum(nil)
	ts := binary.LittleEndian.AppendUint32(nil, uint32(o.timestamp.Unix()))
	for i := 0; i < 4; i++ {
		random[28+i] ^= ts[i]
	}
	copy(rec[randomOffset:], random)
	return rec
}

func randomSessionID() []byte {
	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		panic(err)
	}
	return sid
}

func readTLSRecord(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	_, err := io.ReadFull(r, body)
	return hdr[0], body, err
}

// clientSession — клиент после FakeTLS ServerHello: obfuscated2 внутри
// записей ApplicationData.
type clientSession struct {
	conn    *net.TCPConn
	br      *bufio.Reader
	send    cipher.Stream
	recv    cipher.Stream
	pending []byte
}

func (s *clientSession) write(p []byte) error {
	enc := make([]byte, len(p))
	s.send.XORKeyStream(enc, p)
	rec := append([]byte{0x17, 0x03, 0x03}, be16(len(enc))...)
	_, err := s.conn.Write(append(rec, enc...))
	return err
}

func (s *clientSession) readN(n int) ([]byte, error) {
	for len(s.pending) < n {
		typ, body, err := readTLSRecord(s.br)
		if err != nil {
			return nil, err
		}
		if typ != 0x17 {
			continue
		}
		dec := make([]byte, len(body))
		s.recv.XORKeyStream(dec, body)
		s.pending = append(s.pending, dec...)
	}
	out := s.pending[:n:n]
	s.pending = s.pending[n:]
	return out, nil
}

// roundtrip пишет payload и ждёт эхо от fake-DC.
func (s *clientSession) roundtrip(t *testing.T, payload []byte) {
	t.Helper()
	if err := s.write(payload); err != nil {
		t.Fatalf("запись клиента: %v", err)
	}
	got, err := s.readN(len(payload))
	if err != nil {
		t.Fatalf("чтение эха: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("эхо не совпало")
	}
}

// obfuscatedHandshake строит 64-байтный кадр клиента: DC в int16 LE (со знаком),
// шифры ключаются sha256(key||secret).
func obfuscatedHandshake(secretKey []byte, dc int) (wire []byte, send, recv cipher.Stream) {
	var frame [64]byte
	for {
		if _, err := rand.Read(frame[:]); err != nil {
			panic(err)
		}
		if frame[0] != 0xef {
			break
		}
	}
	copy(frame[56:60], []byte{0xdd, 0xdd, 0xdd, 0xdd})
	binary.LittleEndian.PutUint16(frame[60:62], uint16(int16(dc)))

	keyed := func(f []byte) cipher.Stream {
		h := sha256.New()
		h.Write(f[8:40])
		h.Write(secretKey)
		return newCTR(h.Sum(nil), f[40:56])
	}
	send = keyed(frame[:])
	rev := frame
	slices.Reverse(rev[8:56])
	recv = keyed(rev[:])

	var enc [64]byte
	send.XORKeyStream(enc[:], frame[:])
	copy(enc[8:56], frame[8:56])
	return enc[:], send, recv
}

// --- harness ---------------------------------------------------------------

type harnessCfg struct {
	preferIP      string
	allowFallback bool
	skew          time.Duration
	frontingPort  int
	frontingPP    bool
}

type harness struct {
	t      *testing.T
	proxy  *mtglib.Proxy
	net    *fakeNetwork
	dc     *fakeDC
	events *eventLog
	logs   *logSink
	cache  *countingCache
	secret mtglib.Secret

	shutdownOnce sync.Once
}

func newHarness(t *testing.T, cfg harnessCfg) *harness {
	t.Helper()
	h := &harness{
		t:      t,
		dc:     newFakeDC(t),
		events: &eventLog{},
		logs:   &logSink{},
		secret: mtglib.GenerateSecret(testFrontHost),
	}
	h.net = &fakeNetwork{t: t, dcAddr: h.dc.ln.Addr().String()}
	h.cache = &countingCache{inner: antireplay.NewStableBloomFilter(
		antireplay.DefaultStableBloomFilterMaxSize, antireplay.DefaultStableBloomFilterErrorRate)}

	opts := mtglib.ProxyOpts{
		Secret:                      h.secret,
		Network:                     h.net,
		AntiReplayCache:             h.cache,
		IPBlocklist:                 blockAll{},
		IPAllowlist:                 ipblocklist.NewNoop(),
		EventStream:                 h.events,
		Logger:                      testLogger{sink: h.logs, name: "mtg"},
		PreferIP:                    cfg.preferIP,
		AllowFallbackOnUnknownDC:    cfg.allowFallback,
		TolerateTimeSkewness:        cfg.skew,
		IdleTimeout:                 time.Minute,
		HandshakeTimeout:            testTimeout,
		DomainFrontingIP:            "127.0.0.1",
		DomainFrontingPort:          uint(cfg.frontingPort),
		DomainFrontingProxyProtocol: cfg.frontingPP,
	}
	p, err := mtglib.NewProxy(opts)
	if err != nil {
		t.Fatal(err)
	}
	h.proxy = p
	t.Cleanup(h.shutdown)
	return h
}

func (h *harness) shutdown() { h.shutdownOnce.Do(h.proxy.Shutdown) }

// serve отдаёт mtg серверную сторону loopback-пары с «клиентским» RemoteAddr.
func (h *harness) serve() (client *net.TCPConn, done chan struct{}) {
	h.t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cc, err := (&net.Dialer{Timeout: testTimeout}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		h.t.Fatal(err)
	}
	sc, err := ln.Accept()
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = cc.Close() })
	remote := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(testClientAddr))
	conn := addrConn{Conn: essentials.WrapNetConn(sc), remote: remote}
	done = make(chan struct{})
	go func() {
		defer close(done)
		h.proxy.ServeConn(conn)
	}()
	cc.SetDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	return cc.(*net.TCPConn), done
}

func (h *harness) validHello() []byte {
	return buildClientHello(helloOpts{
		key: h.secret.Key[:], sni: testFrontHost, timestamp: time.Now(), sessionID: randomSessionID(),
	})
}

// connectWith шлёт готовый ClientHello и проходит FakeTLS + obfuscated2.
func (h *harness) connectWith(hello []byte, dc int) (*clientSession, chan struct{}) {
	h.t.Helper()
	conn, done := h.serve()
	if _, err := conn.Write(hello); err != nil {
		h.t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	for i, want := range []byte{0x16, 0x14, 0x17} { // ServerHello, CCS, ApplicationData
		typ, _, err := readTLSRecord(br)
		if err != nil || typ != want {
			h.t.Fatalf("запись %d ServerHello: тип %#x err=%v, ожидали %#x", i, typ, err, want)
		}
	}
	wire, send, recv := obfuscatedHandshake(h.secret.Key[:], dc)
	s := &clientSession{conn: conn, br: br, send: send, recv: recv}
	rec := append([]byte{0x17, 0x03, 0x03}, be16(len(wire))...)
	if _, err := conn.Write(append(rec, wire...)); err != nil {
		h.t.Fatal(err)
	}
	return s, done
}

func (h *harness) connect(dc int) (*clientSession, chan struct{}) {
	h.t.Helper()
	return h.connectWith(h.validHello(), dc)
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(testTimeout):
		t.Fatalf("не дождались: %s", what)
	}
}
