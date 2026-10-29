package mtproto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/mtglib"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/probe"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

const (
	pollEvery = 10 * time.Millisecond
	// revokeBudget — бюджет «отзыв рвёт соединение» из дизайна (≤2 с опроса) для тестов с poll=10 мс.
	revokeBudget = 2 * time.Second
)

// --- вспомогательные типы ----------------------------------------------------

type fakeClock struct{ ns atomic.Int64 }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Now().UnixNano())
	return c
}
func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

// remoteConn отдаёт mtg «клиентский» *net.TCPAddr, как это делает replayConn из mux.
type remoteConn struct {
	*net.TCPConn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

// serveSrv — TCP-листенер, раздающий соединения Manager.Route().Serve по ключу.
type serveSrv struct {
	ln net.Listener
	m  *Manager
	wg sync.WaitGroup
	// idx — индекс инстанса, куда направляются следующие соединения.
	idx atomic.Int64
}

func startServe(t *testing.T, m *Manager) *serveSrv {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &serveSrv{ln: ln, m: m}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handle(c.(*net.TCPConn))
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	return s
}

// handle отдаёт соединение в Route().Serve с индексом, выбранным тестом.
func (s *serveSrv) handle(c *net.TCPConn) {
	route := s.m.Route()
	if route == nil {
		_ = c.Close()
		return
	}
	idx := int(s.idx.Load())
	route.Serve(idx, remoteConn{c, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(testClientAddr))})
}

func (s *serveSrv) addr() string { return s.ln.Addr().String() }

func dialSession(t *testing.T, addr string, key [16]byte, dc int) *clientSession {
	t.Helper()
	cc, err := (&net.Dialer{Timeout: testTimeout}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	conn := cc.(*net.TCPConn)
	conn.SetDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	hello := buildClientHello(helloOpts{key: key[:], sni: testFrontHost, timestamp: time.Now(), sessionID: randomSessionID()})
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	return finishSession(t, conn, key, dc)
}

func finishSession(t *testing.T, conn *net.TCPConn, key [16]byte, dc int) *clientSession {
	t.Helper()
	br := bufio.NewReader(conn)
	for i, want := range []byte{0x16, 0x14, 0x17} {
		typ, _, err := readTLSRecord(br)
		if err != nil || typ != want {
			t.Fatalf("запись %d ServerHello: тип %#x err=%v", i, typ, err)
		}
	}
	wire, send, recv := obfuscatedHandshake(key[:], dc)
	s := &clientSession{conn: conn, br: br, send: send, recv: recv}
	rec := append([]byte{0x17, 0x03, 0x03}, be16(len(wire))...)
	if _, err := conn.Write(append(rec, wire...)); err != nil {
		t.Fatal(err)
	}
	return s
}

// --- окружение ----------------------------------------------------------------

type env struct {
	t     *testing.T
	repo  store.MTProtoSecretRepo
	clk   *fakeClock
	dc    *fakeDC
	front *frontServer
	net   *fakeNetwork
	opens []string
	mu    sync.Mutex

	available atomic.Bool
	replays   chan netip.Addr
	obs       *recObserver
	m         *Manager
}

type recObserver struct {
	mu   sync.Mutex
	logs []string
}

func (o *recObserver) add(s string) { o.mu.Lock(); o.logs = append(o.logs, s); o.mu.Unlock() }
func (o *recObserver) Start(id int64, _ string, ip netip.Addr) {
	o.add("start:" + strconv.FormatInt(id, 10) + ":" + ip.String())
}
func (o *recObserver) ConnectedToDC(id int64, _ string, dc int) {
	o.add("dc:" + strconv.FormatInt(id, 10) + ":" + strconv.Itoa(dc))
}
func (o *recObserver) Traffic(id int64, _ string, n uint, fromTG bool) {
	if n > 0 {
		o.add("traffic:" + strconv.FormatInt(id, 10) + ":" + strconv.FormatBool(fromTG))
	}
}
func (o *recObserver) Finish(id int64, _, _, _ string) { o.add("finish:" + strconv.FormatInt(id, 10)) }
func (o *recObserver) all() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.logs)
}
func (o *recObserver) has(prefix string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.ContainsFunc(o.logs, func(s string) bool { return strings.HasPrefix(s, prefix) })
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func newEnv(t *testing.T, mod ...func(*Options)) (*env, *lockedBuf) {
	t.Helper()
	e := &env{
		t:       t,
		repo:    memtest.New().MTProtoSecrets(),
		clk:     newFakeClock(),
		dc:      newFakeDC(t),
		front:   newFrontServer(t, true),
		replays: make(chan netip.Addr, 8),
		obs:     &recObserver{},
	}
	e.available.Store(true)
	e.net = &fakeNetwork{t: t, dcAddr: e.dc.ln.Addr().String()}
	buf := &lockedBuf{}
	o := Options{
		Secrets:      e.repo,
		Open:         e.open,
		Network:      e.net,
		FrontingAddr: e.front.ln.Addr().(*net.TCPAddr),
		Available:    e.available.Load,
		OnReplay:     func(ip netip.Addr) { e.replays <- ip },
		Observer:     e.obs,
		Logger:       slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Config: config.MTProtoConfig{
			FrontingDomain:   testFrontHost,
			HandshakeTimeout: testTimeout,
			IdleTimeout:      time.Minute,
			TimeSkew:         2 * time.Minute,
			ReplayCache:      1 << 20,
		},
		PollInterval: pollEvery,
		Now:          e.clk.Now,
	}
	for _, f := range mod {
		f(&o)
	}
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	e.m = m
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; _ = m.Close() })
	return e, buf
}

// open — «KEK» теста: sealed == ключ; запоминает aad.
func (e *env) open(sealed []byte, aad string) ([]byte, error) {
	e.mu.Lock()
	e.opens = append(e.opens, aad)
	e.mu.Unlock()
	if len(sealed) == 0 {
		return nil, errors.New("sealed пуст")
	}
	return slices.Clone(sealed), nil
}

func (e *env) addSecret(name string) (store.MTProtoSecret, [16]byte) {
	e.t.Helper()
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		e.t.Fatal(err)
	}
	s, err := e.repo.Create(context.Background(), name, fixedSeal(key[:]), hex.EncodeToString(key[:4]), nil, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	return s, key
}

func (e *env) waitKeys(want int) Route {
	e.t.Helper()
	deadline := time.Now().Add(revokeBudget)
	for time.Now().Before(deadline) {
		r := e.m.Route()
		switch {
		case want == 0 && r == nil:
			return nil
		case r != nil && len(r.Keys()) == want:
			return r
		}
		time.Sleep(2 * time.Millisecond)
	}
	e.t.Fatalf("за %v не получили %d ключей в Route", revokeBudget, want)
	return nil
}

func keyIdx(t *testing.T, r Route, key [16]byte) int {
	t.Helper()
	i := slices.Index(r.Keys(), key)
	if i < 0 {
		t.Fatal("ключа нет в Route")
	}
	return i
}

func waitEOF(t *testing.T, s *clientSession, within time.Duration) {
	t.Helper()
	s.conn.SetReadDeadline(time.Now().Add(within)) //nolint:errcheck
	_, err := s.readN(1)
	if err == nil {
		t.Fatal("ждали разрыв соединения")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("соединение не разорвано за %v", within)
	}
}

// --- тесты ---------------------------------------------------------------------

func TestManager_NoSecretsNoRoute(t *testing.T) {
	e, _ := newEnv(t)
	time.Sleep(3 * pollEvery)
	if e.m.Route() != nil {
		t.Fatal("без секретов Route обязан быть nil")
	}
}

func TestManager_AddSecretWithoutRestart(t *testing.T) {
	fdc, _, err := probe.NewFakeDC()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fdc.Close() })
	e, _ := newEnv(t)
	e.net.dcAddr = fdc.Addr()
	srv := startServe(t, e.m)

	s1, k1 := e.addSecret("one")
	r := e.waitKeys(1)
	if r.Keys()[0] != k1 || r.Domain() != testFrontHost || r.Skew() != 2*time.Minute {
		t.Fatalf("снимок: keys=%x domain=%q skew=%v", r.Keys(), r.Domain(), r.Skew())
	}
	srv.idx.Store(0)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := probe.Run(ctx, srv.addr(), k1, testFrontHost)
	if err != nil || !res.DCResponded {
		t.Fatalf("probe через первый секрет: %+v %v", res, err)
	}

	// второй секрет подхватывается без рестарта; первый инстанс переиспользован
	before := e.m.snap.Load().insts[0]
	_, k2 := e.addSecret("two")
	r = e.waitKeys(2)
	if e.m.snap.Load().insts[keyIdx(t, r, k1)] != before {
		t.Fatal("неизменный секрет пересоздан")
	}
	srv.idx.Store(int64(keyIdx(t, r, k2)))
	res, err = probe.Run(ctx, srv.addr(), k2, testFrontHost)
	if err != nil || !res.DCResponded {
		t.Fatalf("probe через второй секрет: %+v %v", res, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !slices.Contains(e.opens, "mtproto/"+strconv.FormatInt(s1.ID, 10)) {
		t.Fatalf("aad не mtproto/<id>: %v", e.opens)
	}
}

func TestManager_RevokeTearsDownActiveConnection(t *testing.T) {
	e, _ := newEnv(t)
	srv := startServe(t, e.m)
	s, key := e.addSecret("one")
	r := e.waitKeys(1)
	srv.idx.Store(int64(keyIdx(t, r, key)))

	sess := dialSession(t, srv.addr(), key, 2)
	sess.roundtrip(t, []byte("ping"))
	dc := e.dc.waitConn(t)

	start := time.Now()
	if err := e.repo.Revoke(context.Background(), s.ID, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	waitEOF(t, sess, revokeBudget)
	select {
	case <-dc.closed:
	case <-time.After(revokeBudget):
		t.Fatal("DC-сторона relay не закрыта после отзыва")
	}
	if d := time.Since(start); d > revokeBudget {
		t.Fatalf("отзыв сработал за %v", d)
	}
	e.waitKeys(0)
}

func TestManager_GraceUntilKeepsOldSecret(t *testing.T) {
	e, _ := newEnv(t)
	srv := startServe(t, e.m)
	old, oldKey := e.addSecret("one")
	e.waitKeys(1)

	var newKey [16]byte
	if _, err := rand.Read(newKey[:]); err != nil {
		t.Fatal(err)
	}
	grace := e.clk.Now().Add(time.Minute)
	if _, err := e.repo.Rotate(context.Background(), old.ID, fixedSeal(newKey[:]), "aabbccdd", grace); err != nil {
		t.Fatal(err)
	}
	r := e.waitKeys(2)
	if !slices.Contains(r.Keys(), oldKey) || !slices.Contains(r.Keys(), newKey) {
		t.Fatal("в grace ждали оба ключа")
	}
	srv.idx.Store(int64(keyIdx(t, r, oldKey)))
	sess := dialSession(t, srv.addr(), oldKey, 2)
	sess.roundtrip(t, []byte("still works"))

	// версия таблицы не меняется, но срок grace истёк
	e.clk.Advance(2 * time.Minute)
	r = e.waitKeys(1)
	if r.Keys()[0] != newKey {
		t.Fatal("после grace остаться должен только новый ключ")
	}
	waitEOF(t, sess, revokeBudget)
}

func TestManager_ReplayCallsOnReplayAndFronts(t *testing.T) {
	e, _ := newEnv(t)
	srv := startServe(t, e.m)
	_, key := e.addSecret("one")
	r := e.waitKeys(1)
	srv.idx.Store(int64(keyIdx(t, r, key)))

	hello := buildClientHello(helloOpts{key: key[:], sni: testFrontHost, timestamp: time.Now(), sessionID: randomSessionID()})
	for i := range 2 {
		cc, err := (&net.Dialer{Timeout: testTimeout}).DialContext(context.Background(), "tcp", srv.addr())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cc.Close() })
		cc.SetDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
		if _, err := cc.Write(hello); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if typ, _, err := readTLSRecord(cc); err != nil || typ != 0x16 {
				t.Fatalf("первый ClientHello должен принять ServerHello: %#x %v", typ, err)
			}
			select {
			case ip := <-e.replays:
				t.Fatalf("OnReplay на первом ClientHello: %v", ip)
			default:
			}
		}
	}
	select {
	case ip := <-e.replays:
		if ip != netip.MustParseAddr("203.0.113.7") {
			t.Fatalf("OnReplay ip=%v", ip)
		}
	case <-time.After(testTimeout):
		t.Fatal("OnReplay не вызван")
	}
	res := e.front.read(t, len(hello))
	if !bytes.Equal(res.body, hello) || res.header == nil {
		t.Fatal("повтор не ушёл на fronting с PROXY v2")
	}
}

func TestManager_KeyNeverInLogs(t *testing.T) {
	front := newFrontServer(t, true)
	e, buf := newEnv(t, func(o *Options) { o.FrontingAddr = front.ln.Addr().(*net.TCPAddr) })
	srv := startServe(t, e.m)
	_, key := e.addSecret("one")
	r := e.waitKeys(1)
	srv.idx.Store(int64(keyIdx(t, r, key)))

	sess := dialSession(t, srv.addr(), key, 2)
	sess.roundtrip(t, []byte("ping"))
	_ = sess.conn.Close()

	// неверный ClientHello и повтор — ветки с логированием ошибок
	bad := buildClientHello(helloOpts{key: make([]byte, 16), sni: testFrontHost, timestamp: time.Now(), sessionID: randomSessionID()})
	cc, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", srv.addr())
	if err != nil {
		t.Fatal(err)
	}
	cc.Write(bad) //nolint:errcheck
	_ = cc.Close()

	// принудительно останавливаем всё, чтобы все записи лога были сброшены
	_ = e.m.Close()
	out := buf.String()
	if out == "" {
		t.Fatal("лог пуст — проверка бессмысленна")
	}
	hexKey := hex.EncodeToString(key[:])
	if regexp.MustCompile(`(?i)ee[0-9a-f]{32}`).MatchString(out) || strings.Contains(strings.ToLower(out), hexKey) {
		t.Fatalf("ключ секрета попал в лог:\n%s", out)
	}
}

func TestMTGLogger_MasksKeyInAnyForm(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(0xA0 + i)
	}
	buf := &lockedBuf{}
	lg := newMTGLogger(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), key)
	h := hex.EncodeToString(key[:])
	lg = lg.Named("n-"+h).BindStr("link", "ee"+h+"7777").BindJSON("j", `{"k":"`+strings.ToUpper(h)+`"}`).BindInt("n", 3)
	lg.Printf("secret %s", h)
	lg.Info("ee" + h + hex.EncodeToString([]byte("example.com")))
	lg.InfoError("x", errors.New("bad "+h))
	lg.Warning("w " + h)
	lg.WarningError("w", errors.New(h))
	lg.Debug("d " + h)
	lg.DebugError("d", errors.New(h))
	out := buf.String()
	if strings.Count(out, "\n") != 7 {
		t.Fatalf("ждали 7 записей:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), h) || regexp.MustCompile(`(?i)ee[0-9a-f]{32}`).MatchString(out) {
		t.Fatalf("ключ не замаскирован:\n%s", out)
	}
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "n=3") {
		t.Fatalf("уровень/атрибуты потеряны:\n%s", out)
	}
	// nil-логгер не паникует
	newMTGLogger(nil, key).Warning("x")
}

func TestManager_RouteNilWhenNoCapableAgents(t *testing.T) {
	e, _ := newEnv(t)
	e.addSecret("one")
	e.waitKeys(1)
	e.available.Store(false)
	if e.m.Route() != nil {
		t.Fatal("без capable-агентов Route обязан быть nil")
	}
	e.available.Store(true)
	if e.m.Route() == nil {
		t.Fatal("Route не вернулся")
	}
}

func TestRoute_ServeRejectsBadInput(t *testing.T) {
	e, _ := newEnv(t)
	e.addSecret("one")
	r := e.waitKeys(1)

	for name, tc := range map[string]struct {
		idx    int
		remote net.Addr
	}{
		"плохой индекс":       {5, &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1}},
		"отрицательный":       {-1, &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1}},
		"RemoteAddr не TCP":   {0, &net.UnixAddr{Name: "x", Net: "unix"}},
		"RemoteAddr nil-Addr": {0, nilAddr{}},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer func() { _ = b.Close() }()
			done := make(chan struct{})
			go func() { defer close(done); r.Serve(tc.idx, pipeAddr{a, tc.remote}) }()
			waitClosed(t, done, "Serve вернулся")
			_ = b.SetReadDeadline(time.Now().Add(testTimeout))
			if _, err := b.Read(make([]byte, 1)); err == nil {
				t.Fatal("соединение должно быть закрыто")
			}
		})
	}
}

type nilAddr struct{}

func (nilAddr) Network() string { return "x" }
func (nilAddr) String() string  { return "x" }

type pipeAddr struct {
	net.Conn
	remote net.Addr
}

func (c pipeAddr) RemoteAddr() net.Addr { return c.remote }

func TestManager_ObserverGetsSecretID(t *testing.T) {
	fdc, _, err := probe.NewFakeDC()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fdc.Close() })
	e, _ := newEnv(t)
	e.net.dcAddr = fdc.Addr()
	srv := startServe(t, e.m)
	_, k1 := e.addSecret("one")
	s2, k2 := e.addSecret("two")
	r := e.waitKeys(2)
	srv.idx.Store(int64(keyIdx(t, r, k2)))
	_ = k1

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, err := probe.RunDC(ctx, srv.addr(), k2, testFrontHost, 4); err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(s2.ID, 10)
	deadline := time.Now().Add(testTimeout)
	for !e.obs.has("finish:"+id) || !e.obs.has("traffic:"+id+":true") {
		if time.Now().After(deadline) {
			t.Fatalf("события не дошли: %v", e.obs.all())
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, p := range []string{"start:" + id + ":203.0.113.7", "dc:" + id + ":4"} {
		if !e.obs.has(p) {
			t.Fatalf("нет события %q: %v", p, e.obs.all())
		}
	}
}

func TestManager_OpenFailureSkipsOnlyThatSecret(t *testing.T) {
	e, buf := newEnv(t)
	if _, err := e.repo.Create(context.Background(), "broken", fixedSeal([]byte{1, 2, 3}), "01020304", nil, 0); err != nil {
		t.Fatal(err)
	}
	_, good := e.addSecret("good")
	r := e.waitKeys(1)
	if r.Keys()[0] != good {
		t.Fatal("ждали только исправный секрет")
	}
	if !strings.Contains(buf.String(), "секрет пропущен") {
		t.Fatalf("пропуск не залогирован:\n%s", buf.String())
	}
	// ошибка расшифровки
	e2, _ := newEnv(t, func(o *Options) {
		o.Open = func([]byte, string) ([]byte, error) { return nil, errors.New("wrong aad") }
	})
	e2.addSecret("x")
	time.Sleep(10 * pollEvery)
	if e2.m.Route() != nil {
		t.Fatal("секрет без возможности расшифровки не должен попадать в Route")
	}
}

func TestManager_CloseTearsDownAndIsIdempotent(t *testing.T) {
	e, _ := newEnv(t)
	srv := startServe(t, e.m)
	_, key := e.addSecret("one")
	r := e.waitKeys(1)
	srv.idx.Store(int64(keyIdx(t, r, key)))
	sess := dialSession(t, srv.addr(), key, 2)
	sess.roundtrip(t, []byte("ping"))

	if err := e.m.Close(); err != nil {
		t.Fatal(err)
	}
	waitEOF(t, sess, revokeBudget)
	if e.m.Route() != nil {
		t.Fatal("после Close Route обязан быть nil")
	}
	if err := e.m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Reload(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Reload после Close: %v", err)
	}
}

type failingSecrets struct {
	Secrets
	failList, failVersion atomic.Bool
}

func (f *failingSecrets) ListActive(ctx context.Context, now time.Time) ([]store.MTProtoSecret, int64, error) {
	if f.failList.Load() {
		return nil, 0, errors.New("db down")
	}
	return f.Secrets.ListActive(ctx, now)
}

func (f *failingSecrets) Version(ctx context.Context) (int64, error) {
	if f.failVersion.Load() {
		return 0, errors.New("db down")
	}
	return f.Secrets.Version(ctx)
}

func TestManager_DBErrorsKeepCurrentSnapshotAndRecover(t *testing.T) {
	fs := &failingSecrets{}
	e, buf := newEnv(t, func(o *Options) { fs.Secrets = o.Secrets; o.Secrets = fs })
	e.addSecret("one")
	e.waitKeys(1)

	fs.failVersion.Store(true)
	time.Sleep(5 * pollEvery)
	if e.m.Route() == nil {
		t.Fatal("ошибка чтения версии не должна сбрасывать разводку")
	}
	fs.failVersion.Store(false)
	fs.failList.Store(true)
	e.addSecret("two")
	time.Sleep(5 * pollEvery)
	if r := e.m.Route(); r == nil || len(r.Keys()) != 1 {
		t.Fatal("ошибка ListActive не должна менять снимок")
	}
	fs.failList.Store(false)
	e.waitKeys(2)
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Fatal("ошибки БД не залогированы")
	}
}

func TestManager_InitialLoadErrorRetries(t *testing.T) {
	fs := &failingSecrets{}
	fs.failList.Store(true)
	e, _ := newEnv(t, func(o *Options) { fs.Secrets = o.Secrets; o.Secrets = fs })
	e.addSecret("one")
	time.Sleep(5 * pollEvery)
	if e.m.Route() != nil {
		t.Fatal("маршрут до первой успешной загрузки")
	}
	fs.failList.Store(false)
	e.waitKeys(1)
}

func TestNew_Validation(t *testing.T) {
	e, _ := newEnv(t)
	base := e.m.o
	cases := map[string]func(*Options){
		"Secrets":         func(o *Options) { o.Secrets = nil },
		"Open":            func(o *Options) { o.Open = nil },
		"Network":         func(o *Options) { o.Network = nil },
		"FrontingAddr":    func(o *Options) { o.FrontingAddr = nil },
		"FrontingPort":    func(o *Options) { o.FrontingAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} },
		"fronting_domain": func(o *Options) { o.Config.FrontingDomain = "" },
	}
	for name, mod := range cases {
		o := base
		mod(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: ждали ошибку", name)
		}
	}
	o := base
	o.PollInterval, o.Now, o.Logger = 0, nil, nil
	m, err := New(o)
	if err != nil || m.o.PollInterval != DefaultPollInterval || m.o.Now == nil {
		t.Fatalf("дефолты: %v", err)
	}
}

func TestEventSink_ReplayWithoutStartIsIgnored(t *testing.T) {
	var calls atomic.Int32
	sink := newEventSink(1, nil, func(netip.Addr) { calls.Add(1) }, nil)
	sink.Send(context.Background(), mtglib.NewEventReplayAttack("unknown"))
	sink.Send(context.Background(), mtglib.NewEventStart("s", net.ParseIP("::ffff:198.51.100.9")))
	sink.Send(context.Background(), mtglib.NewEventTraffic("s", 1, true))
	sink.Send(context.Background(), mtglib.NewEventConnectedToDC("s", nil, 1))
	sink.Send(context.Background(), mtglib.NewEventReplayAttack("s"))
	sink.Send(context.Background(), mtglib.NewEventFinish("s"))
	sink.Send(context.Background(), mtglib.NewEventReplayAttack("s"))
	if calls.Load() != 1 {
		t.Fatalf("OnReplay вызван %d раз, ждали 1", calls.Load())
	}
}

func fixedSeal(b []byte) store.SealFunc {
	return func(int64) ([]byte, error) { return slices.Clone(b), nil }
}

func TestRoute_LimitsExposeSecretCIDRAndMaxConns(t *testing.T) {
	e, _ := newEnv(t)
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	s, err := e.repo.Create(context.Background(), "lim", fixedSeal(key[:]), hex.EncodeToString(key[:4]), cidrs, 5)
	if err != nil {
		t.Fatal(err)
	}
	r := e.waitKeys(1)
	id, got, mc := r.Limits(0)
	if id != s.ID || mc != 5 || !slices.Equal(got, cidrs) {
		t.Fatalf("Limits = %d %v %d", id, got, mc)
	}
	// неверный индекс — «закрыто всё»
	_, bad, _ := r.Limits(9)
	if len(bad) == 0 || bad[0].Contains(netip.MustParseAddr("1.2.3.4")) {
		t.Fatalf("плохой idx должен запрещать любой IP: %v", bad)
	}
}
