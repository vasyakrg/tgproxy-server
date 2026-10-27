package mtproto

// Контракт-тесты mtg v2.2.8 (M9-T0): фиксируют поведение, на которое опирается
// docs/mtproto.md. Настоящий mtglib.Proxy, fake-DC и fronting-листенер на
// loopback, Network — фейковый. При обновлении mtg падают первыми.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/pires/go-proxyproto"
)

// v4Addrs — IPv4-адреса DC из публичной таблицы mtg.
func v4Addrs(dc int) []string {
	var out []string
	for _, a := range essentials.TelegramCoreAddresses[dc] {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			panic(err)
		}
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			out = append(out, a)
		}
	}
	return out
}

// --- RemoteAddr -------------------------------------------------------------

// ServeConn делает type assertion RemoteAddr().(*net.TCPAddr) в newStreamContext:
// наш conn обязан отдавать *net.TCPAddr, иначе panic (recover — на нашей стороне).
func TestContract_ServeConnPanicsWithoutTCPAddr(t *testing.T) {
	h := newHarness(t, harnessCfg{})

	for name, remote := range map[string]net.Addr{
		"pipeAddr": nil, // net.Pipe отдаёт собственный тип адреса
		"unix":     &net.UnixAddr{Name: "x", Net: "unix"},
		"nil":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer func() { _ = c1.Close() }()
			defer func() { _ = c2.Close() }()
			conn := essentials.WrapNetConn(c1)
			if name != "pipeAddr" {
				conn = addrConn{Conn: conn, remote: remote}
			}
			defer func() {
				if recover() == nil {
					t.Fatal("ServeConn не запаниковал при RemoteAddr не *net.TCPAddr")
				}
			}()
			h.proxy.ServeConn(conn)
		})
	}
}

// --- сетевой интерфейс ------------------------------------------------------

// ServeConn не использует DialContext/HTTP; blocklist не проверяется (бан — на нас).
func TestContract_NetworkSurfaceAndBlocklistIgnored(t *testing.T) {
	h := newHarness(t, harnessCfg{preferIP: "only-ipv4"})
	s, done := h.connect(2)
	s.roundtrip(t, []byte("ping"))
	_ = s.conn.Close()
	waitClosed(t, done, "завершение ServeConn")

	if n := h.net.dialCtxCalls.Load(); n != 0 {
		t.Fatalf("DialContext вызван %d раз: к DC mtg ходит только через Dial(network, address)", n)
	}
	if h.net.httpClientCalls.Load() < 1 {
		t.Fatal("NewProxy обязан вызвать Network.MakeHTTPClient (nil недопустим)")
	}
	if n := h.net.nativeDialerCall.Load(); n != 0 {
		t.Fatalf("NativeDialer вызван %d раз вне domain fronting", n)
	}
	// blockAll{} в harness «банит» всех — ServeConn это игнорирует (проверено roundtrip выше).
}

// --- адреса DC, PreferIP, отрицательные/неизвестные DC ----------------------

func TestContract_AddressMapIsUnambiguous(t *testing.T) {
	seen := map[string]int{}
	for dc, addrs := range essentials.TelegramCoreAddresses {
		for _, a := range addrs {
			if prev, dup := seen[a]; dup {
				t.Fatalf("адрес %s в DC %d и DC %d: отображение addr→DC неоднозначно", a, prev, dc)
			}
			seen[a] = dc
		}
	}
	// Состав таблицы, на который опирается tgapi.DCAddrs (сверка в M10-T4).
	for _, dc := range []int{1, 2, 3, 4, 5, 203} {
		if len(v4Addrs(dc)) == 0 {
			t.Fatalf("у DC %d нет IPv4-адреса", dc)
		}
	}
	for dc := range essentials.TelegramCoreAddresses {
		if !slices.Contains([]int{1, 2, 3, 4, 5, 203}, dc) {
			t.Fatalf("в таблице mtg появился неожиданный DC %d", dc)
		}
	}
}

func TestContract_DialAddressesPerDC(t *testing.T) {
	for _, dc := range []int{1, 2, 3, 4, 5, 203} {
		t.Run("dc-"+strconv.Itoa(dc), func(t *testing.T) {
			h := newHarness(t, harnessCfg{preferIP: "only-ipv4"})
			s, done := h.connect(dc)
			s.roundtrip(t, []byte("ping"))

			dials := h.net.dialLog()
			if len(dials) != 1 {
				t.Fatalf("ожидали ровно один Dial, получили %v", dials)
			}
			if dials[0].Network != "tcp4" || !slices.Contains(v4Addrs(dc), dials[0].Address) {
				t.Fatalf("Dial %v вне IPv4-адресов DC %d (%v)", dials[0], dc, v4Addrs(dc))
			}
			if got := h.dc.waitConn(t).dc; got != dc {
				t.Fatalf("DC в handshake к Telegram = %d, ждали %d", got, dc)
			}

			evs := h.events.snapshot()
			c, ok := findEvent[mtglib.EventConnectedToDC](evs)
			if !ok || c.DC != dc || net.JoinHostPort(c.RemoteIP.String(), "443") != dials[0].Address {
				t.Fatalf("EventConnectedToDC=%+v, dial=%v", c, dials[0])
			}
			_ = s.conn.Close()
			waitClosed(t, done, "ServeConn")
		})
	}
}

// only-ipv4 → только tcp4 (все IPv4 DC перебираются), дефолт mtg — IPv6 первым.
func TestContract_PreferIP(t *testing.T) {
	t.Run("only-ipv4", func(t *testing.T) {
		h := newHarness(t, harnessCfg{preferIP: "only-ipv4"})
		h.net.failAll = true
		_, done := h.connect(2)
		waitClosed(t, done, "ServeConn после отказа всех Dial")

		dials := h.net.dialLog()
		if len(dials) != len(v4Addrs(2)) {
			t.Fatalf("ожидали перебор %d IPv4-адресов DC2, получили %v", len(v4Addrs(2)), dials)
		}
		for _, d := range dials {
			if d.Network != "tcp4" || strings.HasPrefix(d.Address, "[") {
				t.Fatalf("only-ipv4 пропустил %v", d)
			}
		}
		got := []string{}
		for _, d := range dials {
			got = append(got, d.Address)
		}
		slices.Sort(got)
		want := slices.Clone(v4Addrs(2))
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("адреса %v != %v", got, want)
		}
	})
	t.Run("default-prefers-ipv6", func(t *testing.T) {
		h := newHarness(t, harnessCfg{})
		h.net.failAll = true
		_, done := h.connect(2)
		waitClosed(t, done, "ServeConn")
		dials := h.net.dialLog()
		if len(dials) == 0 || dials[0].Network != "tcp6" {
			t.Fatalf("дефолт mtg (prefer-ipv6) должен начинать с tcp6, получили %v: PreferIP обязателен", dials)
		}
	})
}

// Dial вернул ошибку → mtg пробует следующий адрес того же DC (основа повтора на другом агенте).
func TestContract_NextAddressOnDialError(t *testing.T) {
	h := newHarness(t, harnessCfg{preferIP: "only-ipv4"})
	h.net.failFirst = 1
	s, done := h.connect(2)
	s.roundtrip(t, []byte("ping"))
	dials := h.net.dialLog()
	if len(dials) != 2 || dials[0].Address == dials[1].Address {
		t.Fatalf("ожидали два разных адреса DC2, получили %v", dials)
	}
	_ = s.conn.Close()
	waitClosed(t, done, "ServeConn")
}

// Знак DC теряется: mtg берёт abs() (media-DC → тот же DC), к Telegram всегда
// идёт положительный номер; неизвестный DC → fallback на DC2 или закрытие.
func TestContract_NegativeAndUnknownDC(t *testing.T) {
	cases := []struct {
		name     string
		dc       int
		fallback bool
		wantDC   int // 0 — Dial не должно быть
	}{
		{"media-dc2", -2, false, 2},
		{"media-dc1", -1, false, 1},
		{"media-dc5", -5, false, 5},
		{"zero-defaults-to-2", 0, false, 2},
		{"unknown-fallback", 9, true, 2},
		{"unknown-negative-fallback", -9, true, 2},
		{"unknown-no-fallback", 9, false, 0},
		{"int16-min-no-fallback", -32768, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, harnessCfg{preferIP: "only-ipv4", allowFallback: tc.fallback})
			s, done := h.connect(tc.dc)
			if tc.wantDC == 0 {
				waitClosed(t, done, "закрытие при неизвестном DC без fallback")
				if d := h.net.dialLog(); len(d) != 0 {
					t.Fatalf("Dial при неизвестном DC без fallback: %v", d)
				}
				return
			}
			s.roundtrip(t, []byte("ping"))
			dials := h.net.dialLog()
			if len(dials) != 1 || !slices.Contains(v4Addrs(tc.wantDC), dials[0].Address) {
				t.Fatalf("Dial %v вне адресов DC %d", dials, tc.wantDC)
			}
			if got := h.dc.waitConn(t).dc; got != tc.wantDC {
				t.Fatalf("к Telegram ушёл DC %d, ждали %d (знак не передаётся)", got, tc.wantDC)
			}
			c, _ := findEvent[mtglib.EventConnectedToDC](h.events.snapshot())
			if c.DC != tc.wantDC {
				t.Fatalf("EventConnectedToDC.DC=%d, ждали %d", c.DC, tc.wantDC)
			}
			_ = s.conn.Close()
			waitClosed(t, done, "ServeConn")
		})
	}
}

// --- anti-replay ------------------------------------------------------------

// SeenBefore вызывается ровно один раз на валидный ClientHello и получает
// SessionID (не HMAC-digest); для невалидных ClientHello (HMAC/SNI/время) — не вызывается.
func TestContract_SeenBeforeOncePerValidHello(t *testing.T) {
	h := newHarness(t, harnessCfg{preferIP: "only-ipv4", skew: 3 * time.Second, frontingPort: 1})

	sid := randomSessionID()
	hello := buildClientHello(helloOpts{
		key: h.secret.Key[:], sni: testFrontHost, timestamp: time.Now(), sessionID: sid,
	})
	s, done := h.connectWith(hello, 2)
	s.roundtrip(t, []byte("ping"))
	calls := h.cache.callList()
	if len(calls) != 1 {
		t.Fatalf("SeenBefore вызван %d раз на один ClientHello, ждали 1", len(calls))
	}
	if !bytes.Equal(calls[0], sid) {
		t.Fatalf("SeenBefore получил %x, ждали SessionID %x", calls[0], sid)
	}
	_ = s.conn.Close()
	waitClosed(t, done, "ServeConn")

	// Невалидные варианты: fronting уходит на порт 1 (недоступен) — важно лишь,
	// что до SeenBefore дело не доходит.
	bad := map[string][]byte{
		"wrong-hmac": buildClientHello(helloOpts{
			key: bytes.Repeat([]byte{7}, 16), sni: testFrontHost, timestamp: time.Now(), sessionID: randomSessionID()}),
		"wrong-sni": buildClientHello(helloOpts{
			key: h.secret.Key[:], sni: "other.example.test", timestamp: time.Now(), sessionID: randomSessionID()}),
		"stale-timestamp": buildClientHello(helloOpts{
			key: h.secret.Key[:], sni: testFrontHost, timestamp: time.Now().Add(-time.Minute), sessionID: randomSessionID()}),
		"future-timestamp": buildClientHello(helloOpts{
			key: h.secret.Key[:], sni: testFrontHost, timestamp: time.Now().Add(time.Minute), sessionID: randomSessionID()}),
	}
	for name, hello := range bad {
		conn, done := h.serve()
		if _, err := conn.Write(hello); err != nil {
			t.Fatal(err)
		}
		waitClosed(t, done, name)
		_ = conn.Close()
	}
	if n := len(h.cache.callList()); n != 1 {
		t.Fatalf("SeenBefore вызван для невалидного ClientHello (всего вызовов %d)", n)
	}
}

// Общий StableBloomFilter ловит повтор: событие ReplayAttack + domain fronting,
// байты ClientHello воспроизводятся на fronting-хост без искажений.
func TestContract_ReplayDetected(t *testing.T) {
	front := newFrontServer(t, false)
	h := newHarness(t, harnessCfg{preferIP: "only-ipv4", frontingPort: front.port()})

	hello := h.validHello()
	s, done := h.connectWith(hello, 2)
	s.roundtrip(t, []byte("ping"))
	_ = s.conn.Close()
	waitClosed(t, done, "первый ServeConn")

	conn, done2 := h.serve()
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	got := front.read(t, len(hello))
	if !bytes.Equal(got.body, hello) {
		t.Fatal("fronting получил не те байты, что прислал клиент")
	}
	reply, _ := io.ReadAll(conn)
	if !bytes.HasPrefix(reply, []byte("HTTP/1.1 200")) {
		t.Fatalf("клиент не получил ответ сайта: %q", reply)
	}
	waitClosed(t, done2, "второй ServeConn")

	if calls := h.cache.callList(); len(calls) != 2 || !bytes.Equal(calls[0], calls[1]) {
		t.Fatalf("SeenBefore: %d вызовов, ждали 2 с одинаковым аргументом", len(calls))
	}
	evs := h.events.snapshot()
	if !hasEvent[mtglib.EventReplayAttack](evs) || !hasEvent[mtglib.EventDomainFronting](evs) {
		t.Fatalf("при повторе ждали ReplayAttack+DomainFronting, есть: %s", describeEvents(evs))
	}
	if len(h.net.dialLog()) != 1 {
		t.Fatalf("повтор не должен ходить к DC: %v", h.net.dialLog())
	}
}

// --- Shutdown ----------------------------------------------------------------

// Shutdown рвёт активный relay (обе стороны) и возвращается быстро.
func TestContract_ShutdownTearsDownRelay(t *testing.T) {
	h := newHarness(t, harnessCfg{preferIP: "only-ipv4"})
	s, done := h.connect(2)
	s.roundtrip(t, []byte("ping"))
	dcc := h.dc.waitConn(t)

	finished := make(chan struct{})
	started := time.Now()
	go func() { h.shutdown(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown не вернулся за 3 с при активном relay: нужен свой реестр conn (docs/mtproto.md §4.3)")
	}
	t.Logf("Shutdown с активным relay занял %s", time.Since(started))

	waitClosed(t, done, "ServeConn после Shutdown")
	waitClosed(t, dcc.closed, "соединение к DC после Shutdown")
	s.conn.SetReadDeadline(time.Now().Add(time.Second)) //nolint:errcheck
	if _, err := s.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("клиентское соединение читается после Shutdown")
	} else if ne := (net.Error)(nil); errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("клиентское соединение не закрыто Shutdown")
	}

	// Соединение, принятое уже после Shutdown, закрывается без обращения к DC.
	conn, done2 := h.serve()
	conn.Write(h.validHello()) //nolint:errcheck
	waitClosed(t, done2, "ServeConn после Shutdown")
	if n := len(h.net.dialLog()); n != 1 {
		t.Fatalf("после Shutdown были Dial: %v", h.net.dialLog())
	}
}

// --- domain fronting ----------------------------------------------------------

type frontResult struct {
	header *proxyproto.Header
	body   []byte
}

// frontServer — «настоящий сайт»: читает PROXY v2 (опц.), N байт, отвечает 200.
type frontServer struct {
	ln net.Listener
	pp bool
	ch chan frontResult
}

func newFrontServer(t *testing.T, pp bool) *frontServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &frontServer{ln: ln, pp: pp, ch: make(chan frontResult, 4)}
}

func (f *frontServer) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

// read принимает одно соединение, ждёт n байт тела и отвечает.
func (f *frontServer) read(t *testing.T, n int) frontResult {
	t.Helper()
	if tl, ok := f.ln.(*net.TCPListener); ok {
		tl.SetDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	}
	c, err := f.ln.Accept()
	if err != nil {
		t.Fatalf("fronting-сайт не получил соединение: %v", err)
	}
	defer func() { _ = c.Close() }()
	c.SetDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	br := bufio.NewReader(c)
	var res frontResult
	if f.pp {
		res.header, err = proxyproto.Read(br)
		if err != nil {
			t.Fatalf("PROXY-заголовок: %v", err)
		}
	}
	res.body = make([]byte, n)
	if _, err := io.ReadFull(br, res.body); err != nil {
		t.Fatalf("тело fronting: %v (получено %q)", err, res.body)
	}
	c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")) //nolint:errcheck
	return res
}

func TestContract_DomainFronting(t *testing.T) {
	garbage := []byte("GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
	cases := []struct {
		name  string
		hello func(h *harness) []byte
	}{
		{"bad-hmac", func(_ *harness) []byte {
			return buildClientHello(helloOpts{key: bytes.Repeat([]byte{9}, 16), sni: testFrontHost,
				timestamp: time.Now(), sessionID: randomSessionID()})
		}},
		{"wrong-sni", func(h *harness) []byte {
			return buildClientHello(helloOpts{key: h.secret.Key[:], sni: "scanner.example.test",
				timestamp: time.Now(), sessionID: randomSessionID()})
		}},
		{"not-tls", func(*harness) []byte { return garbage }},
	}
	for _, pp := range []bool{true, false} {
		for _, tc := range cases {
			name := tc.name + "/proxy-protocol-off"
			if pp {
				name = tc.name + "/proxy-protocol-v2"
			}
			t.Run(name, func(t *testing.T) {
				front := newFrontServer(t, pp)
				h := newHarness(t, harnessCfg{frontingPort: front.port(), frontingPP: pp})
				hello := tc.hello(h)

				conn, done := h.serve()
				if _, err := conn.Write(hello); err != nil {
					t.Fatal(err)
				}
				got := front.read(t, len(hello))
				if !bytes.Equal(got.body, hello) {
					t.Fatalf("fronting получил не те байты, что отправил клиент:\n%q\n%q", got.body, hello)
				}
				if pp {
					hd := got.header
					if hd.Version != 2 || hd.Command != proxyproto.PROXY || hd.TransportProtocol != proxyproto.TCPv4 {
						t.Fatalf("заголовок PROXY: %+v", hd)
					}
					src, _, _ := hd.TCPAddrs()
					if src.String() != testClientAddr {
						t.Fatalf("PROXY src=%s, ждали исходный адрес клиента %s", src, testClientAddr)
					}
				} else if got.header != nil {
					t.Fatal("PROXY-заголовок при ProxyProtocol=false")
				}

				reply, _ := io.ReadAll(conn)
				if !bytes.HasPrefix(reply, []byte("HTTP/1.1 200 OK")) {
					t.Fatalf("клиент не получил ответ сайта: %q", reply)
				}
				waitClosed(t, done, "ServeConn")

				evs := h.events.snapshot()
				if !hasEvent[mtglib.EventDomainFronting](evs) {
					t.Fatalf("нет EventDomainFronting: %s", describeEvents(evs))
				}
				if hasEvent[mtglib.EventReplayAttack](evs) {
					t.Fatal("EventReplayAttack на невалидном ClientHello")
				}
				if len(h.net.dialLog()) != 0 || len(h.cache.callList()) != 0 {
					t.Fatal("невалидный ClientHello дошёл до DC или anti-replay")
				}
				if h.net.nativeDialerCall.Load() != 1 {
					t.Fatal("fronting обязан идти через Network.NativeDialer")
				}
			})
		}
	}
}

// --- события -------------------------------------------------------------------

func TestContract_EventsOfSuccessfulSession(t *testing.T) {
	h := newHarness(t, harnessCfg{preferIP: "only-ipv4"})
	s, done := h.connect(4)
	payload := bytes.Repeat([]byte("x"), 1000)
	s.roundtrip(t, payload)
	_ = s.conn.Close()
	waitClosed(t, done, "ServeConn")

	evs := h.events.waitFor(t, "EventFinish", hasEvent[mtglib.EventFinish])
	start, ok := evs[0].(mtglib.EventStart)
	if !ok {
		t.Fatalf("первое событие %T, ждали EventStart", evs[0])
	}
	if start.StreamID() == "" || start.RemoteIP.String() != "203.0.113.7" {
		t.Fatalf("EventStart: id=%q ip=%s (IP берётся из RemoteAddr)", start.StreamID(), start.RemoteIP)
	}
	if _, ok := evs[len(evs)-1].(mtglib.EventFinish); !ok {
		t.Fatalf("последнее событие %T, ждали EventFinish", evs[len(evs)-1])
	}
	var connAt, firstTraffic = -1, -1
	var in, out uint
	for i, ev := range evs {
		if ev.StreamID() != start.StreamID() {
			t.Fatalf("событие %T с другим StreamID", ev)
		}
		if ev.Timestamp().IsZero() {
			t.Fatalf("событие %T без Timestamp", ev)
		}
		switch e := ev.(type) {
		case mtglib.EventConnectedToDC:
			connAt = i
			if e.DC != 4 || !slices.Contains(v4Addrs(4), net.JoinHostPort(e.RemoteIP.String(), "443")) {
				t.Fatalf("EventConnectedToDC=%+v", e)
			}
		case mtglib.EventTraffic:
			if firstTraffic < 0 {
				firstTraffic = i
			}
			if e.IsRead {
				in += e.Traffic // байты от Telegram к клиенту
			} else {
				out += e.Traffic // байты от клиента к Telegram
			}
		}
	}
	if connAt < 0 || firstTraffic < connAt {
		t.Fatalf("порядок событий: ConnectedToDC=%d, первый Traffic=%d", connAt, firstTraffic)
	}
	if in != 1000 || out != 1000 {
		t.Fatalf("EventTraffic: от DC %d, к DC %d; ждали по 1000 (handshake 64 байта не считается)", in, out)
	}
}

// --- секреты в логах mtg ----------------------------------------------------------

func TestContract_SecretNotInMtgLogs(t *testing.T) {
	front := newFrontServer(t, false)
	h := newHarness(t, harnessCfg{preferIP: "only-ipv4", frontingPort: front.port()})

	hello := h.validHello()
	s, done := h.connectWith(hello, 2)
	s.roundtrip(t, []byte("ping"))
	_ = s.conn.Close()
	waitClosed(t, done, "ServeConn")

	conn, done2 := h.serve() // повтор
	conn.Write(hello)        //nolint:errcheck
	front.read(t, len(hello))
	waitClosed(t, done2, "ServeConn повтора")

	logs := h.logs.all()
	if logs == "" {
		t.Fatal("mtg ничего не залогировал: тест бессмыслен")
	}
	key := h.secret.Key[:]
	for _, needle := range []string{
		hex.EncodeToString(key),
		strings.ToUpper(hex.EncodeToString(key)),
		h.secret.Hex(),
		h.secret.Base64(),
		base64.StdEncoding.EncodeToString(key),
		base64.RawURLEncoding.EncodeToString(key),
	} {
		if strings.Contains(logs, needle) {
			t.Fatalf("секрет (%d симв.) попал в логи mtg", len(needle))
		}
	}
	// ключ не должен вытекать и в события — у них просто нет таких полей, проверяем текстом
	if strings.Contains(describeEvents(h.events.snapshot()), hex.EncodeToString(key)) {
		t.Fatal("ключ в описании событий")
	}
}
