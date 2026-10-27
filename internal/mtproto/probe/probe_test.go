package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/mtglib"
)

const front = "front.example.test"

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func newDC(t *testing.T) *FakeDC {
	t.Helper()
	d, _, err := NewFakeDC()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// serveOnce принимает одно соединение и отдаёт его handler'у.
func serveOnce(t *testing.T, h func(net.Conn)) string {
	t.Helper()
	ln := listen(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		h(c)
	}()
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	return ln.Addr().String()
}

// --- fake-DC напрямую ------------------------------------------------------

func TestFakeDC_DirectResPQ(t *testing.T) {
	d := newDC(t)
	c, err := (&net.Dialer{}).DialContext(ctxT(t, 5*time.Second), "tcp", d.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	wire, send, recv, err := obfuscatedClient(nil, -3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	nonce := [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1}
	msg := unencryptedMessage(1<<32|4, reqPQMulti(nonce))
	pkt := append(binary.LittleEndian.AppendUint32(nil, uint32(len(msg))), msg...)
	send.XORKeyStream(pkt, pkt)
	if _, err := c.Write(pkt); err != nil {
		t.Fatal(err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatal(err)
	}
	recv.XORKeyStream(hdr[:], hdr[:])
	body := make([]byte, binary.LittleEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	recv.XORKeyStream(body, body)
	_, b, err := parseUnencrypted(body)
	if err != nil || binary.LittleEndian.Uint32(b) != ctorResPQ || !bytes.Equal(b[4:20], nonce[:]) {
		t.Fatalf("resPQ: %v % x", err, b)
	}
	if d.LastDC() != -3 || d.Accepted() != 1 || d.Answered() != 1 {
		t.Fatalf("статистика fake-DC: dc=%d acc=%d ans=%d", d.LastDC(), d.Accepted(), d.Answered())
	}
}

func TestFakeDC_RejectsGarbage(t *testing.T) {
	d := newDC(t)
	c, err := (&net.Dialer{}).DialContext(ctxT(t, 5*time.Second), "tcp", d.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write(bytes.Repeat([]byte{0x42}, 64)) // не тот тег протокола
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("ожидали закрытие соединения")
	}
}

func TestFakeDC_CloseStopsHandlers(t *testing.T) {
	d, _, err := NewFakeDC()
	if err != nil {
		t.Fatal(err)
	}
	c, err := (&net.Dialer{}).DialContext(ctxT(t, 5*time.Second), "tcp", d.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write(make([]byte, 10)) // handler ждёт остаток кадра
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

// --- негативные сценарии клиента -------------------------------------------

func TestRun_ServerClosesImmediately(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) { _ = c.Close() })
	_, err := Run(ctxT(t, 5*time.Second), addr, [16]byte{1}, front)
	if err == nil {
		t.Fatal("ожидали ошибку")
	}
}

func TestRun_SilentServerHitsDeadline(t *testing.T) {
	done := make(chan struct{})
	addr := serveOnce(t, func(_ net.Conn) { <-done })
	t.Cleanup(func() { close(done) })
	start := time.Now()
	_, err := Run(ctxT(t, 300*time.Millisecond), addr, [16]byte{1}, front)
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("ожидали быструю ошибку по дедлайну, err=%v, %v", err, time.Since(start))
	}
}

func TestRun_CancelUnblocks(t *testing.T) {
	done := make(chan struct{})
	addr := serveOnce(t, func(_ net.Conn) { <-done })
	t.Cleanup(func() { close(done) })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := Run(ctx, addr, [16]byte{1}, front)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидали context.Canceled, err=%v", err)
	}
}

func TestRun_NoDeadlineGetsDefault(t *testing.T) {
	// Проверяем лишь, что без дедлайна ctx Run не зависает на закрытом порту.
	ln := listen(t)
	addr := ln.Addr().String()
	_ = ln.Close()
	if _, err := Run(context.Background(), addr, [16]byte{1}, front); err == nil {
		t.Fatal("ожидали ошибку подключения")
	}
}

func TestRun_PlainHTTPInsteadOfTLS(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadFull(c, make([]byte, 5))
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	_, err := Run(ctxT(t, 5*time.Second), addr, [16]byte{1}, front)
	if err == nil {
		t.Fatal("ожидали ошибку рукопожатия")
	}
}

func TestRun_TLSAlertInsteadOfServerHello(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadFull(c, make([]byte, 5))
		_ = writeRecord(c, 0x15, []byte{2, 40})
	})
	_, err := Run(ctxT(t, 5*time.Second), addr, [16]byte{1}, front)
	if err == nil || !strings.Contains(err.Error(), "не принято") {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_WrongServerHMAC(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _, _, _ = readRecord(c)
		sh := make([]byte, 90)
		_ = writeRecord(c, recHandshake, sh)
		_ = writeRecord(c, recCCS, []byte{1})
		_ = writeRecord(c, recAppData, make([]byte, 100))
	})
	_, err := Run(ctxT(t, 5*time.Second), addr, [16]byte{1}, front)
	if err == nil || !strings.Contains(err.Error(), "HMAC") {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_ShortServerHello(t *testing.T) {
	addr := serveOnce(t, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _, _, _ = readRecord(c)
		_ = writeRecord(c, recHandshake, []byte{1})
		_ = writeRecord(c, recCCS, []byte{1})
		_ = writeRecord(c, recAppData, []byte{1})
	})
	if _, err := Run(ctxT(t, 5*time.Second), addr, [16]byte{1}, front); err == nil {
		t.Fatal("ожидали ошибку")
	}
}

// --- сквозной: настоящий mtglib.Proxy → FakeDC -----------------------------

type noopLogger struct{}

func (noopLogger) Named(string) mtglib.Logger           { return noopLogger{} }
func (noopLogger) BindInt(string, int) mtglib.Logger    { return noopLogger{} }
func (noopLogger) BindStr(string, string) mtglib.Logger { return noopLogger{} }
func (noopLogger) BindJSON(string, string) mtglib.Logger {
	return noopLogger{}
}
func (noopLogger) Printf(string, ...any)      {}
func (noopLogger) Info(string)                {}
func (noopLogger) InfoError(string, error)    {}
func (noopLogger) Warning(string)             {}
func (noopLogger) WarningError(string, error) {}
func (noopLogger) Debug(string)               {}
func (noopLogger) DebugError(string, error)   {}

type dcNetwork struct{ addr string }

func (n dcNetwork) Dial(network, address string) (essentials.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

func (n dcNetwork) DialContext(ctx context.Context, _, _ string) (essentials.Conn, error) {
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", n.addr)
	if err != nil {
		return nil, err
	}
	return essentials.WrapNetConn(c), nil
}

func (dcNetwork) MakeHTTPClient(func(context.Context, string, string) (essentials.Conn, error)) *http.Client {
	return &http.Client{}
}
func (dcNetwork) NativeDialer() *net.Dialer { return &net.Dialer{Timeout: 5 * time.Second} }

type nopEvents struct{}

func (nopEvents) Send(context.Context, mtglib.Event) {}

// startProxy поднимает mtglib.Proxy на loopback; fronting — на frontPort.
func startProxy(t *testing.T, secret mtglib.Secret, dcAddr string, frontPort int) string {
	t.Helper()
	p, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:             secret,
		Network:            dcNetwork{addr: dcAddr},
		AntiReplayCache:    antireplay.NewStableBloomFilter(antireplay.DefaultStableBloomFilterMaxSize, antireplay.DefaultStableBloomFilterErrorRate),
		IPBlocklist:        ipblocklist.NewNoop(),
		IPAllowlist:        ipblocklist.NewNoop(),
		EventStream:        nopEvents{},
		Logger:             noopLogger{},
		PreferIP:           "only-ipv4",
		IdleTimeout:        time.Minute,
		HandshakeTimeout:   5 * time.Second,
		DomainFrontingIP:   "127.0.0.1",
		DomainFrontingPort: uint(frontPort),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.ServeConn(essentials.WrapNetConn(c))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		p.Shutdown()
		wg.Wait()
	})
	return ln.Addr().String()
}

func TestRun_ThroughRealMTG(t *testing.T) {
	dc := newDC(t)
	secret := mtglib.GenerateSecret(front)
	addr := startProxy(t, secret, dc.Addr(), 1)

	res, err := Run(ctxT(t, 10*time.Second), addr, secret.Key, front)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DCResponded || res.RTT <= 0 {
		t.Fatalf("результат: %+v", res)
	}
	if dc.Answered() != 1 || dc.LastDC() != DefaultDC {
		t.Fatalf("fake-DC: ans=%d dc=%d", dc.Answered(), dc.LastDC())
	}

	if _, err := RunDC(ctxT(t, 10*time.Second), addr, secret.Key, front, -4); err != nil {
		t.Fatal(err)
	}
	if dc.LastDC() != 4 { // mtg берёт abs(dc) при переподключении к DC
		t.Fatalf("media DC: %d", dc.LastDC())
	}
}

func TestRun_ThroughRealMTG_WrongSecret(t *testing.T) {
	dc := newDC(t)
	secret := mtglib.GenerateSecret(front)
	// fronting: «настоящий сайт» отвечает обычным HTTP
	frontLn := listen(t)
	go func() {
		for {
			c, err := frontLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(make([]byte, 1024))
				_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			}()
		}
	}()
	addr := startProxy(t, secret, dc.Addr(), frontLn.Addr().(*net.TCPAddr).Port)

	wrong := secret.Key
	wrong[0] ^= 0xff
	start := time.Now()
	_, err := Run(ctxT(t, 10*time.Second), addr, wrong, front)
	if err == nil {
		t.Fatal("ожидали ошибку рукопожатия")
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("зависание: %v", time.Since(start))
	}
	if strings.Contains(err.Error(), hex.EncodeToString(wrong[:])) || strings.Contains(err.Error(), hex.EncodeToString(secret.Key[:])) {
		t.Fatalf("ключ в ошибке: %v", err)
	}
	if dc.Accepted() != 0 {
		t.Fatal("DC не должен был получить соединение")
	}
}

func TestRun_DCSilent(t *testing.T) {
	// DC принимает соединение, но не отвечает: прокси жив, resPQ нет.
	silent := listen(t)
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	secret := mtglib.GenerateSecret(front)
	addr := startProxy(t, secret, silent.Addr().String(), 1)
	res, err := Run(ctxT(t, 700*time.Millisecond), addr, secret.Key, front)
	if err == nil || res.DCResponded {
		t.Fatalf("ожидали ошибку без DCResponded, res=%+v err=%v", res, err)
	}
}

func TestParseUnencrypted(t *testing.T) {
	good := unencryptedMessage(4, []byte{1, 2, 3, 4})
	if id, b, err := parseUnencrypted(good); err != nil || id != 4 || len(b) != 4 {
		t.Fatalf("%v %v %v", id, b, err)
	}
	enc := slicesClone(good)
	enc[0] = 1 // auth_key_id != 0
	for name, p := range map[string][]byte{
		"короткий":     good[:10],
		"auth_key":     enc,
		"длина > тела": append(good[:16:16], 0xff, 0, 0, 0, 1, 2, 3, 4),
		"длина < 4":    unencryptedMessage(4, nil),
	} {
		if _, _, err := parseUnencrypted(p); err == nil {
			t.Errorf("%s: ожидали ошибку", name)
		}
	}
}

func slicesClone(b []byte) []byte { return append([]byte(nil), b...) }

func TestFakeDCEcho_ReturnsPacketsAsIs(t *testing.T) {
	d, _, err := NewFakeDCEcho()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	c, err := (&net.Dialer{}).DialContext(ctxT(t, 5*time.Second), "tcp", d.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	wire, send, recv, err := obfuscatedClient(nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 100, 16 << 10} { // не req_pq: произвольная нагрузка
		payload := bytes.Repeat([]byte{byte(size)}, size)
		pkt := append(binary.LittleEndian.AppendUint32(nil, uint32(size)), payload...)
		send.XORKeyStream(pkt, pkt)
		if _, err := c.Write(pkt); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 4+size)
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		recv.XORKeyStream(got, got)
		if binary.LittleEndian.Uint32(got) != uint32(size) || !bytes.Equal(got[4:], payload) {
			t.Fatalf("эхо size=%d не совпало", size)
		}
	}
	if d.Answered() != 3 {
		t.Fatalf("answered=%d, want 3", d.Answered())
	}
}
