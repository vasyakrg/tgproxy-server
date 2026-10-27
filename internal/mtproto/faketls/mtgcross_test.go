package faketls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/mtglib"
)

// Перекрёстная проверка: настоящий mtglib.Proxy принимает ровно те ClientHello,
// которые принимает наш Match (валидный → ответ ServerHello 0x16; иначе mtg
// пытается domain fronting на недоступный порт и закрывает соединение).

type noNet struct{}

func (noNet) Dial(string, string) (essentials.Conn, error) { return nil, errors.New("no dial") }
func (noNet) DialContext(context.Context, string, string) (essentials.Conn, error) {
	return nil, errors.New("no dial")
}
func (noNet) MakeHTTPClient(func(context.Context, string, string) (essentials.Conn, error)) *http.Client {
	return &http.Client{}
}
func (noNet) NativeDialer() *net.Dialer { return &net.Dialer{Timeout: time.Second} }

type nopEvents struct{}

func (nopEvents) Send(context.Context, mtglib.Event) {}

func mtgAccepts(t *testing.T, proxy *mtglib.Proxy, rec []byte) bool {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cc, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.ServeConn(essentials.WrapNetConn(sc))
	}()
	_ = cc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cc.Write(rec); err != nil {
		t.Fatal(err)
	}
	var first [1]byte
	_, rerr := io.ReadFull(cc, first[:])
	_ = cc.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn завис")
	}
	return rerr == nil && first[0] == 0x16
}

func TestMatchAgreesWithMTG(t *testing.T) {
	secret := mtglib.GenerateSecret(dom)
	skew := 5 * time.Second
	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:               secret,
		Network:              noNet{},
		AntiReplayCache:      antireplay.NewStableBloomFilter(antireplay.DefaultStableBloomFilterMaxSize, antireplay.DefaultStableBloomFilterErrorRate),
		IPBlocklist:          ipblocklist.NewNoop(),
		IPAllowlist:          ipblocklist.NewNoop(),
		EventStream:          nopEvents{},
		Logger:               noopLogger{},
		TolerateTimeSkewness: skew,
		IdleTimeout:          time.Minute,
		HandshakeTimeout:     5 * time.Second,
		DomainFrontingIP:     "127.0.0.1",
		DomainFrontingPort:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Shutdown)

	var key [16]byte
	copy(key[:], secret.Key[:])
	other := k1
	n := time.Now()
	cases := map[string][]byte{
		"valid":     hello(key, n, dom),
		"wrong key": hello(other, n, dom),
		"wrong sni": hello(key, n, "other.example.test"),
		"stale":     hello(key, n.Add(-time.Minute), dom),
		"future":    hello(key, n.Add(time.Minute), dom),
		"two names": hello(key, n, "a.example.test", dom),
		"no sni":    hello(key, n),
		"grease only": buildHello(genOpts{key: key[:], sni: []string{dom}, timestamp: n, sessionID: sid(),
			ciphers: []byte{0x0a, 0x0a}}),
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			var ours bool
			if h, err := Parse(rec); err == nil {
				_, ours = Match(h, [][16]byte{k2, key}, dom, time.Now(), skew)
			}
			if theirs := mtgAccepts(t, proxy, rec); ours != theirs {
				t.Fatalf("расхождение: faketls=%v mtg=%v", ours, theirs)
			}
		})
	}
	if !mtgAccepts(t, proxy, hello(key, time.Now(), dom)) {
		t.Fatal("sanity: mtg обязан принять валидный hello")
	}
}

type noopLogger struct{}

func (l noopLogger) Named(string) mtglib.Logger        { return l }
func (l noopLogger) BindInt(string, int) mtglib.Logger { return l }
func (l noopLogger) BindStr(string, string) mtglib.Logger {
	return l
}
func (l noopLogger) BindJSON(string, string) mtglib.Logger { return l }
func (noopLogger) Printf(string, ...any)                   {}
func (noopLogger) Info(string)                             {}
func (noopLogger) Warning(string)                          {}
func (noopLogger) Debug(string)                            {}
func (noopLogger) InfoError(string, error)                 {}
func (noopLogger) WarningError(string, error)              {}
func (noopLogger) DebugError(string, error)                {}
