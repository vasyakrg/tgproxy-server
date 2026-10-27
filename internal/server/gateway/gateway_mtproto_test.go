package gateway

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// mtHandler — «агент» MTProto-класса: эхо-стримы и приём сигнала пула.
var mtHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut && r.URL.Path == transport.MTProtoPoolPath {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
})

func (e *env) connectMT(t *testing.T, cert tls.Certificate, h http.Handler) *tls.Conn {
	t.Helper()
	c := e.dialTLS(t, e.clientCfg(&cert, transport.ALPNMTProto))
	go (&http2.Server{}).ServeConn(c, &http2.ServeConnOpts{Handler: h}) //nolint:staticcheck // SA1019: ServeConn поверх готового соединения
	return c
}

func (e *env) waitMT(t *testing.T, id string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e.mt.Conns(id) == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("mt conns(%s)=%d, want %d", id, e.mt.Conns(id), n)
}

func (e *env) openStream(t *testing.T, id string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := e.mt.OpenMTProto(ctx, ref(id), 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestMTProtoALPNRequiresClientCert(t *testing.T) {
	e := newEnv(t)
	c := e.dialTLS(t, e.clientCfg(nil, transport.ALPNMTProto))
	expectClosed(t, c)
	if e.mt.Conns("a1") != 0 {
		t.Fatal("соединение без сертификата попало в пул")
	}
}

func TestMTProtoALPNRejectsUnknownAndDenied(t *testing.T) {
	e := newEnv(t)
	c := e.dialTLS(t, e.clientCfg(ptr(issueAgent(t, e.ca, "ghost")), transport.ALPNMTProto))
	expectClosed(t, c)

	cert := issueAgent(t, e.ca, "a1")
	if cert.Leaf == nil {
		t.Fatal("нет Leaf")
	}
	e.denied.Store(cert.Leaf.SerialNumber.String())
	c2 := e.dialTLS(t, e.clientCfg(&cert, transport.ALPNMTProto))
	expectClosed(t, c2)
}

func TestMTProtoStreamThroughGateway(t *testing.T) {
	e := newEnv(t)
	e.connectMT(t, issueAgent(t, e.ca, "a1"), mtHandler)
	e.waitMT(t, "a1", 1)
	if e.rp.Conns("a1") != 0 {
		t.Fatal("MTProto-соединение попало в пул Bot API")
	}
	s := e.openStream(t, "a1")
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(s, b); err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestMTProtoAndBotAPIClassesIndependent(t *testing.T) {
	e := newEnv(t)
	cert := issueAgent(t, e.ca, "a1")
	mtConn := e.connectMT(t, cert, mtHandler)
	e.connectAgent(t, cert, echo)
	e.waitMT(t, "a1", 1)
	e.waitConns(t, "a1", 1)
	s := e.openStream(t, "a1")

	_ = mtConn.Close() // обрыв MTProto-соединения
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("стрим жив после обрыва соединения")
	}
	e.waitMT(t, "a1", 0)
	e.waitConns(t, "a1", 1)
	if resp, err := e.post(t, "a1", nil); err != nil || resp.StatusCode != http.StatusOK { //nolint:bodyclose // закрывается в t.Cleanup
		t.Fatalf("Bot API после обрыва MTProto: %v", err)
	}
}

func TestMTProtoOwnConnLimitPerAgent(t *testing.T) {
	e := newEnv(t) // лимит MTProto-пула = 2, Bot API-пула = 2 (по умолчанию)
	cert := issueAgent(t, e.ca, "a1")
	c1 := e.connectMT(t, cert, mtHandler)
	e.waitMT(t, "a1", 1)
	e.connectMT(t, cert, mtHandler)
	e.waitMT(t, "a1", 2)
	e.connectAgent(t, cert, echo)
	e.waitConns(t, "a1", 1)
	e.connectMT(t, cert, mtHandler)
	expectClosed(t, c1)
	e.waitMT(t, "a1", 2)
	e.waitConns(t, "a1", 1)
}

func TestMTProtoPoolSignalThroughGateway(t *testing.T) {
	e := newEnv(t)
	e.connectMT(t, issueAgent(t, e.ca, "a1"), mtHandler)
	e.waitMT(t, "a1", 1)
	e.openStream(t, "a1")
	e.openStream(t, "a1") // max_streams_per_conn = 2
	select {
	case n := <-e.signals:
		if n != 2 {
			t.Fatalf("запрошено %d соединений, ожидалось 2", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("сигнал PUT /pool не дошёл до агента")
	}
}
