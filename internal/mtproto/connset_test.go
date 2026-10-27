package mtproto

import (
	"net"
	"testing"
	"time"
)

func TestConnSetDrainClosesAndRejects(t *testing.T) {
	c := newConnSet()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	if !c.enter(a) {
		t.Fatal("enter до drain должен проходить")
	}
	released := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = a.Read(buf) // разблокируется закрытием a
		c.leave(a)
		close(released)
	}()
	if !c.drain(2 * time.Second) {
		t.Fatal("drain не дождался выхода обработчика")
	}
	<-released
	x, y := net.Pipe()
	defer func() { _ = x.Close(); _ = y.Close() }()
	if c.enter(x) {
		t.Fatal("enter после drain должен отказывать")
	}
}

func TestConnSetDrainTimeout(t *testing.T) {
	c := newConnSet()
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	c.enter(a) // обработчик не вызывает leave
	if c.drain(50 * time.Millisecond) {
		t.Fatal("ожидался таймаут")
	}
	c.leave(a)
}
