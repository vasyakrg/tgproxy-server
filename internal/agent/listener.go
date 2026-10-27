package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 30 * time.Second
)

// dialListener — входящий mTLS-листенер режима dial (cfg.Listen.API).
type dialListener struct {
	a    *Agent
	srv  *http.Server
	done chan struct{}
}

// startListener поднимает HTTPS-сервер на готовом листенере. Фатальная ошибка
// Serve уходит в fatal (не блокируясь).
func (a *Agent) startListener(ctx context.Context, ln net.Listener, fatal func(error)) *dialListener {
	l := &dialListener{
		a: a,
		srv: &http.Server{
			Handler:           a.Handler(),
			TLSConfig:         a.tlsCfg.Clone(),
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      0,
			IdleTimeout:       idleTimeout,
			ErrorLog:          slogErrorLog(a),
			HTTP2:             &http.HTTP2Config{MaxReadFrameSize: transport.StreamMaxFrameSize},
			BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
		},
		done: make(chan struct{}),
	}
	go func() {
		defer close(l.done)
		if err := l.srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(fmt.Errorf("agent: serve: %w", err))
		}
	}()
	return l
}

// stop gracefully завершает листенер (порт освобождается сразу, in-flight
// запросы дорабатывают до shutdownTimeout).
func (l *dialListener) stop(parent context.Context) error {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(parent), shutdownTimeout)
	defer cancel()
	err := l.srv.Shutdown(sctx)
	if err != nil {
		_ = l.srv.Close()
	}
	closeIdle(l.a)
	<-l.done
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("agent: shutdown: %w", err)
	}
	return nil
}
