package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 30 * time.Second
)

// Handler возвращает корневой HTTP-обработчик агента (/tg/*, /_agent/*).
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(tgapi.AgentTGPrefix, a.handleTG)
	mux.HandleFunc("GET /_agent/healthz", a.handleHealthz)
	mux.HandleFunc("GET /_agent/status", a.handleStatus)
	mux.HandleFunc("POST /_agent/drain", a.handleDrain(true))
	mux.HandleFunc("DELETE /_agent/drain", a.handleDrain(false))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeAgentError(w, http.StatusNotFound, "", "tgproxy: not found")
	})
	return mux
}

// Run слушает cfg.Listen.API (mTLS) и работает до отмены ctx, затем
// gracefully завершается.
func (a *Agent) Run(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", a.cfg.Listen.API)
	if err != nil {
		return fmt.Errorf("agent: listen %s: %w", a.cfg.Listen.API, err)
	}
	return a.Serve(ctx, ln)
}

// Serve обслуживает готовый листенер (TLS оборачивается внутри).
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           a.Handler(),
		TLSConfig:         a.tlsCfg.Clone(),
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      0,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slogErrorLog(a),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("agent: serve: %w", err)
	case <-ctx.Done():
	}
	a.logger.Info("agent shutting down")
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	err := srv.Shutdown(sctx)
	if err != nil {
		_ = srv.Close()
	}
	closeIdle(a)
	if serr := <-errc; serr != nil && !errors.Is(serr, http.ErrServerClosed) {
		a.logger.Warn("agent serve ended", "err", serr)
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("agent: shutdown: %w", err)
	}
	return nil
}
