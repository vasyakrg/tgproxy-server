package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// onReload вызывает fn на каждый SIGHUP до отмены ctx.
func onReload(ctx context.Context, fn func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				fn()
			}
		}
	}()
}
