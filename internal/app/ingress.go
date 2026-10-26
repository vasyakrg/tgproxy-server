package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/tlsin"
)

const ingressReportTimeout = 5 * time.Second

// newIngress создаёт провайдера TLS входа. События и метрики адресуются в
// s.obs лениво: провайдер создаётся до wireObs, а начальное состояние
// публикуется в reportIngress после него.
func (s *Server) newIngress(cfg *config.ServerConfig) (tlsin.Provider, error) {
	proxyAddr := cfg.Listen.Proxy
	if ln := s.opts.ProxyListener; ln != nil {
		proxyAddr = ln.Addr().String() // фактический адрес (тесты)
	}
	p, err := tlsin.New(cfg.TLS,
		tlsin.WithLogger(s.logger),
		tlsin.WithOffGuard(cfg.TrustedProxies, proxyAddr),
		tlsin.WithEvents(s.onIngressEvent),
		tlsin.WithMetrics(s.setIngressNotAfter),
	)
	if err != nil {
		return nil, fmt.Errorf("app: ingress tls: %w", redact.Error(err))
	}
	s.http01Addr = cfg.TLS.ACME.HTTP01Listen
	return p, nil
}

func (s *Server) setIngressNotAfter(t time.Time) {
	if s.obs != nil && s.obs.m != nil {
		s.obs.m.SetIngressCertNotAfter(t)
	}
}

// onIngressEvent передаёт состояние сертификата входа в Evaluator
// (ingress_cert_invalid / ingress_cert_expiring, с авто-resolve).
func (s *Server) onIngressEvent(ev tlsin.Event) {
	s.reportEvent(context.Background(), ev)
}

func (s *Server) reportEvent(ctx context.Context, ev tlsin.Event) {
	if s.obs == nil || s.obs.eval == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, ingressReportTimeout)
	defer cancel()
	s.obs.eval.ReportIngressCert(ctx, ev.NotAfter, ev.Err)
}

// reportIngress публикует начальное состояние сертификата (события, пришедшие
// при создании провайдера, терялись: obs ещё не был собран).
func (s *Server) reportIngress(ctx context.Context) {
	if na := s.ingress.Info().NotAfter; !na.IsZero() {
		s.setIngressNotAfter(na)
		s.reportEvent(ctx, tlsin.Event{Type: tlsin.EventReloaded, NotAfter: na})
	}
}

// reloadIngress — SIGHUP: перечитать сертификат входа (ошибка уже учтена
// событием cert_invalid, прежний сертификат остаётся).
func (s *Server) reloadIngress() {
	if err := s.ingress.Reload(); err != nil {
		s.logger.Error("ingress certificate reload rejected, keeping previous", "error", redact.Error(err))
	}
}

// runIngress запускает фоновую работу провайдера и, для acme с заданным
// tls.acme.http01_listen, HTTP-01 листенер. Возвращает функцию ожидания
// завершения после отмены ctx.
func (s *Server) runIngress(ctx context.Context) func() {
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := s.ingress.Run(ctx); err != nil {
			s.logger.Error("ingress tls provider stopped", "error", redact.Error(err))
		}
	})
	if h, ok := s.ingress.(tlsin.HTTP01); ok && s.http01Addr != "" {
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp", s.http01Addr)
		if err != nil {
			// TLS-ALPN-01 продолжает работать; HTTP-01 недоступен.
			s.logger.Error("acme http-01 listener failed", "addr", s.http01Addr, "error", err)
		} else {
			srv := newHTTPServer(h.HTTPHandler(nil), nil, s.logger)
			wg.Go(func() {
				if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					s.logger.Error("acme http-01 server stopped", "error", err)
				}
			})
			wg.Go(func() {
				<-ctx.Done()
				_ = srv.Close()
			})
			s.logger.Info("acme http-01 listener started", "addr", ln.Addr().String())
		}
	}
	return wg.Wait
}

// ingressTLSConfig — TLS-конфиг входа (nil для tls.mode=off).
func (s *Server) ingressTLSConfig() *tls.Config { return s.ingress.TLSConfig() }
