package app

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/enroll"
	"github.com/vasyakrg/tgproxy-server/internal/server/gateway"
	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

const (
	defaultDenylistInterval = 10 * time.Second
	enrollGCPeriod          = time.Hour
	lookupTimeout           = 2 * time.Second
	healthPath              = "/_agent/healthz"
)

// pkiState — PKI-обвязка сервера (M5): CA в БД под KEK, denylist, reverse-канал,
// agent_gateway, enrollment, ротация/удаление агентов и SSH-установщик. nil —
// сервер работает со статическими agent_tls-файлами (без reverse и enrollment).
type pkiState struct {
	auth  *pki.Authority
	deny  *pki.Denylist
	pool  *transport.ReversePool
	caDER []byte

	gw      *gateway.Gateway
	enroll  *enroll.Service // nil — не удалось определить публичный URL gateway
	rotator *agents.Rotator
	remover *agents.Remover
	inst    *installer.Installer
}

// Authority — CA сервера (nil без PKI-режима).
func (s *Server) Authority() *pki.Authority {
	if s.pki == nil {
		return nil
	}
	return s.pki.auth
}

// Denylist — denylist серийников (nil без PKI-режима).
func (s *Server) Denylist() *pki.Denylist {
	if s.pki == nil {
		return nil
	}
	return s.pki.deny
}

// Enrollment — выпуск enrollment-токенов (nil, если PKI-режим выключен или
// публичный URL gateway неизвестен).
func (s *Server) Enrollment() *enroll.Service {
	if s.pki == nil {
		return nil
	}
	return s.pki.enroll
}

// Rotator — ротация сертификатов агентов (nil без PKI-режима).
func (s *Server) Rotator() *agents.Rotator {
	if s.pki == nil {
		return nil
	}
	return s.pki.rotator
}

// Remover — удаление агентов с отзывом сертификатов (nil без PKI-режима).
func (s *Server) Remover() *agents.Remover {
	if s.pki == nil {
		return nil
	}
	return s.pki.remover
}

// Installer — SSH-установщик агентов (nil без PKI-режима).
func (s *Server) Installer() *installer.Installer {
	if s.pki == nil {
		return nil
	}
	return s.pki.inst
}

// Registry — реестр агентов.
func (s *Server) Registry() *agents.Registry { return s.reg }

// Transport — транспорт к агентам (dial + reverse).
func (s *Server) Transport() *transport.Registry { return s.tr }

// useAuthority: PKI-режим включается, когда нет статических agent_tls и задан
// pki.kek_file; иначе — файловые материалы (agent_tls или pki.dir).
func useAuthority(cfg *config.ServerConfig) bool {
	return cfg.AgentTLS.CertFile == "" && cfg.PKI.KEKFile != ""
}

// ErrCANotInitialized — CA ещё не создан в БД.
var ErrCANotInitialized = errors.New("app: CA is not initialized (run: tgproxy pki kek-init, tgproxy pki init -c <server.yaml>)")

// initTransport строит транспорт к агентам: dial (+ reverse в PKI-режиме).
func (s *Server) initTransport(ctx context.Context, cfg *config.ServerConfig) error {
	if !useAuthority(cfg) {
		cert, pool, err := loadAgentTLS(cfg)
		if err != nil {
			return err
		}
		s.tr = transport.NewRegistry(map[config.AgentMode]transport.AgentTransport{
			config.AgentModeDial: transport.NewDial(cert, pool),
		})
		return nil
	}
	kek, err := pki.LoadKEK(cfg.PKI.KEKFile)
	if err != nil {
		return fmt.Errorf("app: load kek (create: tgproxy pki kek-init --out %s): %w", cfg.PKI.KEKFile, redact.Error(err))
	}
	if _, err := s.st.Certs().LoadCA(ctx); errors.Is(err, store.ErrNotFound) {
		return ErrCANotInitialized
	} else if err != nil {
		return fmt.Errorf("app: load CA: %w", err)
	}
	auth, err := pki.LoadOrInit(ctx, s.st.Certs(), kek, pki.Options{})
	if err != nil {
		return fmt.Errorf("app: load CA: %w", err)
	}
	deny, err := pki.NewDenylist(ctx, s.st.Certs())
	if err != nil {
		return fmt.Errorf("app: denylist: %w", err)
	}
	blk, _ := pem.Decode(auth.CertPEM())
	if blk == nil {
		return errors.New("app: CA certificate is not PEM")
	}
	p := &pkiState{auth: auth, deny: deny, caDER: blk.Bytes}
	p.pool = transport.NewReversePool(
		transport.WithOnAttach(func(id string, n int) { s.setReverseConns(id, n) }),
		transport.WithOnDetach(func(id string, n int) { s.setReverseConns(id, n) }),
		transport.WithOnDown(func(id string) { s.setReverseConns(id, 0) }),
	)
	dial := transport.NewDial(tls.Certificate{}, auth.Pool(),
		transport.WithClientCertFunc(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { //nolint:contextcheck // колбэк рукопожатия живёт вне запроса
			return auth.ServerCert(context.Background())
		}),
		transport.WithPeerChecks(deny.Check),
	)
	s.pki = p
	s.tr = transport.NewRegistry(map[config.AgentMode]transport.AgentTransport{
		config.AgentModeDial:    dial,
		config.AgentModeReverse: p.pool,
		config.AgentModeBoth:    transport.Both{Dial: dial, Reverse: p.pool},
	})
	return nil
}

func (s *Server) setReverseConns(id string, n int) {
	if s.obs != nil && s.obs.m != nil {
		s.obs.m.SetAgentReverseConns(id, n)
	}
}

// gatewayCert отдаёт серверный сертификат с CA вторым элементом цепочки:
// enroll-клиент пиннит CA по отпечатку из цепочки.
func (p *pkiState) gatewayCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	leaf, err := p.auth.ServerCert(context.Background())
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{leaf.Certificate[0], p.caDER},
		PrivateKey:  leaf.PrivateKey,
		Leaf:        leaf.Leaf,
	}, nil
}

// repoLookup — gateway.AgentLookup поверх БД: только что созданный
// enrollment-агент виден сразу, без ожидания Refresh реестра.
type repoLookup struct{ repo store.AgentRepo }

func (l repoLookup) Known(id string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	a, err := l.repo.Get(ctx, id)
	if err != nil {
		return "", false
	}
	return string(a.Mode), true
}

// agentHealth — installer.HealthChecker: GET /_agent/healthz по mTLS (агент
// проверяет доступ к Telegram).
type agentHealth struct{ tr transport.AgentTransport }

func (h agentHealth) Check(ctx context.Context, agentURL, agentID string) error {
	u, err := url.Parse(agentURL)
	if err != nil {
		return fmt.Errorf("health: bad agent url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthPath, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := h.tr.RoundTrip(ctx, transport.AgentRef{ID: agentID, URL: u, Mode: config.AgentModeDial}, req)
	if err != nil {
		return fmt.Errorf("health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: agent answered %d", resp.StatusCode)
	}
	return nil
}

// gatewayURL — публичный https-URL agent_gateway для команды enrollment:
// явный ServerOptions.GatewayURL, иначе хост server.public_base_url (или
// не-wildcard хост listen.agent_gateway) + порт listen.agent_gateway.
func gatewayURL(cfg *config.ServerConfig, override string) (string, bool) {
	if override != "" {
		return override, true
	}
	lhost, port, err := net.SplitHostPort(cfg.Listen.AgentGateway)
	if err != nil || port == "" {
		return "", false
	}
	host := ""
	if u, perr := url.Parse(cfg.Server.PublicBaseURL); perr == nil {
		host = u.Hostname()
	}
	if host == "" {
		if ip := net.ParseIP(lhost); lhost == "" || (ip != nil && ip.IsUnspecified()) {
			return "", false
		}
		host = lhost
	}
	return "https://" + net.JoinHostPort(host, port), true
}

// wirePKI подключает сервисы PKI-режима; вызывается после wire (нужны реестр и метрики).
func (s *Server) wirePKI(cfg *config.ServerConfig) error {
	p := s.pki
	if p == nil {
		return nil
	}
	gwOpts := []gateway.Option{gateway.WithChecks(p.deny.Check), gateway.WithLogger(s.logger)}
	if gwURL, ok := gatewayURL(cfg, s.opts.GatewayURL); ok {
		svc, err := enroll.New(enroll.Config{
			Enrollments: s.st.Enrollments(), Agents: s.st.Agents(), Audit: s.st.Audit(), CA: p.auth,
			GatewayURL: gwURL, Logger: s.logger, Notify: s.onEnrolled, Observe: s.obs.m.EnrollAttempt,
		})
		if err != nil {
			return fmt.Errorf("app: enroll: %w", err)
		}
		p.enroll = svc
		gwOpts = append(gwOpts, gateway.WithEnrollHandler(svc.Handler()))
	} else {
		s.logger.Warn("enrollment disabled: cannot derive public agent_gateway url (set server.public_base_url)")
	}
	gw, err := gateway.New(gateway.Config{
		GetCertificate: p.gatewayCert, CA: p.auth.Pool(), Lookup: repoLookup{s.st.Agents()}, Pool: p.pool,
	}, gwOpts...)
	if err != nil {
		return fmt.Errorf("app: gateway: %w", err)
	}
	p.gw = gw

	if p.rotator, err = agents.NewRotator(agents.RotatorConfig{
		Source: s.reg, Caller: s.tr, Signer: p.auth, Revoker: p.deny, Certs: s.st.Certs(),
		Interval: s.opts.RotateInterval, Log: s.logger, OnEvent: s.onRotation,
	}); err != nil {
		return fmt.Errorf("app: rotator: %w", err)
	}
	if p.remover, err = agents.NewRemover(agents.RemoverConfig{
		Registry: s.reg, Repo: s.st.Agents(), Revoker: p.deny, Status: s.tr.Status, Log: s.logger,
	}); err != nil {
		return fmt.Errorf("app: remover: %w", err)
	}
	return s.wireInstaller(cfg)
}

func (s *Server) wireInstaller(cfg *config.ServerConfig) error {
	dataDir := filepath.Dir(cfg.Store.SQLitePath)
	key, err := installer.LoadOrCreateServerKey(filepath.Join(dataDir, "ssh"))
	if err != nil {
		return fmt.Errorf("app: installer key: %w", err)
	}
	icfg := installer.Config{
		Store: s.st, CA: s.pki.auth, Health: agentHealth{s.tr}, ServerKey: key,
		PackagesDir: filepath.Join(dataDir, "packages"), Logger: s.logger,
	}
	if s.obs.eval != nil {
		icfg.Alerter = s.obs.eval
	}
	if s.pki.inst, err = installer.New(icfg); err != nil {
		return fmt.Errorf("app: installer: %w", err)
	}
	return nil
}

// onEnrolled: реестр подхватывает нового агента сразу, админам уходит алерт agent_enrolled.
func (s *Server) onEnrolled(ctx context.Context, agentID, _ string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readyProbeTimeout)
	defer cancel()
	if err := s.reg.Refresh(rctx); err != nil {
		s.logger.Warn("agent registry refresh after enroll failed", "agent", agentID, "error", redact.Error(err))
	}
	if s.obs.eval != nil {
		s.obs.eval.AgentEnrolled(ctx, agentID)
	}
}

func (s *Server) onRotation(ev agents.RotationEvent) {
	if ev.OK {
		s.logger.Info("agent certificate rotated", "agent", ev.AgentID, "serial", ev.NewSerial)
		return
	}
	s.logger.Warn("agent certificate rotation failed", "agent", ev.AgentID, "error", redact.Error(ev.Err))
}

// runPKI запускает фоновые задачи PKI: обновление denylist, ротацию сертификатов,
// очистку просроченных enrollment-токенов.
func (s *Server) runPKI(ctx context.Context) (wait func()) {
	p := s.pki
	if p == nil {
		return func() {}
	}
	interval := s.opts.DenylistInterval
	if interval <= 0 {
		interval = defaultDenylistInterval
	}
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}
	run(func() {
		p.deny.Run(ctx, interval, func(err error) {
			s.logger.Warn("denylist refresh failed", "error", redact.Error(err))
		})
	})
	run(func() { p.rotator.Run(ctx) })
	run(func() {
		t := time.NewTicker(enrollGCPeriod)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := s.st.Enrollments().DeleteExpired(ctx, time.Now()); err != nil {
					s.logger.Warn("delete expired enrollments failed", "error", redact.Error(err))
				}
			}
		}
	})
	return wg.Wait
}

// GatewayURL — публичный URL agent_gateway для команды enrollment (для CLI).
func GatewayURL(cfg *config.ServerConfig, override string) (string, bool) {
	return gatewayURL(cfg, override)
}
