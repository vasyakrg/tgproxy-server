package app

import (
	"context"
	"fmt"
	"net/http"
	"runtime"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/rollout"
	"github.com/vasyakrg/tgproxy-server/internal/server/updater"
	"github.com/vasyakrg/tgproxy-server/internal/server/web"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
)

// Rollout — раскатка версий на агентов (nil без PKI-режима или без публичного URL agent_gateway).
func (s *Server) Rollout() *rollout.Manager { return s.rollout }

// routerRegistrar подключает маршруты JSON API прямо к маршрутизатору веб-UI: пути
// POST /api/v1/rollouts, GET /api/v1/rollouts/current, POST /api/v1/agents/{id}/update и т.д.
// длиннее общего префикса /api/v1/ и обрабатываются раньше.
type routerRegistrar struct{ rt *web.Router }

func (r routerRegistrar) Handle(pattern string, h http.Handler) { r.rt.Mount(pattern, h) }

// wireRollout собирает Manager раскатки и подключает его REST API. Агенты качают релиз с
// agent_gateway (GET /_agent_gw/packages/…) одинаково для dial и reverse, поэтому нужен
// публичный URL gateway; без PKI-режима раскатка не настраивается.
func (s *Server) wireRollout(ctx context.Context, cfg *config.ServerConfig) error {
	if s.pki == nil {
		return nil
	}
	gwURL, ok := gatewayURL(cfg, s.opts.GatewayURL)
	if !ok {
		s.logger.Warn("agent rollout disabled: cannot derive public agent_gateway url (set server.public_base_url)")
		return nil
	}
	downloads := cfg.Update.Downloads()
	if downloads == "" {
		s.logger.Warn("agent rollout disabled: update.staging_dir / update.downloads_dir is not set")
		return nil
	}
	rc := rollout.Config{
		Store: s.st, Registry: s.reg, Transport: s.tr,
		Packages:   updater.Cache{Dir: downloads, Arch: runtime.GOARCH},
		GatewayURL: gwURL, Logger: s.logger,
	}
	if s.obs.eval != nil {
		rc.Alerter = s.obs.eval
	}
	m, err := rollout.New(rc)
	if err != nil {
		return fmt.Errorf("app: rollout: %w", err)
	}
	if err := m.Recover(ctx); err != nil {
		m.Close()
		return fmt.Errorf("app: rollout recover: %w", redact.Error(err))
	}
	s.rollout = m
	pkgs := rc.Packages
	if s.web == nil {
		return nil
	}
	rt, ok := s.web.handler.(*web.Router)
	if !ok {
		return nil
	}
	protected := api.Wrap(func(h http.Handler) http.Handler { return auth.Protect(s.web.auth.RequireAuth(h)) })
	rapi := &api.RolloutAPI{Manager: m, Audit: s.st.Audit(), ClientIP: s.checker.ClientIP, Log: s.logger}
	rapi.Routes(routerRegistrar{rt}, protected)
	s.rolloutUI.Store(&screens.RolloutHandle{API: rapi, Packages: pkgs})
	return nil
}
