package app

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/geoip"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/ban"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// NewBanProtector собирает защиту от самоблокировки: trusted_proxies, агенты и сети правил читаются из БД
// в момент проверки (общий код сервера и CLI `tgproxy ban`). networks — дополнительный источник сетей
// (снимок Checker); nil — только БД.
func NewBanProtector(cfg *config.ServerConfig, st store.Store, networks func() []netip.Prefix) ban.StaticProtector {
	return ban.StaticProtector{
		Trusted: cfg.TrustedProxies,
		Agents:  func(ctx context.Context) ([]store.Agent, error) { return st.Agents().List(ctx) },
		Networks: func(ctx context.Context) ([]netip.Prefix, error) {
			var out []netip.Prefix
			if networks != nil {
				out = append(out, networks()...)
			}
			rules, err := st.AccessRules().List(ctx)
			if err != nil {
				return out, nil //nolint:nilerr // источник сетей из Checker уже есть; отказ БД не должен блокировать проверку
			}
			for _, r := range rules {
				if r.Enabled && r.RevokedAt == nil {
					out = append(out, r.CIDRs...)
				}
			}
			return out, nil
		},
	}
}

// wireBans открывает базу стран и собирает бан-менеджер (кэш банов, автобан, алерты пачкой).
func (s *Server) wireBans(ctx context.Context, cfg *config.ServerConfig) error {
	geo, err := geoip.Open(cfg.GeoIP.File)
	if err != nil {
		// битая база — не повод не стартовать: флаги просто не показываются
		s.logger.Warn("geoip database unavailable, country flags disabled", "error", redact.Error(err))
	}
	s.geo = geo
	if geo == nil && cfg.GeoIP.File != "" {
		s.logger.Info("geoip database not found, country flags disabled", "file", cfg.GeoIP.File)
	}

	s.banDigest = ban.NewDigest(func(ctx context.Context, bans []store.Ban) {
		if s.obs.eval != nil {
			s.obs.eval.AutoBans(ctx, bans)
		}
	})
	m, err := ban.New(ctx, s.st.Bans(), ban.Options{
		Config:  cfg.Ban,
		Protect: NewBanProtector(cfg, s.st, s.checker.Networks),
		Log:     s.logger,
		OnAutoBan: func(b store.Ban, count int) {
			api.RecordAutoBan(context.WithoutCancel(ctx), s.st.Audit(), s.logger, b, count)
			s.banDigest.Add(b)
		},
	})
	if err != nil {
		return fmt.Errorf("app: bans: %w", err)
	}
	s.bans = m
	return nil
}
