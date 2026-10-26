package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/server/proxy"
	"github.com/vasyakrg/tgproxy-server/internal/server/router"
	"github.com/vasyakrg/tgproxy-server/internal/server/web"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const (
	sessionGCPeriod = 10 * time.Minute
	recentEvents    = 50
	totpIssuer      = "tgproxy"
)

// webState — веб-UI админки (M4): пользователи, аутентификация и общий обработчик.
type webState struct {
	users   *auth.Users
	auth    *auth.Auth
	handler http.Handler
	update  *updateState // периодическая проверка обновлений (nil — не запускается)
}

// ruleRecorder дополняет метрики прокси счётчиками по правилам доступа.
type ruleRecorder struct {
	proxy.Recorder
	stats *ruleStats
}

func (r ruleRecorder) RequestDone(rule, method string, code int) {
	r.Recorder.RequestDone(rule, method, code)
	r.stats.Observe(rule)
}

// outboxEvents — лента «События» на Обзоре из последних элементов outbox.
type outboxEvents struct{ repo store.OutboxRepo }

func (o outboxEvents) RecentEvents(ctx context.Context, limit int) ([]screens.Event, error) {
	items, err := o.repo.Recent(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]screens.Event, 0, len(items))
	for _, it := range items {
		out = append(out, screens.Event{
			At: it.CreatedAt, AgentID: it.AgentID, Type: it.Type, State: string(it.State),
			Text: it.Text, Sent: it.SentAt != nil,
		})
	}
	return out, nil
}

// accessEnv — AccessEnv экрана «Доступ»: base URL из актуального конфига и счётчики по правилам.
type accessEnv struct{ s *Server }

func (e accessEnv) PublicBaseURL() string {
	return strings.TrimRight(e.s.cur.Load().cfg.Server.PublicBaseURL, "/")
}

func (e accessEnv) RuleStats(name string) (int64, time.Time, bool) { return e.s.rstats.RuleStats(name) }

// liveInflight отдаёт живое число запросов в полёте (общий счётчик роутера).
type liveInflight struct{ t *router.Inflight }

func (l liveInflight) LiveInflight() int { return l.t.Total() }

// muxMounter подключает маршруты JSON API к отдельному ServeMux.
type muxMounter struct{ mux *http.ServeMux }

func (m muxMounter) Mount(pattern string, h http.Handler) { m.mux.Handle(pattern, h) }

// refreshOnWrite вызывает refresh перед отправкой ответа на изменяющий запрос (после коммита в БД).
func refreshOnWrite(next http.Handler, refresh func()) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&refreshWriter{ResponseWriter: w, refresh: refresh}, r)
	})
}

type refreshWriter struct {
	http.ResponseWriter
	once    sync.Once
	refresh func()
}

func (w *refreshWriter) fire(code int) {
	if code < http.StatusBadRequest {
		w.once.Do(w.refresh)
	}
}

func (w *refreshWriter) WriteHeader(code int) {
	w.fire(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *refreshWriter) Write(b []byte) (int, error) {
	w.fire(http.StatusOK)
	return w.ResponseWriter.Write(b)
}

func (w *refreshWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// wireWeb собирает веб-UI админки. Без users_file или pki.kek_file UI не поднимается
// (остаются /healthz и /readyz) — так работают CLI и тесты без админки.
func (s *Server) wireWeb(cfg *config.ServerConfig) error {
	if cfg.Auth.UsersFile == "" || cfg.PKI.KEKFile == "" {
		s.logger.Warn("web ui disabled: auth.users_file and pki.kek_file are required")
		return nil
	}
	kek, err := pki.LoadKEK(cfg.PKI.KEKFile)
	if err != nil {
		return fmt.Errorf("app: load kek (create: tgproxy pki kek-init --out %s): %w", cfg.PKI.KEKFile, redact.Error(err))
	}
	users, err := auth.LoadUsers(cfg.Auth.UsersFile, s.logger)
	if err != nil {
		return fmt.Errorf("app: load users: %w", redact.Error(err))
	}
	opts := auth.Options{
		Users: users, Store: s.st, TOTP: auth.NewTOTP(kek, s.st.RateState(), totpIssuer),
		AllowPasswordOnly: cfg.Auth.AllowPasswordOnly, Logger: s.logger, ClientIP: s.checker.ClientIP,
	}
	if s.obs.eval != nil {
		opts.Notifier = s.obs.eval
	}
	if cfg.Auth.AllowPasswordOnly {
		s.logger.Warn("auth.allow_password_only is enabled: users without TOTP log in by password only (DEV ONLY)")
	}
	a := auth.New(opts)

	rt := web.NewRouter(web.Deps{Version: buildinfo.Version, Session: screens.NewSessionProvider(a), Logger: s.logger})
	protected := func(h http.Handler) http.Handler { return auth.Protect(a.RequireAuth(h)) }
	refresh := func() {
		ctx, cancel := context.WithTimeout(context.Background(), readyProbeTimeout)
		defer cancel()
		if err := s.checker.Refresh(ctx); err != nil {
			s.logger.Warn("access rules refresh after change failed", "error", redact.Error(err))
		}
	}

	screens.MountLogin(rt, screens.LoginDeps{Auth: a, ClientIP: s.checker.ClientIP, Logger: s.logger})
	svc := api.NewAccessService(s.st.AccessRules(), s.st.Audit(), s.logger, nil)
	env := accessEnv{s}
	screens.MountAccess(accessRouter{rt, refresh}, screens.AccessDeps{
		Auth: a, Service: svc, Env: env, Bots: s.obs.top, ClientIP: s.checker.ClientIP, Logger: s.logger,
	})
	rt.SetOverview(protected(screens.NewOverview(screens.OverviewDeps{
		Shell: rt, Stats: s.obs.hq, Agents: s.reg, Events: outboxEvents{s.st.Outbox()}, Live: liveInflight{s.obs.inflight},
		ServerVersion: buildinfo.Version, Log: s.logger,
	})))
	rt.Mount("GET /errors", protected(screens.NewErrors(screens.ErrorsDeps{
		Shell: rt, Source: s.obs.hq, Agents: s.reg, Log: s.logger,
	})))
	agentsAPI := s.mountAgents(rt, a, cfg)
	sysAPI, sysState, err := s.mountSystem(rt, a, users, cfg)
	if err != nil {
		return err
	}

	apiMux := http.NewServeMux()
	a.Routes(apiMux)
	(&api.AccessAPI{Service: svc, ClientIP: s.checker.ClientIP, BaseURL: env.PublicBaseURL, Stats: env.RuleStats}).
		Routes(muxMounter{apiMux}, wrapRefresh(protected, refresh))
	(&api.StatsAPI{Stats: s.obs.hq, Agents: s.reg, Live: liveInflight{s.obs.inflight}, Log: s.logger}).Routes(apiMux, protected)
	(&api.ErrorsAPI{Source: s.obs.hq, Log: s.logger}).Routes(apiMux, protected)
	agentsAPI(apiMux, protected)
	sysAPI(apiMux, protected)
	rt.Mount("/api/v1/", apiMux)

	s.web = &webState{users: users, auth: a, handler: rt, update: sysState}
	return nil
}

// wrapRefresh добавляет к обёртке защиты перечитывание правил после изменений.
func wrapRefresh(protected func(http.Handler) http.Handler, refresh func()) api.Wrap {
	return func(h http.Handler) http.Handler { return protected(refreshOnWrite(h, refresh)) }
}

// accessRouter подменяет Mount, оборачивая обработчики экрана «Доступ» в refreshOnWrite.
type accessRouter struct {
	*web.Router
	refresh func()
}

func (r accessRouter) Mount(pattern string, h http.Handler) {
	r.Router.Mount(pattern, refreshOnWrite(h, r.refresh))
}

// runWeb запускает слежение за users-файлом и очистку просроченных сессий.
func (s *Server) runWeb(ctx context.Context) (wait func()) {
	if s.web == nil {
		return func() {}
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		s.web.update.run(ctx, s)
	}()
	go func() {
		defer wg.Done()
		if err := s.web.users.Watch(ctx); err != nil {
			s.logger.Error("users file watcher stopped", "error", redact.Error(err))
		}
	}()
	go func() {
		defer wg.Done()
		t := time.NewTicker(sessionGCPeriod)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := s.st.Sessions().DeleteExpired(ctx); err != nil {
					s.logger.Warn("delete expired sessions failed", "error", redact.Error(err))
				} else if n > 0 {
					s.logger.Debug("expired sessions deleted", "count", n)
				}
			}
		}
	}()
	return wg.Wait
}

// reloadUsers перечитывает users-файл по SIGHUP.
func (s *Server) reloadUsers() {
	if s.web == nil {
		return
	}
	if err := s.web.users.Reload(); err != nil {
		s.logger.Error("users file reload rejected, keeping previous", "error", redact.Error(err))
	}
}

// observedInstaller считает итоги задач установки (tgp_install_jobs_total{result}) поверх installer.Installer.
type observedInstaller struct {
	*installer.Installer
	observe func(result string)
}

// installWatchTimeout — потолок ожидания итога задачи установки для метрики.
const installWatchTimeout = time.Hour

func (o observedInstaller) Install(ctx context.Context, req installer.Request) (string, error) {
	id, err := o.Installer.Install(ctx, req)
	if err != nil {
		o.observe("rejected")
		return id, err
	}
	go func() { //nolint:gosec,contextcheck // наблюдение за задачей живёт дольше HTTP-запроса
		wctx, cancel := context.WithTimeout(context.Background(), installWatchTimeout)
		defer cancel()
		_ = o.Wait(wctx, id)
		st, serr := o.Status(wctx, id)
		switch {
		case serr != nil:
			o.observe("unknown")
		case st.State == store.InstallDone:
			o.observe("ok")
		default:
			o.observe("failed")
		}
	}()
	return id, nil
}

// mountAgents подключает экран «Агенты» и мастер; возвращает функцию монтирования REST API.
// Без PKI-режима (статические agent_tls) нет ротации, удаления, смены режима, установки и enrollment:
// экран показывает эти части как «не настроено».
func (s *Server) mountAgents(rt *web.Router, a *auth.Auth, cfg *config.ServerConfig) func(*http.ServeMux, func(http.Handler) http.Handler) {
	acfg := api.AgentsConfig{
		Agents: s.reg, Drainer: s.reg, Weight: s.reg, Audit: s.st.Audit(), Logger: s.logger,
	}
	deps := screens.AgentsDeps{
		Auth: a, ServerVersion: buildinfo.Version, ClientIP: s.checker.ClientIP, Logger: s.logger,
		Rollout: func() *screens.RolloutHandle { return s.rolloutUI.Load() },
	}
	if p := s.pki; p != nil {
		acfg.Rotator, acfg.Remover, acfg.Reverse = p.rotator, p.remover, p.pool
		acfg.Mode = api.TransportModeSetter{Agents: s.st.Agents(), Refs: s.reg, Transport: s.tr, Refresh: s.reg.Refresh}
		if u, ok := gatewayURL(cfg, s.opts.GatewayURL); ok {
			acfg.GatewayURL = u
		}
		deps.Install = api.NewInstallService(api.InstallConfig{
			Installer: observedInstaller{Installer: p.inst, observe: s.obs.m.InstallJob},
			HostKeys:  s.st.HostKeys(), Audit: s.st.Audit(), Logger: s.logger,
		})
		if p.enroll != nil {
			deps.Enroll = api.NewEnrollService(api.EnrollConfig{
				Issuer: p.enroll, Enrollments: s.st.Enrollments(), Audit: s.st.Audit(), Logger: s.logger,
			})
		}
	}
	deps.Service = api.NewAgentsService(acfg)
	screens.MountAgents(rt, deps)
	return func(mux *http.ServeMux, wrap func(http.Handler) http.Handler) {
		w := api.Wrap(wrap)
		(&api.AgentsAPI{Service: deps.Service, ClientIP: s.checker.ClientIP, Log: s.logger}).Routes(mux, w)
		if deps.Install != nil {
			(&api.InstallAPI{Service: deps.Install, ClientIP: s.checker.ClientIP, Log: s.logger}).Routes(mux, w)
		}
		if deps.Enroll != nil {
			(&api.EnrollAPI{Service: deps.Enroll, ClientIP: s.checker.ClientIP, Log: s.logger}).Routes(mux, w)
		}
	}
}

// botIDOf — публичная часть токена бота (до «:»); сам токен в UI не попадает.
func botIDOf(token string) string {
	id, _, _ := strings.Cut(token, ":")
	return id
}

// mountSystem подключает экран «Система» (обновление сервера и уведомления) и возвращает
// функцию монтирования его JSON API.
func (s *Server) mountSystem(rt *web.Router, a *auth.Auth, users *auth.Users, cfg *config.ServerConfig) (
	func(*http.ServeMux, func(http.Handler) http.Handler), *updateState, error,
) {
	upd, err := s.wireUpdate(cfg)
	if err != nil {
		return nil, nil, err
	}
	ncfg := api.NotificationsConfig{
		Toggles: s.obs.toggles, Admins: users, Audit: s.st.Audit(), Outbox: s.st.Outbox(), Logger: s.logger,
	}
	if s.obs.notifier != nil {
		ncfg.Sender, ncfg.BotID = s.obs.notifier, botIDOf(cfg.Notify.BotToken.Reveal())
		if s.obs.deliv != nil {
			ncfg.Wake = s.obs.deliv.Wake
		}
	}
	nsvc := api.NewNotificationsService(ncfg)
	screens.MountSystem(rt, screens.SystemDeps{
		Auth: a, Update: upd.svc, Notify: nsvc, ClientIP: s.checker.ClientIP, Logger: s.logger,
	})
	return func(mux *http.ServeMux, wrap func(http.Handler) http.Handler) {
		w := api.Wrap(wrap)
		(&api.SystemAPI{Service: upd.svc, ClientIP: s.checker.ClientIP, Log: s.logger}).Routes(mux, w)
		(&api.NotificationsAPI{Service: nsvc, ClientIP: s.checker.ClientIP, Log: s.logger}).Routes(mux, w)
	}, upd, nil
}
