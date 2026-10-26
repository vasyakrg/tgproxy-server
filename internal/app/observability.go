package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/metrics"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/history"
	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
	"github.com/vasyakrg/tgproxy-server/internal/server/router"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// obs — метрики, история и алерты сервера (M3).
type obs struct {
	reg      *prometheus.Registry
	m        *metrics.Server
	top      *metrics.TopBots
	coll     *history.Collector
	errlog   *history.ErrorLog
	hq       *history.Query
	inflight *router.Inflight

	metricsHandler http.Handler // nil — листенер метрик не поднимается

	toggles  *notify.Toggles  // переключатели типов событий (всегда есть)
	notifier *notify.Notifier // nil — уведомления выключены
	deliv    *notify.Deliverer
	eval     *notify.Evaluator
}

// routerSender отправляет служебные запросы через актуальный роутер
// (снимок подменяется при reload).
type routerSender struct{ s *Server }

func (r routerSender) Do(ctx context.Context, req *http.Request, route tgapi.Route) (*http.Response, error) {
	return r.s.cur.Load().router.Do(ctx, req, route)
}

// isLoopbackAddr сообщает, что host:port слушает только loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// newMetricsHandler защищает /metrics bearer-ом; без bearer допустим только
// loopback-адрес, иначе ошибка старта.
func newMetricsHandler(reg *prometheus.Registry, bearer, addr string) (http.Handler, error) {
	h, err := metrics.NewHandler(reg, bearer, isLoopbackAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("app: metrics listener %q: %w", addr, err)
	}
	return h, nil
}

// wireObs создаёт реестр метрик, историю и (если задан токен) уведомления.
func (s *Server) wireObs(cfg *config.ServerConfig) error {
	o := &obs{top: metrics.NewTopBots(0), coll: history.NewCollector(), inflight: &router.Inflight{}}
	o.reg, o.m = metrics.NewServerRegistry()
	o.errlog = history.NewErrorLog(s.st.Errors(), 0)
	o.errlog.Log = s.logger
	o.hq = &history.Query{History: s.st.History(), ErrorRepo: s.st.Errors()}

	addr := cfg.Listen.Metrics
	if s.opts.MetricsListener != nil {
		addr = s.opts.MetricsListener.Addr().String()
	}
	if addr != "" {
		h, err := newMetricsHandler(o.reg, cfg.Metrics.Bearer.Reveal(), addr)
		if err != nil {
			return err
		}
		o.metricsHandler = h
	}
	o.toggles = notify.NewToggles(s.st.Settings())
	s.obs = o

	token := cfg.Notify.BotToken.Reveal()
	if !cfg.Notify.Enabled() || token == "" {
		s.logger.Info("notifications disabled: notify.bot_token_file is not set")
		return nil
	}
	o.notifier = notify.NewNotifier(s.st.Outbox(), notify.Options{
		RepeatInterval: cfg.Notify.RepeatInterval, MaxPerMinute: cfg.Notify.MaxPerMinute, Logger: s.logger,
		Enabled: o.toggles.Enabled})
	o.deliv = notify.NewDeliverer(notify.DeliverOptions{
		Outbox: s.st.Outbox(), Sender: routerSender{s}, Token: token, Metrics: o.m, Logger: s.logger,
		Timeout: cfg.Notify.DeliveryTimeout, Poll: s.opts.NotifyPoll,
		Load: func() ([]notify.Recipient, error) { return notify.LoadRecipients(s.cur.Load().cfg.Auth.UsersFile) },
	})
	o.eval = notify.NewEvaluator(notify.EvalOptions{
		Registry: s.reg, Alerter: o.notifier, Errors: o.hq, CertWarn: cfg.Notify.CertExpiryWarn, Logger: s.logger})
	return nil
}

// syncAgentMetrics зеркалит состояние реестра в agent_up и пишет события в лог.
func (s *Server) syncAgentMetrics(ctx context.Context, events <-chan agents.Event) {
	modes := map[string]string{}
	refresh := func() {
		for _, st := range s.reg.List() {
			modes[st.Agent.ID] = string(st.Agent.Mode)
			s.obs.m.SetAgentUp(st.Agent.ID, string(st.Agent.Mode), st.Up)
		}
	}
	refresh()
	for ev := range events {
		lvl := slog.LevelInfo
		if ev.Type == agents.AgentDown {
			lvl = slog.LevelWarn
		}
		s.logger.Log(ctx, lvl, "agent event", "type", string(ev.Type), "agent", ev.AgentID)
		switch ev.Type {
		case agents.AgentRemoved:
			s.obs.m.ForgetAgent(ev.AgentID)
			delete(modes, ev.AgentID)
		case agents.AgentUp:
			s.obs.m.SetAgentUp(ev.AgentID, modeOf(s.reg, ev.AgentID, modes), true)
			if s.obs.deliv != nil {
				s.obs.deliv.Wake()
			}
		case agents.AgentDown:
			s.obs.m.SetAgentUp(ev.AgentID, modeOf(s.reg, ev.AgentID, modes), false)
		case agents.AgentAdded:
			refresh()
		case agents.AgentDraining:
		}
	}
}

func modeOf(reg *agents.Registry, id string, cache map[string]string) string {
	for _, st := range reg.List() {
		if st.Agent.ID == id {
			cache[id] = string(st.Agent.Mode)
			return cache[id]
		}
	}
	return cache[id]
}

// runObs запускает фоновые задачи метрик/истории/алертов; возвращает функцию
// ожидания их завершения после отмены ctx.
func (s *Server) runObs(ctx context.Context) (wait func()) {
	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(ctx)
		}()
	}
	sampler := &history.Sampler{Collector: s.obs.coll, Repo: s.st.History(),
		Roller: history.NewRoller(s.st.History()), Log: s.logger}
	if s.opts.SamplerTicks != nil {
		run(func(ctx context.Context) { sampler.Run(ctx, s.opts.SamplerTicks) })
	} else {
		run(sampler.RunTicker)
	}
	run(s.obs.errlog.Run)
	if s.obs.deliv != nil {
		run(s.obs.deliv.Run)
		run(s.obs.eval.Run)
	}
	return wg.Wait
}
