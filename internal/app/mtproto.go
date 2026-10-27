package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/metrics"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/mux"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/upstream"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/balancer"
	"github.com/vasyakrg/tgproxy-server/internal/server/notify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const mtprotoResyncInterval = 5 * time.Second

// mtprotoState — зависимости MTProto, собираемые в NewServer при mtproto.enabled.
// Manager и mux создаются в Serve: им нужен адрес fronting-листенера mux.
type mtprotoState struct {
	kek       *pki.KEK
	keyed     *balancer.Keyed
	network   *upstream.Network
	available atomic.Bool
	mgr       atomic.Pointer[mtproto.Manager]
	mux       atomic.Pointer[mux.Listener] // для SetOptions по SIGHUP

	metrics  *metrics.Server
	names    *secretNames
	mobs     *mtproto.MetricsObserver
	journal  *mtproto.Journal
	dcs      *dcCounters // стримы/ошибки по (agent, dc) для матрицы UI
	listener string      // метка tgp_mtproto_client_conns: shared|dedicated
}

// Route реализует mux.Router: до создания Manager MTProto недоступен (fallthrough).
func (m *mtprotoState) Route() mux.Route {
	mgr := m.mgr.Load()
	if mgr == nil {
		return nil
	}
	r := mgr.Route()
	if r == nil {
		return nil // typed-nil в интерфейсе не пропускаем
	}
	return countedRoute{Route: r, m: m.metrics, listener: m.listener}
}

// countedRoute считает активные клиентские соединения (tgp_mtproto_client_conns).
type countedRoute struct {
	mux.Route
	m        *metrics.Server
	listener string
}

func (r countedRoute) Serve(idx int, conn net.Conn) {
	r.m.MTProtoClientConns(r.listener, 1)
	defer r.m.MTProtoClientConns(r.listener, -1)
	r.Route.Serve(idx, conn)
}

// secretNames — кэш id секрета -> имя для метки secret (в метки идёт имя, не ключ и не префикс).
// Промах (новый секрет) обновляет кэш из БД не чаще раза в секунду.
type secretNames struct {
	repo store.MTProtoSecretRepo
	m    atomic.Pointer[map[int64]string]
	last atomic.Int64 // unix-nano последнего обновления
}

const secretNamesMinGap = time.Second

func (n *secretNames) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	list, err := n.repo.List(ctx)
	n.last.Store(time.Now().UnixNano())
	if err != nil {
		return
	}
	m := make(map[int64]string, len(list))
	for _, sec := range list {
		m[sec.ID] = sec.Name
	}
	n.m.Store(&m)
}

// SecretName реализует mtproto.SecretNamer.
func (n *secretNames) SecretName(id int64) (string, bool) {
	if mp := n.m.Load(); mp != nil {
		if name, ok := (*mp)[id]; ok {
			return name, true
		}
	}
	if time.Since(time.Unix(0, n.last.Load())) < secretNamesMinGap {
		return "", false
	}
	n.refresh()
	if mp := n.m.Load(); mp != nil {
		name, ok := (*mp)[id]
		return name, ok
	}
	return "", false
}

// errFrontingDomain — fronting_domain отсутствует в SAN сертификата входа.
var errFrontingDomain = errors.New("app: mtproto.fronting_domain is not in the ingress certificate SAN")

// sanMatches сообщает, покрывает ли хотя бы одно SAN имя host (wildcard — одна метка).
func sanMatches(sans []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, san := range sans {
		san = strings.ToLower(strings.TrimSuffix(san, "."))
		if san == host {
			return true
		}
		if rest, ok := strings.CutPrefix(san, "*."); ok {
			if label, tail, found := strings.Cut(host, "."); found && label != "" && tail == rest {
				return true
			}
		}
	}
	return false
}

// checkFrontingDomain проверяет fronting_domain по SAN действующего сертификата
// входа. Для acme до первого выпуска SAN берутся из tls.domains.
func (s *Server) checkFrontingDomain(cfg *config.ServerConfig) error {
	sans := s.ingress.Info().SANs
	if len(sans) == 0 && cfg.TLS.Mode == config.TLSModeACME {
		sans = cfg.TLS.Domains
	}
	if !sanMatches(sans, cfg.MTProto.FrontingDomain) {
		return fmt.Errorf("%w: %q not in %v (the FakeTLS domain must match the ingress certificate)",
			errFrontingDomain, cfg.MTProto.FrontingDomain, sans)
	}
	return nil
}

// recheckFronting — повторная проверка после перезагрузки сертификата: Warn,
// работа не прерывается (клиенты с несовпадающим доменом получат fallthrough).
func (s *Server) recheckFronting() {
	snap := s.cur.Load()
	if s.mt == nil || snap == nil {
		return
	}
	if err := s.checkFrontingDomain(snap.cfg); err != nil {
		s.logger.Warn("mtproto: ingress certificate no longer covers fronting_domain", "error", err)
	}
}

// wireMTProto собирает зависимости MTProto (только при enabled): проверка
// fronting_domain, KEK, keyed-балансировщик, Network через агентов.
func (s *Server) wireMTProto(cfg *config.ServerConfig) error {
	if !cfg.MTProto.Enabled {
		return nil
	}
	if s.ingTLS == nil {
		return errors.New("app: mtproto requires ingress tls (tls.mode files|acme)")
	}
	if err := s.checkFrontingDomain(cfg); err != nil {
		return err
	}
	kek, err := pki.LoadKEK(cfg.PKI.KEKFile)
	if err != nil {
		return fmt.Errorf("app: mtproto: load kek: %w", redact.Error(err))
	}
	m := &mtprotoState{kek: kek, keyed: balancer.NewKeyed(), metrics: s.obs.m, listener: "shared"}
	if !cfg.MTProto.Shared() {
		m.listener = "dedicated"
	}
	m.names = &secretNames{repo: s.st.MTProtoSecrets()}
	m.mobs = mtproto.NewMetricsObserver(s.obs.m, m.names)
	m.journal = mtproto.NewJournal(s.st.MTProtoSessions(), s.logger)
	s.obs.coll.SetMTProto(m.journal)
	m.dcs = newDCCounters(s.obs.m)
	m.network, err = upstream.New(upstream.Options{
		Picker:      upstream.KeyedPicker{K: m.keyed},
		Streams:     s.tr,
		Resolve:     s.reg.Ref,
		DialTimeout: cfg.MTProto.AgentPool.DialTimeout,
		Metrics:     m.dcs,
	})
	if err != nil {
		return fmt.Errorf("app: mtproto network: %w", err)
	}
	s.mt = m
	s.syncMTProtoAgents()
	// NTP: общего источника времени в процессе нет; окно time_skew защищает от
	// малых расхождений, большие дают handshake-отказы. Требование — в логе.
	s.logger.Warn("mtproto enabled: server and clients must be time-synchronized (NTP), FakeTLS timestamp window is time_skew",
		"time_skew", cfg.MTProto.TimeSkew)
	return nil
}

// syncMTProtoAgents обновляет keyed-балансировщик и признак доступности по реестру агентов.
func (s *Server) syncMTProtoAgents() {
	list := s.reg.List()
	cands := make([]balancer.KeyedCandidate, 0, len(list))
	avail := false
	for _, st := range list {
		c := st.KeyedCandidate()
		cands = append(cands, c)
		avail = avail || (c.Capable && c.Healthy)
	}
	s.mt.keyed.Update(cands)
	s.mt.available.Store(avail)
	s.syncMTProtoDCMetrics(list)
}

// mtprotoSnapshot собирает снимок для алертов: только capable-агенты (up и с capability).
func mtprotoSnapshot(list []agents.State, active int64, maxConns int) notify.MTProtoSnapshot {
	snap := notify.MTProtoSnapshot{Enabled: true, ActiveConns: int(active), MaxConns: maxConns}
	for _, st := range list {
		capable, dc := st.MTProtoView()
		if !capable || !st.Up {
			continue
		}
		a := notify.MTProtoAgent{ID: st.Agent.ID, DCUp: make(map[int]bool, len(dc))}
		for n, d := range dc {
			a.DCUp[n] = d.Up
		}
		snap.Agents = append(snap.Agents, a)
	}
	return snap
}

// observeMTProto передаёт состояние MTProto правилам алертов (dc_unreachable,
// no_capable_agents, overload). Без уведомлений (eval == nil) — no-op.
func (s *Server) observeMTProto(ctx context.Context) {
	if s.mt == nil || s.obs == nil || s.obs.eval == nil {
		return
	}
	var maxConns int
	if snap := s.cur.Load(); snap != nil {
		maxConns = snap.cfg.MTProto.MaxConns
	}
	s.obs.eval.ObserveMTProto(ctx, mtprotoSnapshot(s.reg.List(), s.mt.journal.ActiveConns(), maxConns))
}

// syncMTProtoDCMetrics зеркалит состояние DC из статусов агентов в dc_up / dc_rtt_seconds.
func (s *Server) syncMTProtoDCMetrics(list []agents.State) {
	for _, st := range list {
		capable, dc := st.MTProtoView()
		if !capable || dc == nil {
			continue
		}
		out := make(map[int]metrics.DCState, len(dc))
		for n, d := range dc {
			out[n] = metrics.DCState{Up: d.Up, RTT: d.RTT}
		}
		s.obs.m.SetMTProtoDCs(st.Agent.ID, out)
	}
}

// mtprotoDenied фиксирует отказ MTProto-клиента: запись в «Ошибках» (фаза mtproto,
// без секрета) и учёт для автобана (считаются только причины с CountsForBan).
func (s *Server) mtprotoDenied(ip netip.Addr, reason access.Reason) {
	if s.obs != nil && s.obs.errlog != nil {
		s.obs.errlog.Record(context.Background(), access.MTProtoErrorEvent(time.Now(), ip, reason))
	}
	if s.bans != nil {
		s.bans.Record(ip, reason)
	}
}

// onMTProtoReplay — повтор ClientHello (Manager.OnReplay): автобан по порогу ban.
func (s *Server) onMTProtoReplay(ip netip.Addr) {
	s.logger.Warn("mtproto: replayed ClientHello", "ip", ip.String())
	s.mt.mobs.Reject("replay")
	s.obs.m.MTProtoConnection("unknown", "replay")
	s.mtprotoDenied(ip, access.ReasonMTProtoReplay)
}

// onMTProtoReject — отказ на входе mux (лимиты, таймаут, битая запись).
func (s *Server) onMTProtoReject(ip netip.Addr, r mux.Reason) {
	s.logger.Debug("mtproto: connection rejected", "reason", string(r), "ip", ip.String())
	mtproto.RejectHook[mux.Reason](s.mt.mobs)(ip, r)
	if r == mux.ReasonConnLimit {
		s.obs.m.MTProtoConnection("unknown", "conn_limit")
		s.mtprotoDenied(ip, access.ReasonMTProtoConnLimit)
	}
}

// muxOptions собирает лимиты mux из конфига (старт и SIGHUP).
func (s *Server) muxOptions(mc config.MTProtoConfig) mux.Options {
	return mux.Options{
		MaxConns: mc.MaxConns, MaxConnsPerIP: mc.MaxConnsPerIP, MaxPendingHandshakes: mc.MaxPendingHandshakes,
		HandshakeTimeout: mc.HandshakeTimeout, Logger: s.logger,
	}
}

// reloadMTProtoLimits применяет лимиты mux по SIGHUP без разрыва живых соединений.
func (s *Server) reloadMTProtoLimits(mc config.MTProtoConfig) {
	if s.mt == nil {
		return
	}
	if ml := s.mt.mux.Load(); ml != nil {
		ml.SetOptions(s.muxOptions(mc))
	}
	s.warnFDBudget(mc)
}

func (s *Server) warnFDBudget(mc config.MTProtoConfig) {
	if w := mtproto.CheckFDBudget(mc.MaxConns); w != "" {
		s.logger.Warn(w, "max_conns", mc.MaxConns)
	}
}

// runMTProtoAgents следит за событиями реестра (и периодически пересинхронизируется:
// события для медленного подписчика отбрасываются).
func (s *Server) runMTProtoAgents(ctx context.Context, wg *sync.WaitGroup) {
	events, unsub := s.reg.Subscribe()
	wg.Go(func() {
		defer unsub()
		t := time.NewTicker(mtprotoResyncInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				if ev.Type == agents.AgentMTProto || ev.Type == agents.AgentUp || ev.Type == agents.AgentDown ||
					ev.Type == agents.AgentAdded || ev.Type == agents.AgentRemoved || ev.Type == agents.AgentDraining {
					s.syncMTProtoAgents()
				}
			case <-t.C:
				s.syncMTProtoAgents()
				s.observeMTProto(ctx)
			}
		}
	})
}

// mtRuntime — запущенные в Serve части MTProto.
type mtRuntime struct {
	mux   *mux.Listener
	mgr   *mtproto.Manager
	extra *http.Server // dedicated: TLS-сервер заглушки поверх mux; nil для shared
}

// notFoundHandler — заглушка fallthrough на dedicated-листенере: обычный сайт-404.
func notFoundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
}

// startMTProto оборачивает листенер в mux и создаёт Manager. shared: оборачивается
// proxyLn (его же и возвращает вызывающему); dedicated: оборачивается
// s.opts.MTProtoListener, TLS-сервер заглушки возвращается в rt.extra.
func (s *Server) startMTProto(cfg *config.ServerConfig, proxyLn net.Listener) (net.Listener, *mtRuntime, error) {
	mc := cfg.MTProto
	inner := proxyLn
	if !mc.Shared() {
		inner = s.opts.MTProtoListener
		if inner == nil {
			return nil, nil, errors.New("app: mtproto dedicated listener is not provided")
		}
	}
	hooks := mux.Hooks{
		Banned:        func(ip netip.Addr) bool { return s.bans != nil && s.bans.Banned(ip) },
		OnReject:      s.onMTProtoReject,
		OnFallthrough: s.mt.mobs.Fallthrough,
	}
	ml, err := mux.New(inner, s.mt, hooks, s.muxOptions(mc))
	if err != nil {
		return nil, nil, fmt.Errorf("app: mtproto mux: %w", err)
	}
	s.mt.mux.Store(ml)
	s.warnFDBudget(mc)
	kek := s.mt.kek
	mgr, err := mtproto.New(mtproto.Options{
		Secrets: s.st.MTProtoSecrets(),
		Open:    func(sealed []byte, aad string) ([]byte, error) { return kek.Open(sealed, []byte(aad)) },
		Network: s.mt.network, FrontingAddr: ml.FrontingAddr(),
		Available: s.mt.available.Load,
		OnReplay:  s.onMTProtoReplay,
		Observer:  mtproto.MultiObserver(s.mt.mobs, s.mt.journal),
		Logger:    s.logger, Config: mc,
	})
	if err != nil {
		_ = ml.Close()
		return nil, nil, fmt.Errorf("app: mtproto manager: %w", err)
	}
	s.mt.mgr.Store(mgr)
	rt := &mtRuntime{mux: ml, mgr: mgr}
	if mc.Shared() {
		return ml, rt, nil
	}
	rt.extra = newHTTPServer(notFoundHandler(), s.ingTLS, s.logger)
	return proxyLn, rt, nil
}

// stop останавливает Manager (рвёт MTProto-соединения) не дольше ctx. Вызывается
// до Shutdown HTTP-серверов: mux.Close ждёт обработчики MTProto-соединений.
// После вызова Route() == nil, новые клиенты уходят в fallthrough.
func (rt *mtRuntime) stop(ctx context.Context, logger *slog.Logger) {
	done := make(chan struct{})
	go func() { _ = rt.mgr.Close(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		logger.Warn("mtproto: manager close incomplete")
	}
}
