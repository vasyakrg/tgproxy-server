package app

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/mtproto/upstream"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/web"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
)

const (
	mtStatsTimeout = 2 * time.Second
	mtLiveMinSpan  = time.Second // реже окно скорости не пересчитывается
)

type dcKey struct {
	agent string
	dc    int
}

type dcCount struct {
	streams int
	errors  int64
}

// dcCounters дублирует метрики стримов upstream по (agent, dc) для матрицы на экране MTProto.
type dcCounters struct {
	upstream.Metrics
	mu sync.Mutex
	m  map[dcKey]*dcCount
}

func newDCCounters(next upstream.Metrics) *dcCounters {
	return &dcCounters{Metrics: next, m: make(map[dcKey]*dcCount)}
}

func (c *dcCounters) cell(agent string, dc int) *dcCount {
	k := dcKey{agent, dc}
	v := c.m[k]
	if v == nil {
		v = &dcCount{}
		c.m[k] = v
	}
	return v
}

// MTProtoStreams — upstream.Metrics.
func (c *dcCounters) MTProtoStreams(agent string, dc, delta int) {
	c.Metrics.MTProtoStreams(agent, dc, delta)
	c.mu.Lock()
	c.cell(agent, dc).streams += delta
	c.mu.Unlock()
}

// MTProtoUpstreamError — upstream.Metrics.
func (c *dcCounters) MTProtoUpstreamError(agent string, dc int, phase string) {
	c.Metrics.MTProtoUpstreamError(agent, dc, phase)
	c.mu.Lock()
	c.cell(agent, dc).errors++
	c.mu.Unlock()
}

func (c *dcCounters) get(agent string, dc int) dcCount {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v := c.m[dcKey{agent, dc}]; v != nil {
		return *v
	}
	return dcCount{}
}

// idsByName возвращает id секретов с данным именем; при промахе обновляет кэш (не чаще раза в секунду).
func (n *secretNames) idsByName(name string) []int64 {
	find := func() []int64 {
		var ids []int64
		if mp := n.m.Load(); mp != nil {
			for id, nm := range *mp {
				if nm == name {
					ids = append(ids, id)
				}
			}
		}
		return ids
	}
	if ids := find(); len(ids) > 0 {
		return ids
	}
	if time.Since(time.Unix(0, n.last.Load())) >= secretNamesMinGap {
		n.refresh()
	}
	return find()
}

// activeConnsByName — число активных MTProto-соединений секрета по имени.
func (m *mtprotoState) activeConnsByName(name string) int {
	total := 0
	for _, id := range m.names.idsByName(name) {
		total += m.mobs.Active(id)
	}
	return total
}

// mtprotoWeb — источник данных экрана и API MTProto (api.MTProtoStatsSource, screens.MTProtoLive).
type mtprotoWeb struct {
	s *Server

	mu       sync.Mutex
	lastAt   time.Time
	lastSum  int64
	lastRate float64
}

// Snapshot реализует api.MTProtoStatsSource.
func (w *mtprotoWeb) Snapshot() api.MTProtoStats {
	s := w.s
	if s.mt == nil {
		return api.MTProtoStats{}
	}
	out := api.MTProtoStats{Enabled: true, Agents: []api.MTProtoAgentStat{}}
	for _, st := range s.reg.List() {
		capable, dc := st.MTProtoView()
		ag := api.MTProtoAgentStat{AgentID: st.Agent.ID, Capable: capable, DC: []api.MTProtoDCStat{}}
		if st.LastStatus != nil && st.LastStatus.MTProto != nil {
			ag.Streams = st.LastStatus.MTProto.Streams
		}
		for n, d := range dc {
			cnt := s.mt.dcs.get(st.Agent.ID, n)
			ag.DC = append(ag.DC, api.MTProtoDCStat{
				DC: n, Up: d.Up, RTTMs: float64(d.RTT) / float64(time.Millisecond),
				Streams: max(cnt.streams, 0), Errors: cnt.errors,
			})
		}
		out.Agents = append(out.Agents, ag)
	}
	out.Totals.ActiveConns = s.mt.journal.ActiveConns()
	out.Totals.BytesIn, out.Totals.BytesOut = s.mt.journal.TotalBytes()
	ctx, cancel := context.WithTimeout(context.Background(), mtStatsTimeout)
	defer cancel()
	if list, err := s.st.MTProtoSecrets().List(ctx); err == nil {
		now := time.Now()
		for _, sec := range list {
			if sec.Active(now) {
				out.Totals.SecretsActive++
			}
		}
	}
	return out
}

// MTProtoLive реализует screens.MTProtoLive: активные соединения и полоса (вход+выход).
func (w *mtprotoWeb) MTProtoLive() (enabled bool, conns int, bytesPerSec float64) {
	s := w.s
	if s.mt == nil {
		return false, 0, 0
	}
	in, out := s.mt.journal.TotalBytes()
	sum, now := in+out, time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	switch dt := now.Sub(w.lastAt); {
	case w.lastAt.IsZero():
		w.lastAt, w.lastSum = now, sum
	case dt >= mtLiveMinSpan:
		w.lastRate = float64(sum-w.lastSum) / dt.Seconds()
		w.lastAt, w.lastSum = now, sum
	}
	return true, int(s.mt.journal.ActiveConns()), w.lastRate
}

// mountMTProto подключает вкладку «MTProto» и JSON API секретов/статистики. Работает и при
// mtproto.enabled=false (подготовка секретов); возвращает функцию монтирования API.
func (s *Server) mountMTProto(rt *web.Router, a *auth.Auth, kek *pki.KEK, protected func(http.Handler) http.Handler) (
	live *mtprotoWeb, mountAPI func(*http.ServeMux),
) {
	endpoint := func() api.MTProtoEndpoint {
		cfg := s.cur.Load().cfg
		return api.ResolveMTProtoEndpoint(cfg.MTProto, cfg.Server.PublicBaseURL, cfg.Listen.Proxy)
	}
	svc := api.NewMTProtoService(s.st.MTProtoSecrets(), s.st.Audit(), kek, endpoint, s.logger, nil)
	live = &mtprotoWeb{s: s}
	var conns func(string) int
	if s.mt != nil {
		conns = s.mt.activeConnsByName
	}
	screens.MountMTProto(rt, screens.MTProtoDeps{
		Auth: a, Service: svc, Stats: live, ActiveConns: conns, ClientIP: s.checker.ClientIP, Logger: s.logger,
	})
	return live, func(mux *http.ServeMux) {
		(&api.MTProtoAPI{Service: svc, ClientIP: s.checker.ClientIP, ActiveConns: conns, Fresh: api.NewFreshTOTP(a)}).
			Routes(muxMounter{mux}, api.Wrap(protected))
		(&api.MTProtoStatsAPI{Source: live}).Routes(mux, api.Wrap(protected))
	}
}
