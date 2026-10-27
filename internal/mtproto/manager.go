package mtproto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/mtglib"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// DefaultPollInterval — период проверки версии таблицы секретов.
const DefaultPollInterval = 2 * time.Second

// ErrClosed возвращается после Close.
var ErrClosed = errors.New("mtproto: manager closed")

// Route — неизменяемый снимок разводки: Keys()[i] соответствует инстансу i.
// Набор методов совпадает с consumer-интерфейсом mux.
type Route interface {
	Keys() [][16]byte
	Domain() string
	Skew() time.Duration
	// Serve блокируется до завершения соединения; conn.RemoteAddr() — *net.TCPAddr.
	Serve(idx int, conn net.Conn)
	// Limits — id секрета, его CIDR (пусто — любые клиенты) и max_conns (0 — без лимита).
	Limits(idx int) (id int64, cidrs []netip.Prefix, maxConns int)
}

// Secrets — consumer-side срез store.MTProtoSecretRepo.
type Secrets interface {
	ListActive(ctx context.Context, now time.Time) ([]store.MTProtoSecret, int64, error)
	Version(ctx context.Context) (int64, error)
}

// Options — зависимости Manager.
type Options struct {
	Secrets Secrets
	// Open расшифровывает secret_enc (KEK.Open); aad = "mtproto/<id>".
	Open    func(sealed []byte, aad string) ([]byte, error)
	Network mtglib.Network
	// FrontingAddr — внутренний loopback-листенер, принимающий PROXY v2 (domain fronting mtg).
	FrontingAddr *net.TCPAddr
	// Available сообщает, что есть capable-агенты; nil — всегда true.
	Available func() bool
	// OnReplay вызывается при повторе ClientHello (→ bans.Record mtproto_replay).
	OnReplay func(ip netip.Addr)
	Observer Observer
	Logger   *slog.Logger
	Config   config.MTProtoConfig

	// PollInterval — период опроса версии (по умолчанию DefaultPollInterval).
	PollInterval time.Duration
	// Now — источник времени (тесты); по умолчанию time.Now.
	Now func() time.Time
}

type instance struct {
	id    int64
	enc   []byte
	key   [16]byte
	cidrs []netip.Prefix
	max   int
	proxy *mtglib.Proxy
	// conns разделяется копиями инстанса (смена лимитов без рестарта mtg).
	conns *connSet
}

// drainTimeout — сколько retire ждёт выхода обработчиков после закрытия соединений.
const drainTimeout = 5 * time.Second

// connSet учитывает активные соединения инстанса. mtg.Proxy.Shutdown отменяет
// контекст всех потоков, и это гоняется с ServeConn (запись streamContext.clientConn
// при рукопожатии против чтения в Close из context.AfterFunc), поэтому на Shutdown
// не полагаемся: перед ним соединения закрываются нами, а Shutdown вызывается
// лишь когда ни одного ServeConn не осталось.
type connSet struct {
	mu      sync.Mutex
	retired bool
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

func newConnSet() *connSet { return &connSet{conns: make(map[net.Conn]struct{})} }

// enter регистрирует соединение; false — инстанс уже выводится из работы.
func (c *connSet) enter(conn net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.retired {
		return false
	}
	c.conns[conn] = struct{}{}
	c.wg.Add(1)
	return true
}

func (c *connSet) leave(conn net.Conn) {
	c.mu.Lock()
	delete(c.conns, conn)
	c.mu.Unlock()
	c.wg.Done()
}

// drain запрещает новые соединения, закрывает активные и ждёт выхода Serve не дольше timeout.
// Возвращает false, если не дождались.
func (c *connSet) drain(timeout time.Duration) bool {
	c.mu.Lock()
	c.retired = true
	open := make([]net.Conn, 0, len(c.conns))
	for conn := range c.conns {
		open = append(open, conn)
	}
	c.mu.Unlock()
	for _, conn := range open {
		_ = conn.Close()
	}
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

type snapshot struct {
	keys   [][16]byte
	insts  []*instance
	domain string
	skew   time.Duration
	m      *Manager
}

// Manager держит по инстансу mtglib.Proxy на активный секрет и следит за таблицей.
type Manager struct {
	o      Options
	cache  mtglib.AntiReplayCache
	logger *slog.Logger

	snap atomic.Pointer[snapshot]

	mu         sync.Mutex
	insts      map[int64]*instance
	version    int64
	loaded     bool
	nextExpiry time.Time
	closed     bool
	wg         sync.WaitGroup
}

// New проверяет зависимости и создаёт Manager без загрузки секретов (Reload/Run).
func New(o Options) (*Manager, error) {
	switch {
	case o.Secrets == nil:
		return nil, errors.New("mtproto: Secrets обязателен")
	case o.Open == nil:
		return nil, errors.New("mtproto: Open обязателен")
	case o.Network == nil:
		return nil, errors.New("mtproto: Network обязателен")
	case o.FrontingAddr == nil || o.FrontingAddr.IP == nil || o.FrontingAddr.Port == 0:
		return nil, errors.New("mtproto: FrontingAddr обязателен")
	case o.Config.FrontingDomain == "":
		return nil, errors.New("mtproto: fronting_domain не задан")
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	l := o.Logger
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	return &Manager{
		o:      o,
		logger: l.With("component", "mtproto"),
		insts:  make(map[int64]*instance),
		cache: antireplay.NewStableBloomFilter(
			uint(max(o.Config.ReplayCache, 0)), antireplay.DefaultStableBloomFilterErrorRate), //nolint:gosec // значение провалидировано конфигом
	}, nil
}

// Route возвращает текущий снимок или nil, если активных секретов нет либо
// нет capable-агентов.
func (m *Manager) Route() Route {
	s := m.snap.Load()
	if s == nil || len(s.insts) == 0 {
		return nil
	}
	if m.o.Available != nil && !m.o.Available() {
		return nil
	}
	return s
}

// Run загружает секреты и опрашивает версию до отмены ctx. Ошибки чтения
// логируются и повторяются на следующем тике.
func (m *Manager) Run(ctx context.Context) error {
	if err := m.Reload(ctx); err != nil && ctx.Err() == nil {
		m.logger.Warn("начальная загрузка секретов не удалась", "error", err)
	}
	t := time.NewTicker(m.o.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.poll(ctx)
		}
	}
}

func (m *Manager) poll(ctx context.Context) {
	m.mu.Lock()
	closed, loaded, ver, exp := m.closed, m.loaded, m.version, m.nextExpiry
	m.mu.Unlock()
	if closed {
		return
	}
	cur, err := m.o.Secrets.Version(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.logger.Warn("не удалось прочитать версию секретов", "error", err)
		}
		return
	}
	expired := !exp.IsZero() && !m.o.Now().Before(exp)
	if loaded && cur == ver && !expired {
		return
	}
	if err := m.Reload(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, ErrClosed) {
		m.logger.Warn("перечитать секреты не удалось", "error", err)
	}
}

// Reload перечитывает активные секреты: новые получают инстанс, исчезнувшие
// закрываются (Shutdown рвёт их соединения), неизменные переиспользуются.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	now := m.o.Now()
	secrets, ver, err := m.o.Secrets.ListActive(ctx, now)
	if err != nil {
		return fmt.Errorf("mtproto: чтение секретов: %w", err)
	}
	slices.SortFunc(secrets, func(a, b store.MTProtoSecret) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})

	next := make(map[int64]*instance, len(secrets))
	var (
		list   []*instance
		expiry time.Time
	)
	for _, s := range secrets {
		inst := m.insts[s.ID]
		if inst == nil || !bytes.Equal(inst.enc, s.SecretEnc) {
			if inst, err = m.newInstance(s); err != nil {
				m.logger.Error("секрет пропущен", "secret_id", s.ID, "secret", s.Name, "error", err)
				continue
			}
		} else if inst.max != s.MaxConns || !slices.Equal(inst.cidrs, s.CIDRs) {
			// Ключ тот же, лимиты изменились: новый объект без рестарта mtg-инстанса.
			cp := *inst
			cp.cidrs, cp.max = slices.Clone(s.CIDRs), s.MaxConns
			inst = &cp
		}
		next[s.ID] = inst
		list = append(list, inst)
		if s.GraceUntil != nil && (expiry.IsZero() || s.GraceUntil.Before(expiry)) {
			expiry = *s.GraceUntil
		}
	}

	var removed []*instance
	for id, inst := range m.insts {
		if n := next[id]; n == nil || n.proxy != inst.proxy {
			removed = append(removed, inst)
		}
	}
	m.insts, m.version, m.loaded, m.nextExpiry = next, ver, true, expiry

	snap := &snapshot{
		insts:  list,
		keys:   make([][16]byte, len(list)),
		domain: m.o.Config.FrontingDomain,
		skew:   m.o.Config.TimeSkew,
		m:      m,
	}
	for i, inst := range list {
		snap.keys[i] = inst.key
	}
	m.snap.Store(snap)

	for _, inst := range removed {
		m.retire(inst)
	}
	m.logger.Info("секреты MTProto обновлены", "active", len(list), "removed", len(removed), "version", ver)
	return nil
}

// retire останавливает инстанс асинхронно: сначала закрывает его соединения и
// ждёт выхода обработчиков, затем Shutdown (см. connSet).
func (m *Manager) retire(inst *instance) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if !inst.conns.drain(drainTimeout) {
			m.logger.Warn("обработчики MTProto не завершились вовремя", "secret_id", inst.id)
		}
		inst.proxy.Shutdown()
		m.logger.Info("секрет MTProto остановлен", "secret_id", inst.id)
	}()
}

func (m *Manager) newInstance(s store.MTProtoSecret) (*instance, error) {
	raw, err := m.o.Open(s.SecretEnc, "mtproto/"+strconv.FormatInt(s.ID, 10))
	if err != nil {
		return nil, fmt.Errorf("расшифровка: %w", err)
	}
	if len(raw) != mtglib.SecretKeyLength {
		return nil, fmt.Errorf("ключ неверной длины: %d", len(raw))
	}
	inst := &instance{
		id: s.ID, enc: bytes.Clone(s.SecretEnc),
		cidrs: slices.Clone(s.CIDRs), max: s.MaxConns, conns: newConnSet(),
	}
	copy(inst.key[:], raw)
	clear(raw)

	c := m.o.Config
	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:                      mtglib.Secret{Key: inst.key, Host: c.FrontingDomain},
		Network:                     m.o.Network,
		AntiReplayCache:             m.cache,
		IPBlocklist:                 ipblocklist.NewNoop(),
		IPAllowlist:                 ipblocklist.NewNoop(),
		EventStream:                 newEventSink(s.ID, m.o.Observer, m.o.OnReplay),
		Logger:                      newMTGLogger(m.logger, inst.key),
		PreferIP:                    "only-ipv4",
		AllowFallbackOnUnknownDC:    true,
		TolerateTimeSkewness:        c.TimeSkew,
		IdleTimeout:                 c.IdleTimeout,
		HandshakeTimeout:            c.HandshakeTimeout,
		DomainFrontingIP:            m.o.FrontingAddr.IP.String(),
		DomainFrontingPort:          uint(m.o.FrontingAddr.Port), //nolint:gosec // порт TCP ≥ 0
		DomainFrontingProxyProtocol: true,
	})
	if err != nil {
		return nil, fmt.Errorf("mtglib: %w", err)
	}
	inst.proxy = proxy
	return inst, nil
}

// Close убирает разводку, останавливает все инстансы (рвёт активные
// соединения) и ждёт их завершения.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		m.wg.Wait()
		return nil
	}
	m.closed = true
	m.snap.Store(nil)
	for _, inst := range m.insts {
		m.retire(inst)
	}
	m.insts = map[int64]*instance{}
	m.mu.Unlock()
	m.wg.Wait()
	return nil
}

func (s *snapshot) Keys() [][16]byte    { return slices.Clone(s.keys) }
func (s *snapshot) Domain() string      { return s.domain }
func (s *snapshot) Skew() time.Duration { return s.skew }

// Limits возвращает ограничения секрета idx; для неверного idx — «закрыто всё».
func (s *snapshot) Limits(idx int) (int64, []netip.Prefix, int) {
	if idx < 0 || idx >= len(s.insts) {
		return 0, []netip.Prefix{{}}, 1
	}
	in := s.insts[idx]
	return in.id, in.cidrs, in.max
}

// Serve отдаёт соединение инстансу idx. Блокируется до конца relay.
// Некорректный индекс или RemoteAddr не *net.TCPAddr (mtg паникует на type
// assertion) закрывают соединение.
func (s *snapshot) Serve(idx int, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.m.logger.Error("паника в обработчике MTProto", "panic", fmt.Sprint(r))
			_ = conn.Close()
		}
	}()
	if idx < 0 || idx >= len(s.insts) {
		_ = conn.Close()
		return
	}
	if _, ok := conn.RemoteAddr().(*net.TCPAddr); !ok {
		_ = conn.Close()
		return
	}
	ec, ok := conn.(essentials.Conn)
	if !ok {
		ec = essentials.WrapNetConn(conn)
	}
	in := s.insts[idx]
	if !in.conns.enter(conn) {
		_ = conn.Close() // секрет отозван между выбором снимка и Serve
		return
	}
	defer in.conns.leave(conn)
	in.proxy.ServeConn(ec)
}
