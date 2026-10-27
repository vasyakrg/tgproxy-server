package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

// connRun — запущенный коннектор.
type connRun struct {
	c      *Connector
	url    string
	cancel context.CancelFunc
	done   chan struct{}
}

func (r *connRun) stop() {
	r.cancel()
	<-r.done
}

// manager управляет dial-листенером и reverse-коннектором в зависимости от
// режима; режим меняется на лету (PUT /_agent/config).
type manager struct {
	a *Agent

	opMu sync.Mutex // сериализует смену режима целиком (включая сохранение файла)

	mu     sync.Mutex
	ctx    context.Context
	mode   config.AgentMode
	url    string
	preset net.Listener // готовый листенер для первого запуска dial
	lst    *dialListener
	conn   *connRun
	mconn  *connRun // MTProto-класс reverse-соединений (только при mtproto.enabled)
	fatal  chan error
	bg     sync.WaitGroup // фоновые остановки старых компонентов
}

func newManager(a *Agent) *manager {
	return &manager{a: a, mode: a.cfg.Mode, url: a.cfg.ServerURL, fatal: make(chan error, 1)}
}

func wantListener(m config.AgentMode) bool { return m != config.AgentModeReverse }
func wantConnector(m config.AgentMode) bool {
	return m == config.AgentModeReverse || m == config.AgentModeBoth
}

func (m *manager) wantMTConnector(mode config.AgentMode) bool {
	return wantConnector(mode) && m.a.MTProtoEnabled()
}

// mtprotoConns — живые MTProto-соединения и целевой размер пула.
func (m *manager) mtprotoConns() (conns, target int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mconn == nil {
		return 0, 0
	}
	return m.mconn.c.Conns(), m.mconn.c.Target()
}

// snapshot — текущий режим и состояние reverse-канала.
func (m *manager) snapshot() (mode config.AgentMode, serverURL string, conns int, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mode, serverURL = m.mode, m.url
	if m.conn != nil {
		conns, state = m.conn.c.Conns(), m.conn.c.State()
	}
	return mode, serverURL, conns, state
}

func (m *manager) reportFatal(err error) {
	select {
	case m.fatal <- err:
	default:
	}
}

// switchTo переводит агента в режим mode/url. Новые ресурсы (листенер,
// коннектор) поднимаются синхронно — ошибка возвращается и состояние не
// меняется; остановка вытесняемых компонентов отдаётся в teardown, который
// вызывающий запускает ПОСЛЕ отправки ответа (запрос мог прийти по
// закрываемому каналу).
func (m *manager) switchTo(mode config.AgentMode, serverURL string) (teardown func(), err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var newConn *connRun
	if wantConnector(mode) && (m.conn == nil || m.conn.url != serverURL) {
		c, cerr := m.a.NewConnector(serverURL)
		if cerr != nil {
			return nil, cerr
		}
		newConn = &connRun{c: c, url: serverURL}
	}
	var newMConn *connRun
	if m.wantMTConnector(mode) && (m.mconn == nil || m.mconn.url != serverURL) {
		c, cerr := m.a.NewMTProtoConnector(serverURL)
		if cerr != nil {
			return nil, cerr
		}
		newMConn = &connRun{c: c, url: serverURL}
	}
	var newLst *dialListener
	if wantListener(mode) && m.lst == nil {
		ln := m.preset
		m.preset = nil
		if ln == nil {
			var lc net.ListenConfig
			ln, err = lc.Listen(m.ctx, "tcp", m.a.cfg.Listen.API)
			if err != nil {
				return nil, fmt.Errorf("agent: listen %s: %w", m.a.cfg.Listen.API, err)
			}
		}
		newLst = m.a.startListener(m.ctx, ln, m.reportFatal)
	}

	if !wantListener(mode) && m.preset != nil {
		_ = m.preset.Close()
		m.preset = nil
	}
	var oldLst *dialListener
	var oldConn *connRun
	if !wantListener(mode) {
		oldLst, m.lst = m.lst, nil
	} else if newLst != nil {
		m.lst = newLst
	}
	var oldMConn *connRun
	if !wantConnector(mode) {
		oldConn, m.conn = m.conn, nil
	} else if newConn != nil {
		oldConn, m.conn = m.conn, newConn
		m.start(newConn)
	}
	if !m.wantMTConnector(mode) {
		oldMConn, m.mconn = m.mconn, nil
	} else if newMConn != nil {
		oldMConn, m.mconn = m.mconn, newMConn
		m.start(newMConn)
	}
	m.mode, m.url = mode, serverURL
	m.a.logger.Info("agent mode applied", "mode", mode, "server_url", serverURL)

	return func() { m.teardown(oldLst, oldConn, oldMConn) }, nil
}

func (m *manager) start(r *connRun) {
	cctx, cancel := context.WithCancel(m.ctx)
	r.cancel, r.done = cancel, make(chan struct{})
	go func() {
		defer close(r.done)
		r.c.Run(cctx)
	}()
}

// teardown останавливает вытесненные компоненты (в фоне, под bg).
func (m *manager) teardown(l *dialListener, rs ...*connRun) {
	rs = slices.DeleteFunc(rs, func(r *connRun) bool { return r == nil })
	if l == nil && len(rs) == 0 {
		return
	}
	m.bg.Add(1)
	go func() {
		defer m.bg.Done()
		for _, r := range rs {
			m.bg.Add(1)
			go func() {
				defer m.bg.Done()
				r.stop()
			}()
		}
		if l != nil {
			if err := l.stop(m.ctx); err != nil {
				m.a.logger.Warn("agent listener stop", "err", err)
			}
		}
	}()
}

// stopAll останавливает всё; возвращает первую ошибку остановки листенера.
func (m *manager) stopAll() error {
	m.mu.Lock()
	l, r, mr := m.lst, m.conn, m.mconn
	m.lst, m.conn, m.mconn = nil, nil, nil
	if m.preset != nil {
		_ = m.preset.Close()
		m.preset = nil
	}
	m.mu.Unlock()

	var errs []error
	if mr != nil {
		mr.stop()
	}
	if r != nil {
		r.stop()
	}
	if l != nil {
		if err := l.stop(m.ctx); err != nil {
			errs = append(errs, err)
		}
	}
	m.bg.Wait()
	return errors.Join(errs...)
}
