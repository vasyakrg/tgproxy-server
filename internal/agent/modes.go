package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	if !wantConnector(mode) {
		oldConn, m.conn = m.conn, nil
	} else if newConn != nil {
		oldConn, m.conn = m.conn, newConn
		cctx, cancel := context.WithCancel(m.ctx)
		newConn.cancel, newConn.done = cancel, make(chan struct{})
		go func() {
			defer close(newConn.done)
			newConn.c.Run(cctx)
		}()
	}
	m.mode, m.url = mode, serverURL
	m.a.logger.Info("agent mode applied", "mode", mode, "server_url", serverURL)

	return func() { m.teardown(oldLst, oldConn) }, nil
}

// teardown останавливает вытесненные компоненты (в фоне, под bg).
func (m *manager) teardown(l *dialListener, r *connRun) {
	if l == nil && r == nil {
		return
	}
	m.bg.Add(1)
	go func() {
		defer m.bg.Done()
		if r != nil {
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
	l, r := m.lst, m.conn
	m.lst, m.conn = nil, nil
	if m.preset != nil {
		_ = m.preset.Close()
		m.preset = nil
	}
	m.mu.Unlock()

	var errs []error
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
