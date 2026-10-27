package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/probe"
	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// srvNewSecret создаёт секрет в store сервера (ключ запечатывается KEK под id строки).
func srvNewSecret(t *testing.T, s *Server, name string) (int64, [16]byte) {
	t.Helper()
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	sec, err := s.st.MTProtoSecrets().Create(context.Background(), name, func(id int64) ([]byte, error) {
		return s.mt.kek.Seal(key[:], []byte("mtproto/"+strconv.FormatInt(id, 10)))
	}, hex.EncodeToString(key[:4]), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return sec.ID, key
}

// metricsText читает /metrics по https (вход с самоподписанным сертификатом).
func metricsText(t *testing.T, base, bearer string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/metrics", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // тестовый самоподписанный сертификат входа
	}}
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

var nonZeroSample = regexp.MustCompile(`\s([1-9][0-9.e+-]*)$`)

// hasNonZero сообщает, есть ли строка метрики с префиксом prefix и ненулевым значением.
func hasNonZero(body, prefix string) bool {
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(ln, prefix) && nonZeroSample.MatchString(ln) {
			return true
		}
	}
	return false
}

// Приёмка среза M11: reverse-агент за NAT обслуживает MTProto, /metrics содержит
// tgp_mtproto_* с ненулевыми значениями и без IP/ключей.
func TestMTProtoReverseAgentProbeAndMetrics(t *testing.T) {
	e := newPKIEnvWith(t, pkiOpts{mtproto: true})
	dc, dcAddr, err := probe.NewFakeDC()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dc.Close() })

	files := e.issue("nat1")
	e.addAgent("nat1", store.ModeReverse, "")
	acfg := e.agentConfig(files, config.AgentModeReverse)
	acfg.MTProto.DCProbeInterval = time.Second
	acfg.OverrideMTProtoDCs(map[int][]netip.AddrPort{2: {netip.MustParseAddrPort(dcAddr)}})
	e.startReverse("nat1", acfg)

	e.waitFor(10*time.Second, "reverse agent up", func() bool { return e.up("nat1") })
	e.waitFor(10*time.Second, "mtproto reverse conns", func() bool { return e.srv.pki.mtpool.Conns("nat1") >= 1 })
	_, key := srvNewSecret(t, e.srv, "main")

	mtAddr := strings.TrimPrefix(e.proxyURL, "https://")
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		res, perr := probe.Run(ctx, mtAddr, key, mtDomain)
		cancel()
		if perr == nil && res.DCResponded {
			break
		}
		last = perr
		if time.Now().After(deadline) {
			t.Fatalf("probe через reverse-агента не прошёл: %v\nlogs:\n%s", last, e.logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if dc.Answered() < 1 {
		t.Fatal("fake-DC не получил обращений")
	}

	var body string
	e.waitFor(10*time.Second, "tgp_mtproto_* в /metrics", func() bool {
		body = metricsText(t, e.metrics, pkiMetricsBearer)
		return hasNonZero(body, `tgp_mtproto_connections_total{result="ok",secret="main"}`) &&
			hasNonZero(body, `tgp_mtproto_bytes_total{agent="nat1",direction="in"}`) &&
			hasNonZero(body, `tgp_mtproto_dc_up{agent="nat1",dc="2"}`) &&
			hasNonZero(body, `tgp_mtproto_session_duration_seconds_count`)
	})
	for _, ln := range strings.Split(body, "\n") {
		if !strings.HasPrefix(ln, "tgp_mtproto_") {
			continue
		}
		if strings.Contains(ln, "127.0.0.1") || strings.Contains(ln, hex.EncodeToString(key[:4])) {
			t.Errorf("IP или ключ в метке: %s", ln)
		}
	}
}

// Replay-флуд с одного IP банит адрес по порогу из конфига ban; запись в «Ошибках»
// несёт фазу mtproto, IP и причину, но не секрет.
func TestMTProtoReplayFloodAutobans(t *testing.T) {
	m := newMTEnv(t, mtOpts{obs: true, banThresh: 3})
	_, key := m.newSecret("main")
	m.probeOK(key)

	attacker := netip.MustParseAddr("203.0.113.9") // loopback защищён от бана — флуд эмулируем вызовом колбэка Manager
	for range 3 {
		m.srv.onMTProtoReplay(attacker)
	}
	m.waitFor(5*time.Second, "автобан по mtproto_replay", func() bool {
		bans, _ := m.srv.st.Bans().ListActive(context.Background(), time.Now())
		return len(bans) == 1 && strings.HasPrefix(bans[0].Prefix.String(), "203.0.113.")
	})
	if !m.srv.bans.Banned(attacker) {
		t.Fatal("адрес не в кэше банов")
	}

	m.ticks <- time.Now()
	m.ticks <- time.Now()
	evs, _ := m.srv.st.Errors().List(context.Background(), store.ErrorQuery{Phase: "mtproto", ClientIP: attacker.String(), Limit: 50})
	if len(evs) != 3 {
		t.Fatalf("записей mtproto в «Ошибках»: %d, want 3", len(evs))
	}
	for _, ev := range evs {
		if ev.Reason != string(access.ReasonMTProtoReplay) {
			t.Errorf("reason=%q", ev.Reason)
		}
		if strings.Contains(ev.Description, hex.EncodeToString(key[:4])) {
			t.Errorf("секрет в записи: %s", ev.Description)
		}
	}
	body := metricsText(t, m.metricsURL, metricsBear)
	if !hasNonZero(body, `tgp_mtproto_handshake_failures_total{reason="replay"}`) {
		t.Errorf("нет tgp_mtproto_handshake_failures_total{reason=replay}:\n%s", grepLines(body, "tgp_mtproto_"))
	}
}

// Лимит на IP: отказ виден в метриках, в счётчик автобана не идёт. reload=true:
// лимит приходит по SIGHUP (Reload) и применяется без рестарта.
func TestMTProtoConnLimitRecordedAndNotBanned(t *testing.T) {
	for _, reload := range []bool{false, true} {
		t.Run("reload="+strconv.FormatBool(reload), func(t *testing.T) {
			perIP := 1
			if reload {
				perIP = 1000
			}
			m := newMTEnv(t, mtOpts{obs: true, maxPerIP: perIP})
			_, key := m.newSecret("main")
			m.probeOK(key)
			if reload {
				m.cfg.MTProto.MaxConnsPerIP = 1
				if err := m.srv.Reload(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			checkConnLimit(t, m, key)
		})
	}
}

func checkConnLimit(t *testing.T, m *mtEnv, key [16]byte) {
	t.Helper()
	hello := probe.ClientHello(key, mtDomain, time.Now())
	var hold net.Conn
	m.waitFor(10*time.Second, "слот IP для удерживаемого соединения", func() bool {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", m.mtAddr)
		if err != nil {
			return false
		}
		if _, err := c.Write(hello); err == nil {
			if _, err := readFirstRecordType(c); err == nil {
				hold = c
				return true
			}
		}
		_ = c.Close()
		return false
	})
	defer func() {
		_ = hold.Close()
		// mtg гонится при Shutdown во время рукопожатия: дожидаемся завершения всех сессий.
		m.waitFor(10*time.Second, "сессии MTProto завершены", func() bool { return m.srv.mt.journal.ActiveConns() == 0 })
	}()
	m.waitFor(10*time.Second, "conn_limit в метриках", func() bool {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", m.mtAddr)
		if err == nil {
			_ = c.Close()
		}
		return hasNonZero(metricsText(t, m.metricsURL, metricsBear), `tgp_mtproto_handshake_failures_total{reason="conn_limit"}`)
	})
	if bans, _ := m.srv.st.Bans().ListActive(context.Background(), time.Now()); len(bans) != 0 {
		t.Fatalf("conn_limit не должен банить: %v", bans)
	}
}
