package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/probe"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Сквозной тест «ключ MTProto-секрета нигде»: после полного жизненного цикла
// (создание, ссылка со свежим TOTP, probe через dial- и reverse-агента, replay,
// ротация, отзыв) ключ не должен встречаться ни в логах сервера и агентов, ни в
// метриках, ни в ответах API (кроме create/rotate/link), аудите, HTML экранов
// (кроме модалки показа ссылки) и дампе БД; secret_enc хранит ключ только
// зашифрованным.

// mtKeyForms — все представления ключа и домена-секрета, которые нельзя встретить в выходах.
func mtKeyForms(key [16]byte, domain string) map[string]string {
	secret := append(append([]byte{0xee}, key[:]...), domain...)
	h := hex.EncodeToString(key[:])
	out := map[string]string{
		"hex":          h,
		"HEX":          strings.ToUpper(h),
		"ee+hex":       "ee" + h,
		"ee+hex+домен": "ee" + h + hex.EncodeToString([]byte(domain)),
	}
	for name, enc := range map[string]*base64.Encoding{
		"std": base64.StdEncoding, "url": base64.URLEncoding, "raw-std": base64.RawStdEncoding, "raw-url": base64.RawURLEncoding,
	} {
		out["base64-"+name+" ключ"] = enc.EncodeToString(key[:])
		out["base64-"+name+" ee-секрет"] = enc.EncodeToString(secret)
	}
	return out
}

// mtShapeRe — форма любого FakeTLS-секрета (не только известных ключей) и длинный secret= в ссылках.
var mtShapeRe = regexp.MustCompile(`(?:^|[^0-9a-fA-F])ee[0-9a-fA-F]{32,}|secret=(?:ee)?[0-9a-fA-F]{32,}|secret=[A-Za-z0-9_-]{22,}`)

// startMTDial запускает dial-агента с MTProto и fake-DC, регистрирует его в БД сервера.
func (e *pkiEnv) startMTDial(id, dcAddr string) *e2eAgent {
	e.t.Helper()
	files := e.issue(id)
	acfg := e.agentConfig(files, config.AgentModeDial)
	ma := freeAddr(e.t)
	acfg.Listen.Metrics = ma
	acfg.MTProto.DCProbeInterval = time.Second
	acfg.OverrideMTProtoDCs(map[int][]netip.AddrPort{2: {netip.MustParseAddrPort(dcAddr)}})
	ln := listen(e.t)
	ctx, cancel := context.WithCancel(context.Background())
	a := &e2eAgent{id: id, addr: ln.Addr().String(), metricsAddr: ma, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(a.done)
		_ = RunAgent(ctx, acfg, e.srv.logger, AgentOptions{Agent: []agent.Option{agent.WithUpstreamRootCAs(e.upPool)}, Listener: ln})
	}()
	e.agents = append(e.agents, a)
	e.addAgent(id, store.ModeDial, "https://"+a.addr)
	return a
}

func TestE2EMTProtoKeyNowhere(t *testing.T) {
	e := newPKIEnvWith(t, pkiOpts{mtproto: true, ticks: true, scfg: func(c *config.ServerConfig) { c.MTProto.PublicPort = 4443 }})
	dcD, dcDAddr, err := probe.NewFakeDC()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dcD.Close() })
	dcR, dcRAddr, err := probe.NewFakeDC()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dcR.Close() })

	d1 := e.startMTDial("d1", dcDAddr)
	nfiles := e.issue("nat1")
	e.addAgent("nat1", store.ModeReverse, "")
	nacfg := e.agentConfig(nfiles, config.AgentModeReverse)
	nacfg.Listen.Metrics = freeAddr(t)
	nacfg.MTProto.DCProbeInterval = time.Second
	nacfg.OverrideMTProtoDCs(map[int][]netip.AddrPort{2: {netip.MustParseAddrPort(dcRAddr)}})
	e.startReverse("nat1", nacfg)
	e.waitFor(15*time.Second, "agents up", func() bool { return e.up("d1") && e.up("nat1") })
	e.waitFor(10*time.Second, "mtproto reverse conns", func() bool { return e.srv.pki.mtpool.Conns("nat1") >= 1 })

	c := newAdminClient(t, e.adminURL)
	c.hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // тестовый самоподписанный сертификат
	t.Cleanup(c.hc.CloseIdleConnections)
	c.login()
	mtAddr := strings.TrimPrefix(e.proxyURL, "https://")

	// --- сценарий ---
	type created struct {
		ID   int64 `json:"id"`
		Link *struct {
			TG string `json:"tg"`
		} `json:"link"`
	}
	mustCreated := func(what string, r adminResp, body string) (created, [16]byte) {
		t.Helper()
		var cr created
		if r.StatusCode >= 300 || json.Unmarshal([]byte(body), &cr) != nil || cr.Link == nil {
			t.Fatalf("%s: %d %.200s", what, r.StatusCode, body)
		}
		return cr, keyFromLink(t, cr.Link.TG)
	}
	r, body := c.jsonBody("POST", "/api/v1/mtproto/secrets", `{"name":"leakcheck"}`)
	cr, keyA := mustCreated("create", r, body)
	idA := strconv.FormatInt(cr.ID, 10)

	probeBoth := func(key [16]byte) {
		t.Helper()
		e.waitFor(30*time.Second, "probe через dial- и reverse-агента", func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = probe.Run(ctx, mtAddr, key, mtDomain)
			cancel()
			return dcD.Answered() >= 1 && dcR.Answered() >= 1
		})
	}
	probeBoth(keyA)

	// ссылка: без свежего TOTP — 401, после подтверждения — 200
	linkPath := "/api/v1/mtproto/secrets/" + idA + "/link"
	sum := sha256.Sum256([]byte(c.cookie.Value))
	if err := e.srv.st.RateState().Delete(context.Background(), "totp:fresh:"+hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if r, b := c.do("GET", linkPath, nil, nil); r.StatusCode != http.StatusUnauthorized || !strings.Contains(b, "totp_required") {
		t.Fatalf("link без свежего TOTP: %d %s", r.StatusCode, b)
	}
	if r, b := c.jsonBody("POST", "/api/v1/auth/totp/confirm", `{"code":"000000"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("totp confirm: %d %s", r.StatusCode, b)
	}
	if r, b := c.do("GET", linkPath, nil, nil); r.StatusCode != http.StatusOK || !strings.Contains(b, "tg://proxy?") {
		t.Fatalf("link: %d %s", r.StatusCode, b)
	}

	// replay: те же байты ClientHello повторно уходят на сайт и попадают в журнал
	hello := probe.ClientHello(keyA, mtDomain, time.Now())
	for range 2 {
		cn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", mtAddr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = cn.Write(hello)
		_, _ = readFirstRecordType(cn)
		_ = cn.Close()
	}
	// чужой ключ
	if _, err := func() (probe.Result, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return probe.Run(ctx, mtAddr, [16]byte{0xAB}, mtDomain)
	}(); err == nil {
		t.Fatal("probe с чужим ключом прошёл")
	}

	// PATCH, затем ротация (grace=0): новый ключ работает, старый нет
	if r, b := c.jsonBody("PATCH", "/api/v1/mtproto/secrets/"+idA, `{"max_conns":50}`); r.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d %s", r.StatusCode, b)
	}
	r, body = c.do("POST", "/api/v1/mtproto/secrets/"+idA+"/rotate", jsonHdr, strings.NewReader(`{}`))
	cr2, keyB := mustCreated("rotate", r, body)
	if keyB == keyA {
		t.Fatal("ротация вернула тот же ключ")
	}
	probeBoth(keyB)
	e.waitFor(10*time.Second, "старый ключ отвергается", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := probe.Run(ctx, mtAddr, keyA, mtDomain)
		return err != nil
	})

	// экраны, формы и API (без модалки показа ссылки и ответов create/rotate/link)
	var cp corpus
	idB := strconv.FormatInt(cr2.ID, 10)
	for _, p := range []string{
		"/", "/mtproto", "/mtproto/list", "/mtproto/new", "/mtproto/" + idB + "/rotate", "/mtproto/" + idB + "/revoke",
		"/errors", "/agents", "/access", "/system",
		"/api/v1/mtproto/secrets", "/api/v1/mtproto/stats", "/api/v1/errors", "/api/v1/agents",
		"/api/v1/stats/summary", "/api/v1/stats/timeseries?range=1h", "/api/v1/inflight",
	} {
		hdr := map[string]string(nil)
		if strings.HasPrefix(p, "/mtproto/") && p != "/mtproto/list" {
			hdr = map[string]string{"HX-Request": "true"}
		}
		rr, b := c.do("GET", p, hdr, nil)
		if rr.StatusCode >= 500 {
			t.Fatalf("GET %s: %d", p, rr.StatusCode)
		}
		cp.add("admin GET "+strings.SplitN(p, "?", 2)[0]+" "+resp2s(rr.StatusCode), b)
	}

	// отзыв и прогон журналов в БД
	if r, b := c.do("DELETE", "/api/v1/mtproto/secrets/"+idB+"?confirm=yes", nil, nil); r.StatusCode >= 300 {
		t.Fatalf("revoke: %d %s", r.StatusCode, b)
	}
	e.waitFor(10*time.Second, "отзыв применён", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := probe.Run(ctx, mtAddr, keyB, mtDomain)
		return err != nil
	})
	e.ticks <- time.Now()
	e.ticks <- time.Now()
	for _, p := range []string{"/api/v1/errors", "/api/v1/mtproto/secrets", "/api/v1/mtproto/stats"} {
		_, b := c.do("GET", p, nil, nil)
		cp.add("admin GET (после отзыва) "+p, b)
	}
	// аудит (админ-API журнала нет — читаем из store): все действия на месте, ключа нет
	entries, err := e.srv.st.Audit().List(context.Background(), store.AuditQuery{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var auditText strings.Builder
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
		auditText.WriteString(en.Actor + " " + en.Action + " " + en.Target + " " + en.IP + " " + en.Detail + "\n")
	}
	for _, act := range []string{"mtproto_secret.create", "mtproto_secret.reveal", "mtproto_secret.rotate", "mtproto_secret.revoke"} {
		if !seen[act] {
			t.Errorf("в аудите нет %s", act)
		}
	}
	cp.add("audit log", auditText.String())

	// --- сбор выходов ---
	logs := e.logs.String()
	cp.add("server+agents logs", logs)
	smetrics := metricsText(t, e.metrics, pkiMetricsBearer)
	cp.add("server /metrics", smetrics)
	cp.add("agent /metrics d1", fetchMetrics(t, d1.metricsAddr, ""))
	cp.add("agent /metrics nat1", fetchMetrics(t, nacfg.Listen.Metrics, ""))

	dbPath := filepath.Join(e.dir, "tgproxy.db")
	cp.add("sqlite tables dump", dumpSQLite(t, dbPath))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if raw, err := os.ReadFile(dbPath + suffix); err == nil {
			cp.add("sqlite raw file "+suffix, string(raw))
		}
	}

	// контроль: сценарий действительно выполнился, корпус не пуст
	if len(logs) < 200 || len(smetrics) < 200 || !hasNonZero(smetrics, "tgp_mtproto_connections_total") {
		t.Fatal("пустые логи/метрики или нет MTProto-активности: проверка бессмысленна")
	}
	if !strings.Contains(logs, "mtproto: replayed ClientHello") {
		t.Error("replay не зафиксирован в логе: сценарий не дошёл до проверяемого пути")
	}

	forbidden := map[string]string{}
	for name, key := range map[string][16]byte{"A": keyA, "B": keyB} {
		for form, needle := range mtKeyForms(key, mtDomain) {
			forbidden["ключ "+name+" ("+form+")"] = needle
		}
		forbidden["ключ "+name+" (сырые байты)"] = string(key[:])
	}
	for name, b := range cp.items {
		data := b.String()
		for what, needle := range forbidden {
			if i := strings.Index(data, needle); i >= 0 {
				t.Errorf("УТЕЧКА: %s найден в %q (смещение %d)", what, name, i)
			}
		}
		if loc := mtShapeRe.FindStringIndex(data); loc != nil {
			t.Errorf("УТЕЧКА: FakeTLS-секрет/secret= по форме в %q (смещение %d)", name, loc[0])
		}
	}

	// secret_enc: не открытый ключ, но расшифровывается KEK под AAD строки
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(context.Background(), `SELECT id, secret_enc FROM mtproto_secrets`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var id int64
		var enc []byte
		if err := rows.Scan(&id, &enc); err != nil {
			t.Fatal(err)
		}
		n++
		for _, key := range [][16]byte{keyA, keyB} {
			if bytes.Contains(enc, key[:]) || bytes.Contains(enc, []byte(hex.EncodeToString(key[:]))) {
				t.Errorf("secret_enc строки %d содержит ключ в открытом виде", id)
			}
		}
		pt, err := e.srv.mt.kek.Open(enc, []byte("mtproto/"+strconv.FormatInt(id, 10)))
		if err != nil || len(pt) != 16 {
			t.Errorf("secret_enc строки %d не расшифровывается KEK под своим AAD: %v", id, err)
		}
		if _, err := e.srv.mt.kek.Open(enc, []byte("mtproto/0")); err == nil {
			t.Errorf("secret_enc строки %d открывается под чужим AAD", id)
		}
	}
	if n < 2 {
		t.Fatalf("в БД %d секретов, want ≥2 (исходный и ротированный)", n)
	}
}

// Контроль детектора: утечка в любой форме обязана быть найдена.
func TestMTProtoLeakDetectorFindsLeaks(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	forms := mtKeyForms(key, "ing.test")
	for _, in := range []string{
		"x " + forms["hex"] + " y", "tg://proxy?server=h&port=1&secret=" + forms["ee+hex+домен"],
		"secret=" + forms["base64-raw-url ee-секрет"],
	} {
		hit := mtShapeRe.MatchString(in)
		for _, n := range forms {
			hit = hit || strings.Contains(in, n)
		}
		if !hit {
			t.Fatalf("детектор пропустил %q", in)
		}
	}
}
