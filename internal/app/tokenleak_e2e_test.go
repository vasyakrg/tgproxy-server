package app

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/agent"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Сквозной тест «токен нигде»: токен бота, пройдя все пути (успех, ошибки апстрима, 429, обрыв,
// отказ доступа, мусорные пути, поля админ-API), не должен остаться ни в одном выходе —
// логах сервера и агентов, метриках, БД (таблицы и сырые файлы), ответах админки, SSE и алертах.

const (
	leakToken  = "987654321:AAGsecretSecretSecret_leak-CheckXYZ123"
	leakSecret = "AAGsecretSecretSecret_leak-CheckXYZ123"
)

var botTokenLike = regexp.MustCompile(`[0-9]{5,15}(?::|%3[Aa])[A-Za-z0-9_-]{30,}`)

type corpus struct{ items map[string]*strings.Builder }

func (c *corpus) add(name, data string) {
	if c.items == nil {
		c.items = map[string]*strings.Builder{}
	}
	if c.items[name] == nil {
		c.items[name] = &strings.Builder{}
	}
	c.items[name].WriteString(data)
	c.items[name].WriteByte('\n')
}

// check не печатает найденные значения — только где и в каком виде найдено.
func (c *corpus) check(t *testing.T, forbidden map[string]string) {
	t.Helper()
	for name, b := range c.items {
		data := b.String()
		for what, needle := range forbidden {
			if i := strings.Index(data, needle); i >= 0 {
				t.Errorf("УТЕЧКА: %s найден в %q (смещение %d)", what, name, i)
			}
		}
		if loc := botTokenLike.FindStringIndex(data); loc != nil {
			t.Errorf("УТЕЧКА: токеноподобная строка в %q (смещение %d)", name, loc[0])
		}
	}
}

func dumpSQLite(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	trs, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for trs.Next() {
		var n string
		if err := trs.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	_ = trs.Close()
	var out strings.Builder
	for _, tb := range tables {
		rows, err := db.QueryContext(ctx, `SELECT * FROM "`+tb+`"`) // #nosec G202 -- имя таблицы из sqlite_master
		if err != nil {
			t.Fatalf("dump %s: %v", tb, err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&out, "%s:", tb)
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					fmt.Fprintf(&out, " %s=%s|%x", cols[i], b, b)
				} else {
					fmt.Fprintf(&out, " %s=%v", cols[i], v)
				}
			}
			out.WriteByte('\n')
		}
		_ = rows.Close()
	}
	return out.String()
}

func fetchMetrics(t *testing.T, addr, bearer string) string {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/metrics", http.NoBody)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	return b.String()
}

// freeAddr резервирует loopback-адрес для /metrics агента.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// startDialAgent запускает dial-агента с листенером и регистрирует его в БД сервера.
func (e *pkiEnv) startDialAgent(id string) *e2eAgent {
	e.t.Helper()
	files := e.issue(id)
	acfg := e.agentConfig(files, config.AgentModeDial)
	ma := freeAddr(e.t)
	acfg.Listen.Metrics = ma
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

func TestE2ETokenNowhere(t *testing.T) {
	e := newPKIEnvWith(t, pkiOpts{rules: []config.AccessRule{localRule("10.0.0.0/8")}, ticks: true})
	var cp corpus
	tok := "/bot" + leakToken

	var rlHits atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"id":987654321,"is_bot":true,"username":"leak_bot"}}`))
		case strings.HasSuffix(r.URL.Path, "/sendMessage") && r.URL.Query().Get("chat_id") == "7":
			rlHits.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 30","parameters":{"retry_after":30}}`))
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
		case strings.HasSuffix(r.URL.Path, "/sendPhoto"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"ok":false,"error_code":400,"description":"Bad Request: bot %s rejected"}`, leakToken)
		case strings.HasSuffix(r.URL.Path, "/getChat"):
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close() // обрыв: url.Error с токеном в пути на агенте
				}
			}
		case strings.HasSuffix(r.URL.Path, "/deleteMessage"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, "upstream crashed handling %s", r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	})
	e.tgHandler.Store(&h)

	// 2 агента: dial (с листенером) и reverse (за «NAT»)
	d1 := e.startDialAgent("d1")
	nfiles := e.issue("nat1")
	e.addAgent("nat1", store.ModeReverse, "")
	nacfg := e.agentConfig(nfiles, config.AgentModeReverse)
	nacfg.Listen.Metrics = freeAddr(t)
	n1 := e.startReverse("nat1", nacfg)
	n1.metricsAddr = nacfg.Listen.Metrics
	e.waitFor(15*time.Second, "agents up", func() bool { return e.up("d1") && e.up("nat1") })

	// админка: вход и ключ доступа (сеть правил не пускает loopback — бот ходит только по ключу)
	c := newAdminClient(t, e.adminURL)
	c.login()
	resp, body := c.form("/access", url.Values{"name": {"leakcheck"}, "with_key": {"1"}}, map[string]string{"HX-Request": "true"})
	key := webKeyRe.FindString(body)
	if resp.StatusCode != 200 || key == "" {
		t.Fatalf("create key: %d %.300s", resp.StatusCode, body)
	}
	k := "/k/" + key
	forbidden := map[string]string{"ключ доступа": key}

	do := func(method, path string, serverGenerated bool) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, e.proxyURL+path, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		r, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Body.Close() }()
		var b bytes.Buffer
		_, _ = b.ReadFrom(r.Body)
		if serverGenerated {
			cp.add("client-response "+method+" "+resp2s(r.StatusCode), b.String())
			cp.add("client-response headers", fmt.Sprint(r.Header))
		}
	}

	// успех: оба агента, по ключу, токен ещё и в query
	for range 6 {
		do("GET", k+tok+"/getMe", false)
	}
	do("GET", k+tok+"/getMe?x="+url.QueryEscape(leakToken), false)
	// 429: окно открывает апстрим, следующий запрос отвечает сервер
	do("POST", k+tok+"/sendMessage?chat_id=7", false)
	do("POST", k+tok+"/sendMessage?chat_id=7", true)
	// ошибки апстрима: эхо токена в description, обрыв, 500 с токеном в тексте
	do("POST", k+tok+"/sendPhoto?chat_id=8", false) // тело апстрима клиенту отдаётся как есть
	do("GET", k+tok+"/getChat?chat_id=8", true)
	do("POST", k+tok+"/deleteMessage?chat_id=8", false)
	// отказ доступа, webhook, мусорные пути
	do("GET", tok+"/getMe", true)
	do("POST", k+tok+"/setWebhook?url=https://evil.example/"+leakSecret, true)
	do("GET", k+"/bot987654321:short/getMe", true)
	do("GET", k+tok+"/../x", true)
	do("GET", k+tok+"/get%2FMe", true)
	do("GET", k+tok+"/", true)
	do("GET", "/file"+tok+"/../../etc/passwd", true)

	// падение dial-агента: трафик идёт через reverse, затем возврат
	cp.add("agent /metrics d1", fetchMetrics(t, d1.metricsAddr, ""))
	d1.cancel()
	<-d1.done
	e.waitFor(15*time.Second, "d1 down", func() bool { return !e.up("d1") })
	for range 3 {
		do("GET", k+tok+"/getMe", false)
	}

	// админ-API: страницы, журнал ошибок, поля с токеном, установка (SSE) и enrollment
	for _, p := range []string{
		"/", "/agents", "/errors", "/access", "/system", "/audit",
		"/api/v1/agents", "/api/v1/errors", "/api/v1/errors?bot_id=987654321", "/api/v1/errors?q=" + url.QueryEscape(leakToken),
		"/api/v1/stats/summary", "/api/v1/stats/timeseries?range=1h", "/api/v1/inflight", "/api/v1/access-rules",
		"/api/v1/notifications", "/api/v1/audit", "/api/v1/enrollments", "/api/v1/system/version",
	} {
		r, b := c.do("GET", p, nil, nil)
		cp.add("admin GET "+strings.SplitN(p, "?", 2)[0]+" "+resp2s(r.StatusCode), b)
	}
	postJSON := func(path, body string, skipBody bool) string {
		r, out := c.do("POST", path, map[string]string{"Content-Type": "application/json"}, strings.NewReader(body))
		t.Logf("admin POST %s -> %d %.200s", path, r.StatusCode, out)
		if !skipBody {
			cp.add("admin POST "+path+" "+resp2s(r.StatusCode), out)
		}
		return out
	}
	postJSON("/api/v1/hostkeys/probe", fmt.Sprintf(`{"host":"127.0.0.1/%s","port":1}`, leakToken), false)
	postJSON("/api/v1/hostkeys/probe", `{"host":"127.0.0.1","port":1}`, false)
	e.publishRelease("1.0.0", newE2ESigner(t)) // кэш пакетов для установщика
	// установка на недоступный SSH: токен в name/user/password/fingerprint
	if out := postJSON("/api/v1/install-jobs", fmt.Sprintf(`{"name":"leak1","host":"127.0.0.1","ssh_port":1,"user":"root","password":"%s","confirmed_fingerprint":"SHA256:%s"}`,
		leakToken, strings.Repeat("A", 43)), false); strings.Contains(out, `"events_url"`) {
		var j struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(out), &j)
		readSSE(t, c, "/api/v1/install-jobs/"+j.ID+"/events", &cp)
		_, st := c.do("GET", "/api/v1/install-jobs/"+j.ID, nil, nil)
		cp.add("admin install-job status", st)
	} else {
		t.Logf("install-job не создан (ожидаемо без SSH-сервера): %.200s", out)
	}
	// enrollment-токен показывается один раз в ответе и нигде больше не хранится
	if out := postJSON("/api/v1/enrollments", `{"name":"nat-leakcheck","weight":10}`, true); out != "" {
		if m := regexp.MustCompile(`printf %s '([A-Za-z0-9_-]{20,})'`).FindStringSubmatch(out); m != nil {
			forbidden["enrollment-токен"] = m[1]
		} else {
			t.Logf("enrollment: токен не найден в ответе (%.120s)", out)
		}
	}
	// форма с токеном в имени: ответ при ошибке валидации эхом возвращает введённое админом значение
	// (value поля) — это его собственный ввод, в корпус не входит; проверяем, что дальше он нигде не оседает.
	c.form("/access", url.Values{"name": {"rule " + leakToken}, "with_key": {"1"}}, map[string]string{"HX-Request": "true"})

	// сброс батчей истории/журнала ошибок в БД
	e.ticks <- time.Now()
	e.waitFor(10*time.Second, "errors journal flushed", func() bool {
		_, b := c.do("GET", "/api/v1/errors", nil, nil)
		return strings.Contains(b, `"phase"`)
	})
	e.ticks <- time.Now()
	time.Sleep(500 * time.Millisecond)

	// сбор выходов
	logs := e.logs.String()
	cp.add("server logs + agent logs", logs)
	mb := fetchMetrics(t, strings.TrimPrefix(e.metrics, "http://"), pkiMetricsBearer)
	cp.add("server /metrics", mb)
	cp.add("agent /metrics nat1", fetchMetrics(t, n1.metricsAddr, ""))
	dbPath := filepath.Join(e.dir, "tgproxy.db")
	cp.add("sqlite tables dump", dumpSQLite(t, dbPath))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if raw, err := os.ReadFile(dbPath + suffix); err == nil {
			cp.add("sqlite raw file "+suffix, string(raw))
		}
	}

	// контроль: сценарий дошёл до апстрима, корпус не пуст
	if e.tgHits.Load() == 0 || rlHits.Load() == 0 {
		t.Fatalf("сценарий не дошёл до апстрима: hits=%d 429=%d", e.tgHits.Load(), rlHits.Load())
	}
	if len(logs) < 200 || len(mb) < 200 {
		t.Fatal("пустые логи/метрики: проверка бессмысленна")
	}

	forbidden["токен бота"] = leakToken
	forbidden["секрет токена"] = leakSecret
	forbidden["токен (url-encoded)"] = url.QueryEscape(leakToken)
	forbidden["токен (%3A)"] = strings.Replace(leakToken, ":", "%3A", 1)
	forbidden["токен уведомлений"] = notifyToken
	forbidden["секрет токена уведомлений"] = notifyToken[strings.IndexByte(notifyToken, ':')+1:]
	cp.check(t, forbidden)
}

func resp2s(code int) string { return fmt.Sprintf("[%d]", code) }

// readSSE читает поток событий задачи до закрытия (задача завершается ошибкой подключения) или таймаута.
func readSSE(t *testing.T, c *adminClient, path string, cp *corpus) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(c.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cp.add("install SSE (error)", err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		cp.add("install SSE", line)
		if strings.HasPrefix(line, "event: fail") || strings.HasPrefix(line, "event: done") {
			// дочитываем data: этого события и выходим
			if sc.Scan() {
				cp.add("install SSE", sc.Text())
			}
			return
		}
	}
}

// Контроль самого детектора: утечка в любой форме обязана быть найдена.
func TestTokenLeakDetectorFindsLeaks(t *testing.T) {
	for _, data := range []string{
		"GET /bot" + leakToken + "/getMe",
		"secret=" + leakSecret,
		"x " + strings.Replace(leakToken, ":", "%3A", 1),
		"other 111111:" + strings.Repeat("Q", 35), // любой токеноподобный
	} {
		if !botTokenLike.MatchString(data) && !strings.Contains(data, leakSecret) {
			t.Fatalf("детектор пропустил %q", data)
		}
	}
}
