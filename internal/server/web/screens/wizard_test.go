package screens_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/enroll"
	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const fpShown = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"

var pendingRe = regexp.MustCompile(`name="pending" value="([^"]+)"`)

func sshForm(extra url.Values) url.Values {
	v := url.Values{
		"name": {"ams-2"}, "host": {"91.204.8.4"}, "ssh_port": {"22"}, "user": {"root"}, "agent_port": {"8443"}, "weight": {"100"},
		"auth": {"password"}, "password": {wSecretPw},
	}
	for k, vs := range extra {
		v[k] = vs
	}
	return v
}

func (a *agFx) leakCheck(t *testing.T, bodies ...string) {
	t.Helper()
	for i, b := range bodies {
		noSecrets(t, fmt.Sprintf("ответ #%d", i), b)
	}
	noSecrets(t, "логи", a.logs.String())
	noSecrets(t, "аудит", fmt.Sprintf("%+v", a.audit()))
}

func TestWizardPages(t *testing.T) {
	a := newAgFx(t, agOpts{})
	code, body, _ := a.call("GET", "/agents/new", nil, false)
	if code != 200 {
		t.Fatalf("%d", code)
	}
	assertStrictCSP(t, body)
	contains(
		t, "ssh", body,
		"<title>Новый агент — tgproxy</title>", "← Агенты", "Сервер → агент, установка по SSH", "Агент → сервер, агент за NAT",
		`name="name"`, `name="host"`, `name="ssh_port"`, `name="user"`, `name="agent_port"`, `name="weight"`, `value="22"`, `value="8443"`, `value="100"`,
		`name="private_key"`, `name="passphrase"`, `name="password"`, "Приватный ключ", "Пароль", "не сохраняются", "Что сделает установщик",
		`hx-post="/agents/new/ssh"`, `aria-current="step"`, "Хост и доступ", "Ключ хоста", "Установка",
	)
	// поля секретов не должны подсказываться браузером
	for _, name := range []string{"password", "passphrase"} {
		re := regexp.MustCompile(`<input[^>]*name="` + name + `"[^>]*>`)
		in := re.FindString(body)
		if !strings.Contains(in, `type="password"`) || !strings.Contains(in, `autocomplete="new-password"`) {
			t.Errorf("поле %s: %s", name, in)
		}
	}
	if !regexp.MustCompile(`<form[^>]*autocomplete="off"`).MatchString(body) || !strings.Contains(body, `<textarea class="textarea mono" id="w-key" name="private_key"`) {
		t.Error("форма без autocomplete=off")
	}
	if !regexp.MustCompile(`<textarea[^>]*autocomplete="off"`).MatchString(body) {
		t.Error("textarea ключа без autocomplete=off")
	}

	_, body, _ = a.call("GET", "/agents/new?mode=nat", nil, false)
	assertStrictCSP(t, body)
	contains(t, "nat", body, `hx-post="/agents/new/nat"`, `name="ttl"`, "Выпустить токен", "Ожидающие подключения", "Неиспользованных токенов нет", `hx-trigger="every 10s"`)
}

func TestWizardNotConfigured(t *testing.T) {
	a := newAgFx(t, agOpts{noInstall: true, noEnroll: true})
	_, body, _ := a.call("GET", "/agents/new", nil, false)
	contains(t, "ssh", body, "Установка по SSH не настроена")
	_, body, _ = a.call("GET", "/agents/new?mode=nat", nil, false)
	contains(t, "nat", body, "Подключение за NAT не настроено")
	code, body, _ := a.call("POST", "/agents/new/ssh", sshForm(nil), true)
	if code != 422 || !strings.Contains(body, "Установка по SSH не настроена") {
		t.Errorf("ssh: %d %s", code, body)
	}
	if code, body, _ = a.call("POST", "/agents/new/nat", url.Values{"name": {"x"}}, true); code != 200 || !strings.Contains(body, "не настроено") {
		t.Errorf("nat: %d %s", code, body)
	}
	if c, _, _ := a.call("GET", "/agents/new/jobs/J1", nil, false); c != http.StatusNotImplemented {
		t.Errorf("job page: %d", c)
	}
	if c, _, _ := a.call("GET", "/agents/new/nat/pending", nil, true); c != 200 {
		t.Errorf("pending: %d", c)
	}
}

func TestSSHSubmitValidationDoesNotEchoSecrets(t *testing.T) {
	a := newAgFx(t, agOpts{})
	cases := map[string]url.Values{
		"name":       sshForm(url.Values{"name": {"bad name!"}}),
		"host":       sshForm(url.Values{"host": {""}}),
		"ssh_port":   sshForm(url.Values{"ssh_port": {"99999"}}),
		"agent_port": sshForm(url.Values{"agent_port": {"abc"}}),
		"weight":     sshForm(url.Values{"weight": {"0"}}),
		"user":       sshForm(url.Values{"user": {"Bad User"}}),
		"auth":       sshForm(url.Values{"password": {""}}),
	}
	var bodies []string
	for field, form := range cases {
		code, body, _ := a.call("POST", "/agents/new/ssh", form, true)
		bodies = append(bodies, body)
		if code != 422 || !strings.Contains(body, "field-error") {
			t.Errorf("%s: %d", field, code)
		}
		if strings.Contains(body, wSecretPw) || regexp.MustCompile(`name="password"[^>]*value="[^"]`).MatchString(body) {
			t.Errorf("%s: пароль возвращён в форму", field)
		}
	}
	if a.probes != 0 || len(a.inst.reqs) != 0 {
		t.Errorf("сеть/установщик вызваны при невалидном вводе: %d %d", a.probes, len(a.inst.reqs))
	}
	if c, _, _ := a.call("POST", "/agents/new/ssh", sshForm(nil), false); c != 400 {
		t.Errorf("не htmx: %d", c)
	}
	// форма сохраняет несекретные поля и просит ввести секреты заново
	_, body, _ := a.call("POST", "/agents/new/ssh", sshForm(url.Values{"name": {"bad name!"}, "host": {"h.example.com"}}), true)
	contains(t, "форма", body, `value="h.example.com"`, "введите их заново")
	a.leakCheck(t, append(bodies, body)...)
}

func TestSSHUnknownHostConfirmFlow(t *testing.T) {
	a := newAgFx(t, agOpts{})
	code, body, _ := a.call("POST", "/agents/new/ssh", sshForm(nil), true)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	contains(t, "шаг 2", body, "Проверьте ключ хоста", "91.204.8.4:22", "ED25519", fpShown, "Отклонить", "Отпечаток совпадает, установить", `value="confirm"`, `value="reject"`)
	if len(a.inst.reqs) != 0 {
		t.Fatal("установка запущена до подтверждения отпечатка")
	}
	m := pendingRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("нет pending id: %s", body)
	}
	pid := m[1]
	// чужая сессия не может подтвердить
	bob := a.sessionCookie("bob")
	w := a.do(req{method: "POST", path: "/agents/new/ssh/confirm", form: url.Values{"pending": {pid}, "action": {"confirm"}}, hdr: hx, cookies: []*http.Cookie{bob}})
	if w.Code != 422 || len(a.inst.reqs) != 0 {
		t.Fatalf("чужое подтверждение: %d reqs=%d", w.Code, len(a.inst.reqs))
	}
	code, body2, hdr := a.call("POST", "/agents/new/ssh/confirm", url.Values{"pending": {pid}, "action": {"confirm"}}, true)
	if code != 200 || hdr.Get("HX-Redirect") != "/agents/new/jobs/01JOBJOBJOBJOBJOBJOBJOBJOB" {
		t.Fatalf("confirm: %d %v %s", code, hdr, body2)
	}
	if len(a.inst.reqs) != 1 {
		t.Fatalf("reqs %d", len(a.inst.reqs))
	}
	r := a.inst.reqs[0]
	if r.Name != "ams-2" || r.Host != "91.204.8.4" || r.User != "root" || r.SSHPort != 22 || r.AgentPort != 8443 || r.Weight != 100 ||
		r.ConfirmedFingerprint != fpShown || string(r.Auth.Password) != wSecretPw {
		t.Errorf("req %+v", r)
	}
	if au := a.audit(); len(au) != 1 || au[0].Actor != "alice" || !strings.Contains(au[0].Detail, "auth=password") {
		t.Errorf("audit %+v", au)
	}
	// одноразовость
	if code, _, _ := a.call("POST", "/agents/new/ssh/confirm", url.Values{"pending": {pid}, "action": {"confirm"}}, true); code != 422 || len(a.inst.reqs) != 1 {
		t.Errorf("повторное подтверждение: %d reqs=%d", code, len(a.inst.reqs))
	}
	a.leakCheck(t, body, body2)
}

func TestSSHKeyAuthWithPassphrase(t *testing.T) {
	a := newAgFx(t, agOpts{})
	form := sshForm(url.Values{"auth": {"key"}, "private_key": {wSecretKey}, "passphrase": {wSecretPass}, "password": {"ignored-pw-SECRET"}})
	_, body, _ := a.call("POST", "/agents/new/ssh", form, true)
	pid := pendingRe.FindStringSubmatch(body)[1]
	_, body2, _ := a.call("POST", "/agents/new/ssh/confirm", url.Values{"pending": {pid}, "action": {"confirm"}}, true)
	r := a.inst.reqs[0]
	if string(r.Auth.PrivateKeyPEM) != wSecretKey || string(r.Auth.Passphrase) != wSecretPass || len(r.Auth.Password) != 0 {
		t.Errorf("auth: key=%q pass=%q pw=%q", r.Auth.PrivateKeyPEM, r.Auth.Passphrase, r.Auth.Password)
	}
	a.leakCheck(t, body, body2)
	noSecrets(t, "ignored", body+body2)
	if strings.Contains(body+body2+a.logs.String(), "ignored-pw-SECRET") {
		t.Error("игнорируемый пароль просочился")
	}
}

func TestSSHRejectReturnsFormWithoutSecrets(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, body, _ := a.call("POST", "/agents/new/ssh", sshForm(url.Values{"host": {"srv.example.com"}}), true)
	pid := pendingRe.FindStringSubmatch(body)[1]
	code, body2, _ := a.call("POST", "/agents/new/ssh/confirm", url.Values{"pending": {pid}, "action": {"reject"}}, true)
	if code != 200 {
		t.Fatalf("%d", code)
	}
	contains(t, "reject", body2, `value="srv.example.com"`, "введите их заново", `hx-post="/agents/new/ssh"`)
	if len(a.inst.reqs) != 0 {
		t.Error("установка запущена после отказа")
	}
	// запись забыта
	if code, _, _ := a.call("POST", "/agents/new/ssh/confirm", url.Values{"pending": {pid}, "action": {"confirm"}}, true); code != 422 {
		t.Errorf("confirm после reject: %d", code)
	}
	if code, b3, _ := a.call("POST", "/agents/new/ssh/confirm", url.Values{"pending": {"unknown"}, "action": {"reject"}}, true); code != 200 || !strings.Contains(b3, `name="host"`) {
		t.Errorf("reject неизвестного: %d", code)
	}
	a.leakCheck(t, body, body2)
}

func TestSSHPinnedHostSkipsConfirmation(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_ = a.st.HostKeys().Put(context.Background(), store.HostKey{Host: "91.204.8.4:22", Algo: "ssh-ed25519", Fingerprint: fpShown, PublicKey: []byte{1}})
	code, body, hdr := a.call("POST", "/agents/new/ssh", sshForm(nil), true)
	if code != 200 || hdr.Get("HX-Redirect") == "" || len(a.inst.reqs) != 1 {
		t.Fatalf("pinned+match: %d %v reqs=%d", code, hdr, len(a.inst.reqs))
	}
	if a.inst.reqs[0].ConfirmedFingerprint != "" {
		t.Errorf("подтверждение не требуется: %+v", a.inst.reqs[0])
	}
	// закреплённый ключ другой: возможна подмена, установка не стартует
	_ = a.st.HostKeys().Put(context.Background(), store.HostKey{Host: "91.204.8.4:22", Algo: "ssh-ed25519", Fingerprint: "SHA256:OTHER", PublicKey: []byte{1}})
	code, body2, hdr2 := a.call("POST", "/agents/new/ssh", sshForm(nil), true)
	if code != 422 || hdr2.Get("HX-Redirect") != "" || len(a.inst.reqs) != 1 || !strings.Contains(body2, "возможна подмена") {
		t.Errorf("pinned+mismatch: %d reqs=%d %s", code, len(a.inst.reqs), body2)
	}
	a.leakCheck(t, body, body2)
}

func TestSSHProbeAndInstallerFailures(t *testing.T) {
	a := newAgFx(t, agOpts{})
	a.probe = func(installer.Target) (string, string, error) {
		return "", "", errors.New("dial tcp 91.204.8.4:22: connection refused")
	}
	code, body, _ := a.call("POST", "/agents/new/ssh", sshForm(nil), true)
	if code != 422 || !strings.Contains(body, "connection refused") {
		t.Errorf("probe: %d %s", code, body)
	}
	a.probe = func(installer.Target) (string, string, error) { return "ssh-ed25519", fpShown, nil }

	_ = a.st.HostKeys().Put(context.Background(), store.HostKey{Host: "91.204.8.4:22", Algo: "ssh-ed25519", Fingerprint: fpShown, PublicKey: []byte{1}})
	for _, c := range []struct {
		err  error
		want string
	}{
		{installer.ErrPassphraseRequired, "Ключ зашифрован: введите passphrase"},
		{installer.ErrBadPassphrase, "Passphrase не подходит"},
		{fmt.Errorf("dup: %w", store.ErrConflict), "Агент с таким именем уже есть"},
		{installer.ErrHostKeyMismatch, "возможна подмена"},
		{errors.New("installer: в кэше нет пакетов tgproxy"), "нет пакетов"},
		{errors.New("db down " + wSecretPw), "Подробности в журнале"},
	} {
		a.inst.err = c.err
		code, b, _ := a.call("POST", "/agents/new/ssh", sshForm(nil), true)
		if code != 422 || !strings.Contains(b, c.want) {
			t.Errorf("%v: %d %s", c.err, code, b)
		}
		a.leakCheck(t, b)
	}
}

func TestInstallPage(t *testing.T) {
	a := newAgFx(t, agOpts{})
	fin := agNow.Add(time.Minute)
	a.inst.status = installer.JobStatus{
		ID: "01JOBJOBJOBJOBJOBJOBJOBJOB", AgentID: "ams-2", Host: "91.204.8.4:22", State: store.InstallRunning, CreatedAt: agNow, FinishedAt: &fin,
		Steps: []installer.StepStatus{
			{Key: "ssh", Label: "SSH-подключение, ключ хоста закреплён", Status: "ok"},
			{Key: "upload", Label: "Загрузка пакета tgproxy 1.4.1", Status: "running"},
			{Key: "install", Label: "Установка пакета и пользователей", Status: "pending"},
		},
	}
	code, body, _ := a.call("GET", "/agents/new/jobs/01JOBJOBJOBJOBJOBJOBJOBJOB", nil, false)
	if code != 200 {
		t.Fatalf("%d", code)
	}
	assertStrictCSP(t, body)
	contains(t, "job", body, "Установка ams-2", `data-events-url="/api/v1/install-jobs/01JOBJOBJOBJOBJOBJOBJOBJOB/events"`,
		`data-status-url="/api/v1/install-jobs/01JOBJOBJOBJOBJOBJOBJOBJOB"`, `data-step="ssh" data-status="ok"`, `data-step="upload" data-status="running"`,
		`data-step="install" data-status="pending"`, "Загрузка пакета tgproxy 1.4.1", `id="job-log"`, `src="/static/js/install.js`, "выполняется",
		`data-started="`+fmt.Sprint(agNow.UnixMilli())+`"`, `data-finished="`+fmt.Sprint(fin.UnixMilli())+`"`)
	a.inst.status.AgentID = ""
	_, body, _ = a.call("GET", "/agents/new/jobs/01JOBJOBJOBJOBJOBJOBJOBJOB", nil, false)
	contains(t, "title", body, "Установка 91.204.8.4:22")
	a.inst.stErr = store.ErrNotFound
	if c, _, _ := a.call("GET", "/agents/new/jobs/01JOBJOBJOBJOBJOBJOBJOBJOB", nil, false); c != 404 {
		t.Errorf("unknown: %d", c)
	}
	a.inst.stErr = errors.New("db")
	if c, _, _ := a.call("GET", "/agents/new/jobs/01JOBJOBJOBJOBJOBJOBJOBJOB", nil, false); c != 500 {
		t.Errorf("internal: %d", c)
	}
	if c, _, _ := a.call("GET", "/agents/new/jobs/bad%20id", nil, false); c != 404 {
		t.Errorf("bad id: %d", c)
	}
}

func TestNATIssueListRevoke(t *testing.T) {
	a := newAgFx(t, agOpts{})
	code, body, hdr := a.call("POST", "/agents/new/nat", url.Values{"name": {"waw-2"}, "weight": {"80"}, "ttl": {"30"}}, true)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	contains(t, "issued", body, "Токен для «waw-2» выпущен", wToken, `id="enroll-cmd"`, `data-copy="enroll-cmd"`, `aria-label="Копировать команду установки"`,
		`id="enroll-cmd-installed"`, `data-copy="enroll-cmd-installed"`, "Если tgproxy уже установлен на хосте",
		"показана один раз", "Ожидающие подключения", "waw-2", `aria-label="Отозвать токен: waw-2"`, `hx-get="/agents/enroll/0000000000000001/revoke"`)
	if !strings.Contains(hdr.Get("HX-Trigger"), "ok") || strings.Contains(hdr.Get("HX-Trigger"), wToken) {
		t.Errorf("trigger %q", hdr.Get("HX-Trigger"))
	}
	// нет проверенного пакета в кэше → понятное сообщение, без команды
	a.issuer.err = fmt.Errorf("%w: загрузите релиз 1.2.3 в Система → Обновления", enroll.ErrPackageUnavailable)
	code, body, _ = a.call("POST", "/agents/new/nat", url.Values{"name": {"waw-3"}, "weight": {"80"}, "ttl": {"30"}}, true)
	if code != 422 || !strings.Contains(body, "загрузите релиз 1.2.3 в Система → Обновления") || strings.Contains(body, `id="enroll-cmd"`) {
		t.Errorf("пакет недоступен: %d %s", code, body)
	}
	a.issuer.err = nil
	// в списке ожидающих токена нет
	_, list, _ := a.call("GET", "/agents/new/nat/pending", nil, true)
	if !strings.Contains(list, "waw-2") || strings.Contains(list, wToken) || strings.Contains(a.logs.String(), wToken) {
		t.Errorf("список/логи: %s", list)
	}
	pend, _ := a.st.Enrollments().ListPending(context.Background(), agNow)
	if len(pend) != 1 || pend[0].Weight != 80 || pend[0].ExpiresAt != agNow.Add(30*time.Minute) {
		t.Fatalf("pending %+v", pend)
	}
	// отзыв
	_, conf, _ := a.call("GET", "/agents/enroll/0000000000000001/revoke", nil, true)
	contains(t, "confirm", conf, "Отозвать токен?", `name="confirm" value="yes"`, `hx-target="#wiz-modal-body"`)
	if c, _, _ := a.call("POST", "/agents/enroll/0000000000000001/revoke", nil, true); c != 400 {
		t.Fatalf("без confirm: %d", c)
	}
	if p, _ := a.st.Enrollments().ListPending(context.Background(), agNow); len(p) != 1 {
		t.Fatal("токен отозван без подтверждения")
	}
	code, body, hdr = a.call("POST", "/agents/enroll/0000000000000001/revoke", url.Values{"confirm": {"yes"}}, true)
	if code != 200 || !strings.Contains(body, "Неиспользованных токенов нет") || !strings.Contains(body, `hx-swap-oob="true"`) || !strings.Contains(hdr.Get("HX-Trigger"), "ok") {
		t.Errorf("revoke: %d %s", code, body)
	}
	if p, _ := a.st.Enrollments().ListPending(context.Background(), agNow); len(p) != 0 {
		t.Error("токен не отозван")
	}
	if code, body, _ = a.call("POST", "/agents/enroll/0000000000000001/revoke", url.Values{"confirm": {"yes"}}, true); code != 422 || !strings.Contains(body, "не найден") {
		t.Errorf("повторный отзыв: %d %s", code, body)
	}
	if c, _, _ := a.call("GET", "/agents/enroll/NOT-HEX/revoke", nil, true); c != 404 {
		t.Errorf("bad id: %d", c)
	}
	var revokes int
	for _, e := range a.audit() {
		if e.Action == "enrollment.revoke" {
			revokes++
		}
	}
	if revokes != 1 {
		t.Errorf("audit revokes=%d", revokes)
	}
}

func TestNATValidationAndFailure(t *testing.T) {
	a := newAgFx(t, agOpts{})
	for field, form := range map[string]url.Values{
		"name":   {"name": {"bad name"}, "weight": {"10"}, "ttl": {"60"}},
		"weight": {"name": {"a"}, "weight": {"0"}, "ttl": {"60"}},
		"ttl":    {"name": {"a"}, "weight": {"10"}, "ttl": {"5000"}},
	} {
		code, body, _ := a.call("POST", "/agents/new/nat", form, true)
		if code != 422 || !strings.Contains(body, "field-error") {
			t.Errorf("%s: %d", field, code)
		}
	}
	if a.issuer.n != 0 {
		t.Errorf("токен выпущен при невалидном вводе")
	}
	a.issuer.err = errors.New("db down")
	code, body, _ := a.call("POST", "/agents/new/nat", url.Values{"name": {"a"}, "weight": {"10"}, "ttl": {"60"}}, true)
	if code != 422 || !strings.Contains(body, "Подробности в журнале") || strings.Contains(body, "db down") {
		t.Errorf("%d %s", code, body)
	}
	if c, _, _ := a.call("POST", "/agents/new/nat", url.Values{"name": {"a"}}, false); c != 400 {
		t.Errorf("не htmx: %d", c)
	}
}

func TestInstallPageStates(t *testing.T) {
	a := newAgFx(t, agOpts{})
	for state, want := range map[string]string{store.InstallDone: "готово", store.InstallFailed: "не удалось"} {
		a.inst.status = installer.JobStatus{ID: "J1", AgentID: "x", State: state, CreatedAt: agNow}
		_, body, _ := a.call("GET", "/agents/new/jobs/J1", nil, false)
		contains(t, state, body, want, `data-state="`+state+`"`)
	}
}

func TestPendingExpiryLabels(t *testing.T) {
	a := newAgFx(t, agOpts{})
	for ttl, want := range map[string]string{"15": "15 мин", "360": "6 ч 0 мин", "1440": "24 ч 0 мин"} {
		a.call("POST", "/agents/new/nat", url.Values{"name": {"n" + ttl}, "weight": {"1"}, "ttl": {ttl}}, true)
		_, list, _ := a.call("GET", "/agents/new/nat/pending", nil, true)
		if !strings.Contains(list, want) {
			t.Errorf("ttl %s: нет %q\n%s", ttl, want, list)
		}
	}
}

func TestAgentsSummaryPlurals(t *testing.T) {
	a := newAgFx(t, agOpts{})
	base := a.fleet.states[0]
	for n, want := range map[int]string{1: "1 агент ·", 2: "2 агента ·", 5: "5 агентов ·", 11: "11 агентов ·", 21: "21 агент ·"} {
		a.fleet.states = nil
		for i := 0; i < n; i++ {
			s := base
			s.Agent.ID = fmt.Sprintf("a%d", i)
			s.Agent.Name = s.Agent.ID
			a.fleet.states = append(a.fleet.states, s)
		}
		_, body, _ := a.call("GET", "/agents", nil, false)
		if !strings.Contains(body, want) {
			t.Errorf("n=%d: нет %q", n, want)
		}
	}
}

// ---------- отслеживание подключения агента ----------

const natStatusID = "0000000000000001"

// issueNAT выпускает токен waw-2 и гасит его (как это делает POST /enroll), если used.
func (a *agFx) issueNAT(t *testing.T, used bool) string {
	t.Helper()
	code, body, _ := a.call("POST", "/agents/new/nat", url.Values{"name": {"waw-2"}, "weight": {"80"}, "ttl": {"30"}}, true)
	if code != 200 {
		t.Fatalf("issue: %d %s", code, body)
	}
	if used {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", wToken, a.issuer.n)))
		if _, err := a.st.Enrollments().Consume(context.Background(), h[:], agNow); err != nil {
			t.Fatal(err)
		}
	}
	return body
}

func (a *agFx) status(path string) (int, string, http.Header) { return a.call("GET", path, nil, true) }

func TestNATIssuedShowsStatusBlock(t *testing.T) {
	a := newAgFx(t, agOpts{})
	body := a.issueNAT(t, false)
	contains(t, "issued", body, `id="nat-status"`, `hx-get="/agents/enroll/`+natStatusID+`/status"`, `hx-trigger="every 3s"`,
		`hx-swap="outerHTML"`, `class="spinner"`, "Ожидаем подключения агента «waw-2»", "Токен действителен ещё 30 мин")
	assertStrictCSP(t, body)
}

func TestEnrollStatusLifecycle(t *testing.T) {
	a := newAgFx(t, agOpts{})
	issued := a.issueNAT(t, false)
	path := "/agents/enroll/" + natStatusID + "/status"

	// waiting
	code, body, hdr := a.status(path)
	if code != 200 || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("waiting: %d %v", code, hdr)
	}
	contains(t, "waiting", body, `hx-trigger="every 3s"`, "Ожидаем подключения агента «waw-2»", "ещё 30 мин")
	if hdr.Get("HX-Redirect") != "" {
		t.Error("редирект при waiting")
	}
	waiting := body

	// токен использован, агента в реестре ещё нет → enrolled, опрос продолжается
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", wToken, a.issuer.n)))
	if _, err := a.st.Enrollments().Consume(context.Background(), h[:], agNow); err != nil {
		t.Fatal(err)
	}
	_, body, hdr = a.status(path)
	contains(t, "enrolled", body, `hx-trigger="every 3s"`, "зарегистрирован, ждём первое соединение")
	if strings.Contains(hdr.Get("HX-Trigger"), "toast") {
		t.Error("тост до подключения")
	}

	// агент зарегистрирован, но не в работе → всё ещё enrolled
	a.fleet.states = append(a.fleet.states, agState("waw-2", store.ModeReverse, false, "v1.4.1", 90))
	_, body, _ = a.status(path)
	contains(t, "enrolled+agent", body, `hx-trigger="every 3s"`, "ждём первое соединение")

	// агент up → connected: опроса нет, отложенный переход, тост
	a.fleet.states[len(a.fleet.states)-1].Up = true
	code, body, hdr = a.status(path)
	if code != 200 {
		t.Fatalf("connected: %d", code)
	}
	contains(t, "connected", body, "Агент «waw-2» подключился", `hx-get="/agents/enroll/`+natStatusID+`/status?go=1"`, `hx-trigger="load delay:2s"`,
		`href="/agents?highlight=waw-2"`)
	if strings.Contains(body, "every 3s") {
		t.Errorf("опрос не остановлен: %s", body)
	}
	var trig struct {
		Toast struct{ Kind, Message string }
	}
	if err := json.Unmarshal([]byte(hdr.Get("HX-Trigger")), &trig); err != nil || trig.Toast.Kind != "ok" || trig.Toast.Message != "Агент «waw-2» подключился" {
		t.Errorf("тост: %q %v", hdr.Get("HX-Trigger"), err)
	}
	assertStrictCSP(t, body)

	// отложенный запрос → HX-Redirect на /agents с подсветкой
	code, _, hdr = a.status(path + "?go=1")
	if code != 200 || hdr.Get("HX-Redirect") != "/agents?highlight=waw-2" {
		t.Errorf("go=1: %d %v", code, hdr)
	}
	// go=1 без подключения не перенаправляет
	a.fleet.states[len(a.fleet.states)-1].Up = false
	if _, _, hdr = a.status(path + "?go=1"); hdr.Get("HX-Redirect") != "" {
		t.Errorf("редирект без подключения: %v", hdr)
	}
	a.fleet.states[len(a.fleet.states)-1].Up = true

	// агент с другим именем или режимом dial не считается подключённым по этому токену
	a.fleet.states[len(a.fleet.states)-1].Agent.Mode = store.ModeDial
	if _, body, _ = a.status(path); strings.Contains(body, "подключился") {
		t.Error("dial-агент засчитан")
	}

	// отсутствие утечек: токена, хеша, секретов нет нигде
	a.leakCheck(t, issued, waiting, body)
	for _, b := range []string{waiting, body} {
		if strings.Contains(b, wToken) || strings.Contains(b, fmt.Sprintf("%x", h)) {
			t.Errorf("утечка токена/хеша: %s", b)
		}
	}
}

func TestEnrollStatusExpiredAndRevoked(t *testing.T) {
	a := newAgFx(t, agOpts{})
	ctx := context.Background()
	// просроченный неиспользованный
	if err := a.st.Enrollments().Create(ctx, store.Enrollment{ID: "ab", TokenHash: []byte("0123456789abcdef0123456789abcdef"), Name: "old-1", Weight: 100,
		CreatedAt: agNow.Add(-2 * time.Hour), ExpiresAt: agNow.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	code, body, _ := a.status("/agents/enroll/ab/status")
	if code != 200 {
		t.Fatalf("%d", code)
	}
	contains(t, "expired", body, "Токен для «old-1» истёк", `href="/agents/new?mode=nat"`, `aria-label="Выпустить новый токен"`)
	if strings.Contains(body, "every 3s") || strings.Contains(body, "hx-get") {
		t.Errorf("опрос expired не остановлен: %s", body)
	}
	// отозван
	a.issueNAT(t, false)
	if c, _, _ := a.call("POST", "/agents/enroll/"+natStatusID+"/revoke", url.Values{"confirm": {"yes"}}, true); c != 200 {
		t.Fatalf("revoke %d", c)
	}
	_, body, _ = a.status("/agents/enroll/" + natStatusID + "/status")
	contains(t, "revoked", body, "Токен отозван", `href="/agents/new?mode=nat"`, `aria-label="Выпустить новый токен"`)
	if strings.Contains(body, "every 3s") || strings.Contains(body, "waw-2") {
		t.Errorf("revoked: %s", body)
	}
	// неизвестный id → revoked, а не 404 (запись могла быть убрана очисткой)
	if _, body, _ = a.status("/agents/enroll/ff/status"); !strings.Contains(body, "Токен отозван") {
		t.Errorf("unknown: %s", body)
	}
}

func TestEnrollStatusAccess(t *testing.T) {
	a := newAgFx(t, agOpts{})
	a.issueNAT(t, false)
	path := "/agents/enroll/" + natStatusID + "/status"
	// без сессии — на логин
	if w := a.do(req{method: "GET", path: path, hdr: hx}); w.Code != http.StatusUnauthorized || w.Header().Get("HX-Redirect") != "/login" {
		t.Errorf("без сессии: %d %v", w.Code, w.Header())
	}
	if w := a.do(req{method: "GET", path: path}); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Errorf("без сессии (не htmx): %d", w.Code)
	}
	// не htmx — на мастер
	if c, _, h := a.call("GET", path, nil, false); c != http.StatusSeeOther || h.Get("Location") != "/agents/new?mode=nat" {
		t.Errorf("не htmx: %d %v", c, h)
	}
	// кривой id
	if c, _, _ := a.status("/agents/enroll/NOT-HEX/status"); c != 404 {
		t.Errorf("bad id: %d", c)
	}
	// NAT не настроен — ничего не раскрываем
	b := newAgFx(t, agOpts{noEnroll: true})
	if c, body, _ := b.status(path); c != 200 || strings.TrimSpace(body) != "" {
		t.Errorf("не настроено: %d %q", c, body)
	}
}

func TestEnrollStatusGolden(t *testing.T) {
	for name, vm := range map[string]screens.EnrollStatusVM{
		"enroll_status_waiting":   {ID: natStatusID, State: "waiting", Name: "waw-2", Left: "42 мин"},
		"enroll_status_enrolled":  {ID: natStatusID, State: "enrolled", Name: "waw-2", AgentID: "waw-2"},
		"enroll_status_connected": {ID: natStatusID, State: "connected", Name: "waw-2", AgentID: "waw-2"},
		"enroll_status_expired":   {ID: natStatusID, State: "expired", Name: "waw-2"},
		"enroll_status_revoked":   {ID: natStatusID, State: "revoked"},
	} {
		golden(t, name, screens.NATStatus(vm))
	}
}

func TestAgentsHighlight(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, body, _ := a.call("GET", "/agents?highlight=waw-1", nil, false)
	if n := strings.Count(body, `class="row-new"`); n != 1 {
		t.Errorf("подсвеченных строк: %d", n)
	}
	for _, q := range []string{"/agents", "/agents?highlight=nope", "/agents?highlight=%22%3E%3Cx"} {
		if _, body, _ = a.call("GET", q, nil, false); strings.Contains(body, "row-new") {
			t.Errorf("%s: лишняя подсветка", q)
		}
	}
	// опрос таблицы (фрагмент) не подсвечивает
	if _, body, _ = a.call("GET", "/agents?highlight=waw-1", nil, true); strings.Contains(body, "row-new") {
		t.Error("подсветка во фрагменте опроса")
	}
}
