package installer

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"golang.org/x/crypto/ssh"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func successCommands(sudo string) []string {
	s := func(c string) string { return sudo + c }
	return []string{
		"[admin] /usr/bin/dpkg --print-architecture",
		"[admin] /usr/bin/sha256sum TMP",
		"[admin] /usr/bin/dpkg-query -W '-f=${db:Status-Abbrev}' tgproxy",
		"[admin] " + s("/usr/bin/env DEBIAN_FRONTEND=noninteractive /usr/bin/dpkg --force-confdef --force-confold -i TMP"),
		"[admin] /usr/bin/id -u tgproxy-deploy",
		"[admin] " + s("/usr/sbin/useradd --system --create-home --home-dir /var/lib/tgproxy-deploy --shell /bin/sh --user-group --password '*' tgproxy-deploy"),
		"[admin] " + s("/usr/bin/install -d -m 0755 -o root -g root /var/cache/tgproxy/packages"),
		"[admin] " + s("/usr/bin/install -d -m 0730 -o root -g tgproxy-deploy /var/lib/tgproxy-incoming"),
		// Копия релиза в доверенный кэш хоста: три файла в incoming + deploy-helper stage.
		"[admin] " + s("/usr/bin/install -D -m 0600 -o root -g root TMP INC"),
		"[admin] " + s("/usr/bin/install -D -m 0600 -o root -g root TMP INC.checksums"),
		"[admin] " + s("/usr/bin/install -D -m 0600 -o root -g root TMP INC.minisig"),
		"[admin] " + s("/usr/bin/tgproxy deploy-helper stage INC 1.4.1"),
		"[admin] /usr/bin/rm -f TMP TMP TMP",
		"[admin] " + s("/usr/bin/install -d -m 0700 -o tgproxy-deploy -g tgproxy-deploy /var/lib/tgproxy-deploy/.ssh"),
		"[admin] " + s("/usr/bin/install -D -m 0600 -o tgproxy-deploy -g tgproxy-deploy TMP /var/lib/tgproxy-deploy/.ssh/authorized_keys"),
		"[admin] /usr/bin/rm -f TMP",
		"[admin] " + s("/usr/sbin/visudo -cf TMP"),
		"[admin] " + s("/usr/bin/install -D -m 0440 -o root -g root TMP /etc/sudoers.d/tgproxy-deploy"),
		"[admin] /usr/bin/rm -f TMP",
		"[admin] " + s("/usr/bin/install -d -m 0750 -o root -g tgproxy /etc/tgproxy/tls"),
		"[admin] " + s("/usr/bin/tgproxy agent csr --key /etc/tgproxy/tls/agent.key --id ams-2 --out - --force"),
		"[admin] " + s("/usr/bin/install -D -m 0640 -o root -g tgproxy TMP /etc/tgproxy/tls/agent.crt"),
		"[admin] /usr/bin/rm -f TMP",
		"[admin] " + s("/usr/bin/install -D -m 0640 -o root -g tgproxy TMP /etc/tgproxy/tls/ca.crt"),
		"[admin] /usr/bin/rm -f TMP",
		"[admin] " + s("/usr/bin/install -D -m 0640 -o root -g tgproxy TMP /etc/tgproxy/agent.yaml"),
		"[admin] /usr/bin/rm -f TMP",
		"[admin] " + s("/usr/bin/tgproxy config validate --mode agent -c /etc/tgproxy/agent.yaml"),
		"[tgproxy-deploy] sudo -n /usr/bin/tgproxy deploy-helper unit enable",
		"[tgproxy-deploy] sudo -n /usr/bin/tgproxy deploy-helper unit enable-update",
		"[tgproxy-deploy] sudo -n /usr/bin/tgproxy deploy-helper unit is-active",
	}
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("команды отличаются.\ngot:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestInstallSuccess(t *testing.T) {
	e := newEnv(t)
	var captured *run
	e.inst.hook = func(r *run) { captured = r }
	id, st := e.install(e.request())

	if st.State != store.InstallDone || st.Error != "" || st.AgentID != "ams-2" || st.FinishedAt == nil {
		t.Fatalf("status %+v", st)
	}
	eq(t, e.cmdLines(), successCommands("sudo -n "))

	labels := []string{
		"SSH-подключение, ключ хоста закреплён", "Загрузка пакета tgproxy 1.4.1", "Установка пакета и пользователей",
		"Выпуск сертификата агента", "Запуск tgproxy-agent", "Проверка mTLS и доступа к Telegram", "Включение в балансировку",
	}
	if len(st.Steps) != 7 {
		t.Fatalf("steps %+v", st.Steps)
	}
	for i, s := range st.Steps {
		if s.Label != labels[i] || s.Status != StepOK {
			t.Fatalf("step %d: %+v", i, s)
		}
	}

	ag, err := e.st.Agents().Get(context.Background(), "ams-2")
	if err != nil || ag.URL != "https://127.0.0.1:8443" || ag.Mode != store.ModeDial || ag.Weight != 100 {
		t.Fatalf("agent %+v err %v", ag, err)
	}
	if got := e.health.called(); len(got) != 1 || got[0] != "https://127.0.0.1:8443|ams-2" {
		t.Fatalf("health %v", got)
	}
	hk, err := e.st.HostKeys().Get(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(e.host.port())))
	if err != nil || hk.AgentID != "ams-2" || hk.Fingerprint != e.fingerprint() {
		t.Fatalf("hostkey %+v %v", hk, err)
	}
	if certs, _ := e.st.Certs().ListByAgent(context.Background(), "ams-2"); len(certs) != 1 {
		t.Fatalf("certs %v", certs)
	}

	// Файлы на «хосте»: authorized_keys, sudoers, конфиг.
	e.host.mu.Lock()
	files := e.host.files
	e.host.mu.Unlock()
	ak := string(files["/var/lib/tgproxy-deploy/.ssh/authorized_keys"])
	wantKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.serverKey.PublicKey())))
	if !strings.Contains(ak, wantKey) || !strings.HasPrefix(ak, "no-port-forwarding,") {
		t.Fatalf("authorized_keys %q", ak)
	}
	if string(files["/etc/sudoers.d/tgproxy-deploy"]) != string(RenderSudoers()) {
		t.Fatal("sudoers differs")
	}
	if !strings.Contains(string(files["/etc/tgproxy/tls/ca.crt"]), "BEGIN CERTIFICATE") ||
		!strings.Contains(string(files["/etc/tgproxy/tls/agent.crt"]), "BEGIN CERTIFICATE") {
		t.Fatal("certs not uploaded")
	}
	yml := files["/etc/tgproxy/agent.yaml"]
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, yml, 0o600); err != nil {
		t.Fatal(err)
	}
	ac, err := config.LoadAgent(p)
	if err != nil {
		t.Fatalf("agent.yaml не проходит config.LoadAgent: %v\n%s", err, yml)
	}
	if ac.Listen.API != "0.0.0.0:8443" || ac.Mode != config.AgentModeDial || ac.AllowedClientSAN != "tgproxy-server" ||
		ac.TLS.CertFile != "/etc/tgproxy/tls/agent.crt" || ac.TLS.KeyFile != "/etc/tgproxy/tls/agent.key" {
		t.Fatalf("agent config %+v", ac)
	}

	// События: монотонный seq, терминальное done, шаги проходят running→ok.
	evs := e.allEvents(id)
	var last int64
	for _, ev := range evs {
		if ev.Seq <= last {
			t.Fatalf("seq не монотонен: %d после %d", ev.Seq, last)
		}
		last = ev.Seq
	}
	if evs[len(evs)-1].Kind != EventDone {
		t.Fatalf("последнее событие %+v", evs[len(evs)-1])
	}

	// Креды обнулены; ссылки на них в задаче не осталось.
	if captured == nil || captured.auth.PrivateKeyPEM != nil || captured.auth.Password != nil || captured.admin != nil {
		t.Fatalf("креды не обнулены: %+v", captured.auth)
	}
}

func TestCredsWipedAfterCertStep(t *testing.T) {
	e := newEnv(t)
	var captured *run
	e.inst.hook = func(r *run) { captured = r }
	var wipedBeforeStart, wipedBeforeCert bool
	e.host.extraFn = func(_, line string) (string, int, bool) {
		switch {
		case strings.HasPrefix(line, "/usr/bin/tgproxy agent csr"):
			wipedBeforeCert = len(captured.auth.PrivateKeyPEM) == 0
		case strings.HasPrefix(line, "/usr/bin/tgproxy deploy-helper unit enable"):
			wipedBeforeStart = len(captured.auth.PrivateKeyPEM) == 0
		}
		return "", 0, false
	}
	e.install(e.request())
	if wipedBeforeCert {
		t.Fatal("креды обнулены до выпуска сертификата")
	}
	if !wipedBeforeStart {
		t.Fatal("креды не обнулены перед запуском агента")
	}
}

func TestInstallWithPasswordUsesSudoStdin(t *testing.T) {
	e := newEnv(t)
	req := e.request()
	req.Auth = Auth{Password: []byte(adminPassword)}
	_, st := e.install(req)
	if st.State != store.InstallDone {
		t.Fatalf("status %+v", st)
	}
	var sudoCmds int
	for _, c := range e.host.commands() {
		if strings.HasPrefix(c.Line, "sudo -S -p '' ") {
			sudoCmds++
			if c.Stdin != adminPassword+"\n" {
				t.Fatalf("stdin sudo = %q", c.Stdin)
			}
		}
		if strings.Contains(c.Line, adminPassword) {
			t.Fatalf("пароль в командной строке: %s", c.Line)
		}
	}
	if sudoCmds < 10 {
		t.Fatalf("ожидались sudo -S команды, получено %d", sudoCmds)
	}
}

func TestInstallAsRootNoSudo(t *testing.T) {
	e := newEnv(t)
	req := e.request()
	req.User = "root"
	_, st := e.install(req)
	if st.State != store.InstallDone {
		t.Fatalf("status %+v", st)
	}
	for _, c := range e.host.commands() {
		if c.User == "root" && strings.HasPrefix(c.Line, "sudo ") {
			t.Fatalf("root через sudo: %s", c)
		}
	}
}

func TestRollbackOnCertStepFailure(t *testing.T) {
	e := newEnv(t)
	e.host.failOn["agent csr"] = "tgproxy: agent csr: boom"
	id, st := e.install(e.request())

	if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "boom") {
		t.Fatalf("status %+v", st)
	}
	want := successCommands("sudo -n ")[:21] // до csr включительно
	want = append(want,
		"[admin] sudo -n /usr/bin/rm -f /etc/tgproxy/tls/agent.key /etc/tgproxy/tls/agent.crt /etc/tgproxy/tls/ca.crt", // шаг 4
		"[admin] sudo -n /usr/bin/rm -f /etc/sudoers.d/tgproxy-deploy",                                                 // шаг 3
		"[admin] sudo -n /usr/sbin/userdel --remove tgproxy-deploy",
		"[admin] sudo -n /usr/bin/dpkg -r tgproxy",
	)
	eq(t, e.cmdLines(), want)

	got := map[string]string{}
	for _, s := range st.Steps {
		got[s.Key] = s.Status
	}
	wantSt := map[string]string{
		stepSSH: StepOK, stepUpload: StepOK, stepInstall: StepRolledBack, stepCert: StepRolledBack,
		stepStart: StepPending, stepCheck: StepPending, stepBalance: StepPending,
	}
	if !reflect.DeepEqual(got, wantSt) {
		t.Fatalf("steps %v, want %v", got, wantSt)
	}
	if _, err := e.st.Agents().Get(context.Background(), "ams-2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("агент не должен существовать: %v", err)
	}
	evs := e.allEvents(id)
	if evs[len(evs)-1].Kind != EventError {
		t.Fatalf("последнее событие %+v", evs[len(evs)-1])
	}
	job, _ := e.st.InstallJobs().Get(context.Background(), id)
	if job.State != store.InstallRolledBack || job.FinishedAt == nil {
		t.Fatalf("job %+v", job)
	}
}

func TestRollbackKeepsPreinstalledPackageAndUser(t *testing.T) {
	e := newEnv(t)
	e.host.extraFn = func(_, line string) (string, int, bool) {
		switch {
		case strings.HasPrefix(line, "/usr/bin/dpkg-query"):
			return "ii \n", 0, true
		case strings.HasPrefix(line, "/usr/bin/id -u"):
			return "999\n", 0, true
		}
		return "", 0, false
	}
	e.host.failOn["visudo"] = "visudo: syntax error"
	_, st := e.install(e.request())
	if st.State != store.InstallRolledBack {
		t.Fatalf("status %+v", st)
	}
	for _, l := range e.cmdLines() {
		if strings.Contains(l, "dpkg -r") || strings.Contains(l, "userdel") {
			t.Fatalf("откат удалил чужое: %s", l)
		}
	}
}

func TestRollbackAfterAdminReleased(t *testing.T) {
	e := newEnv(t)
	e.health.err = errors.New("telegram unreachable")
	id, st := e.install(e.request())
	if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "telegram unreachable") {
		t.Fatalf("status %+v", st)
	}
	cmds := e.cmdLines()
	if got := cmds[len(cmds)-1]; got != "[tgproxy-deploy] sudo -n /usr/bin/tgproxy deploy-helper unit disable" {
		t.Fatalf("последняя команда %q", got)
	}
	for _, l := range cmds {
		if strings.HasPrefix(l, "[admin]") && (strings.Contains(l, "dpkg -r") || strings.Contains(l, "userdel")) {
			t.Fatalf("админ-команда после удаления кредов: %s", l)
		}
	}
	if denied, _ := e.st.Certs().ListDenied(context.Background()); len(denied) != 1 || denied[0].AgentID != "ams-2" {
		t.Fatalf("denylist %+v", denied)
	}
	var warned bool
	for _, ev := range e.allEvents(id) {
		if ev.Level == "warn" && strings.Contains(ev.Message, "Остались на хосте") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("нет предупреждения об оставшихся на хосте пакете и пользователе")
	}
	if _, err := e.st.Agents().Get(context.Background(), "ams-2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("агент остался в БД")
	}
}

func TestRollbackWhenBalanceStepFails(t *testing.T) {
	e := newEnv(t)
	// Агент появился в БД между проверкой и последним шагом.
	e.health.err = nil
	e.host.extraFn = func(_, line string) (string, int, bool) {
		if strings.HasPrefix(line, "/usr/bin/tgproxy deploy-helper unit is-active") {
			_, _ = e.st.Agents().Create(context.Background(), store.Agent{ID: "ams-2", Name: "x", URL: "https://x:1", Mode: store.ModeDial, Weight: 1})
		}
		return "", 0, false
	}
	_, st := e.install(e.request())
	if st.State != store.InstallRolledBack {
		t.Fatalf("status %+v", st)
	}
	// чужой агент не удалён откатом
	if _, err := e.st.Agents().Get(context.Background(), "ams-2"); err != nil {
		t.Fatalf("откат удалил чужого агента: %v", err)
	}
}

func TestSecretsNeverPersisted(t *testing.T) {
	passKey, _ := encryptedKey(t, keyPassphrase)
	keyBody := strings.TrimSpace(strings.Split(string(passKey), "\n")[1])
	for name, tc := range map[string]struct {
		auth    Auth
		secrets []string
	}{
		"password": {Auth{Password: []byte(adminPassword)}, []string{adminPassword}},
		"key+pass": {Auth{PrivateKeyPEM: passKey, Passphrase: []byte(keyPassphrase)}, []string{keyPassphrase, keyBody}},
	} {
		auth, secrets := tc.auth, tc.secrets
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			signer, err := ssh.ParsePrivateKeyWithPassphrase(passKey, []byte(keyPassphrase))
			if err != nil {
				t.Fatal(err)
			}
			e.host.adminKey = signer.PublicKey()
			// провал на шаге 4 со stderr, эхо-печатающим секреты (как делают некоторые обёртки)
			e.host.failOn["agent csr"] = "failed; password=" + adminPassword + " passphrase=" + keyPassphrase + " key=" + string(passKey)
			e.host.failOn["agent csr"] = strings.ReplaceAll(e.host.failOn["agent csr"], "\n", " ")
			req := e.request()
			req.Auth = auth
			id, st := e.install(req)
			if st.State != store.InstallRolledBack {
				t.Fatalf("status %+v", st)
			}
			var dump strings.Builder
			for _, ev := range e.allEvents(id) {
				fmt.Fprintf(&dump, "%+v\n", ev)
			}
			job, _ := e.st.InstallJobs().Get(context.Background(), id)
			fmt.Fprintf(&dump, "%+v\n%s\n", job, e.logs.String())
			for _, c := range e.host.commands() {
				if strings.Contains(c.Line, adminPassword) {
					t.Fatalf("секрет в командной строке: %s", c.Line)
				}
			}
			for _, s := range secrets {
				if strings.Contains(dump.String(), s) {
					t.Fatalf("секрет %q найден в событиях/задаче/логах:\n%s", s[:6], dump.String())
				}
			}
			if !strings.Contains(dump.String(), "***") {
				t.Fatal("ожидалась маскировка секрета в stderr")
			}
		})
	}
}

func TestInvalidInputRejectedBeforeConnect(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func(*Request){
		"имя с кавычкой":    func(r *Request) { r.Name = "a'; rm -rf /" },
		"пустое имя":        func(r *Request) { r.Name = "" },
		"хост с ;":          func(r *Request) { r.Host = "1.2.3.4;reboot" },
		"хост с пробелом":   func(r *Request) { r.Host = "host name" },
		"хост с -":          func(r *Request) { r.Host = "-oProxyCommand=x" },
		"порт 0":            func(r *Request) { r.SSHPort = 0 },
		"порт 70000":        func(r *Request) { r.SSHPort = 70000 },
		"порт агента":       func(r *Request) { r.AgentPort = -1 },
		"пользователь":      func(r *Request) { r.User = "ro ot" },
		"пользователь $()":  func(r *Request) { r.User = "$(id)" },
		"вес":               func(r *Request) { r.Weight = 0 },
		"версия":            func(r *Request) { r.PackageVersion = "1.0/../x" },
		"нет auth":          func(r *Request) { r.Auth = Auth{} },
		"нет версии в кэше": func(r *Request) { r.PackageVersion = "9.9.9" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			req := e.request()
			mut(&req)
			if _, err := e.inst.Install(context.Background(), req); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
	if n := e.host.connCount(); n != 0 {
		t.Fatalf("было %d подключений до валидации", n)
	}
	if _, err := e.st.InstallJobs().Get(context.Background(), "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestInstallExistingAgentConflict(t *testing.T) {
	e := newEnv(t)
	_, _ = e.st.Agents().Create(context.Background(), store.Agent{ID: "ams-2", Name: "ams-2", URL: "https://x:1", Mode: store.ModeDial, Weight: 1})
	_, err := e.inst.Install(context.Background(), e.request())
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallUnknownHostKeyNeedsConfirmation(t *testing.T) {
	e := newEnv(t)
	req := e.request()
	req.ConfirmedFingerprint = ""
	_, err := e.inst.Install(context.Background(), req)
	var unk *ErrHostKeyUnknown
	if !errors.As(err, &unk) {
		t.Fatalf("err = %v", err)
	}
	if e.host.connCount() != 0 {
		t.Fatal("подключение без подтверждённого отпечатка")
	}
}

func TestTOFUFullFlow(t *testing.T) {
	e := newEnv(t)
	target := Target{Host: "127.0.0.1", Port: e.host.port()}
	algo, fp, err := ProbeHostKey(context.Background(), target)
	if err != nil || algo != ssh.KeyAlgoED25519 || fp != e.fingerprint() {
		t.Fatalf("probe: %q %q %v", algo, fp, err)
	}
	if _, ok := e.st.HostKeys().Get(context.Background(), target.Addr()); ok == nil {
		t.Fatal("Probe не должен ничего закреплять")
	}
	req := e.request()
	req.ConfirmedFingerprint = fp
	_, st := e.install(req)
	if st.State != store.InstallDone {
		t.Fatalf("status %+v", st)
	}
	rec, err := e.st.HostKeys().Get(context.Background(), target.Addr())
	if err != nil || rec.Fingerprint != fp {
		t.Fatalf("pin %+v %v", rec, err)
	}
}

func TestConfirmedFingerprintMismatchAbortsAndAlerts(t *testing.T) {
	e := newEnv(t)
	req := e.request()
	req.ConfirmedFingerprint = ssh.FingerprintSHA256(newHostKey(t).PublicKey()) // подтверждали другой хост
	id, st := e.install(req)
	if st.State == store.InstallDone || !strings.Contains(st.Error, ErrHostKeyMismatch.Error()) {
		t.Fatalf("status %+v", st)
	}
	if len(e.host.commands()) != 0 {
		t.Fatal("команды выполнены на хосте с неподтверждённым ключом")
	}
	if got := e.alerts.got(); len(got) != 1 || got[0][0] != "ams-2" {
		t.Fatalf("alerts %v", got)
	}
	if _, err := e.st.HostKeys().Get(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(e.host.port()))); err == nil {
		t.Fatal("неподтверждённый ключ закреплён")
	}
	_ = id
}

func TestHostKeyChangedAfterPinAbortsAndAlerts(t *testing.T) {
	e := newEnv(t)
	e.pin()
	// хост «подменили»: другой ключ на том же адресе
	e.host.setHostKey(newHostKey(t))
	_, st := e.install(e.request())
	if st.State == store.InstallDone || !strings.Contains(st.Error, ErrHostKeyMismatch.Error()) {
		t.Fatalf("status %+v", st)
	}
	if len(e.host.commands()) != 0 {
		t.Fatal("команды выполнены после несовпадения ключа")
	}
	got := e.alerts.got()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(e.host.port()))
	if len(got) != 1 || got[0] != [2]string{"ams-2", addr} {
		t.Fatalf("alerts %v", got)
	}
}

func cloneWithKey(old *ssh.ServerConfig, key ssh.Signer) *ssh.ServerConfig {
	c := &ssh.ServerConfig{PasswordCallback: old.PasswordCallback, PublicKeyCallback: old.PublicKeyCallback}
	c.AddHostKey(key)
	return c
}

func TestUnsafeStateAfterWrongAdminAuth(t *testing.T) {
	e := newEnv(t)
	req := e.request()
	req.Auth = Auth{Password: []byte("wrong")}
	_, st := e.install(req)
	if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "unable to authenticate") {
		t.Fatalf("status %+v", st)
	}
}

func TestSignatureAndSHA256Checks(t *testing.T) {
	t.Run("чужая подпись — на хост ничего не уходит", func(t *testing.T) {
		e := newEnv(t)
		_, other, _ := minisign.GenerateKey(rand.Reader)
		writeRelease(t, e.pkgDir, "1.5.0", other, map[string]string{"amd64": "deb-body-1.5.0"})
		_, st := e.install(e.request())
		if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "подпись") {
			t.Fatalf("status %+v", st)
		}
		if len(e.host.commands()) != 1 { // только dpkg --print-architecture
			t.Fatalf("cmds %v", e.cmdLines())
		}
	})
	t.Run("изменён 1 байт deb", func(t *testing.T) {
		e := newEnv(t)
		p := filepath.Join(e.pkgDir, "1.4.1", "tgproxy_1.4.1_amd64.deb")
		if err := os.WriteFile(p, []byte("deb-body-1.4.2"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, st := e.install(e.request())
		if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "sha256") {
			t.Fatalf("status %+v", st)
		}
		if len(e.host.commands()) != 1 {
			t.Fatalf("cmds %v", e.cmdLines())
		}
	})
	t.Run("нет подписи в кэше", func(t *testing.T) {
		e := newEnv(t)
		_ = os.Remove(filepath.Join(e.pkgDir, "1.4.1", "checksums.txt.minisig"))
		_, st := e.install(e.request())
		if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "minisig") {
			t.Fatalf("status %+v", st)
		}
	})
	t.Run("версия ниже min_version", func(t *testing.T) {
		e := newEnv(t, func(c *Config) {
			c.Verifier = verify.Verifier{Keys: c.Verifier.(verify.Verifier).Keys, MinVersion: "2.0.0"}
		})
		_, st := e.install(e.request())
		if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "min_version") && !strings.Contains(st.Error, "ниже") {
			t.Fatalf("status %+v", st)
		}
	})
	t.Run("на хосте", func(t *testing.T) {
		e := newEnv(t)
		e.host.wrongSH = true
		_, st := e.install(e.request())
		if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "sha256") {
			t.Fatalf("status %+v", st)
		}
	})
}

func TestStageFailureRollsBackAndCleansIncoming(t *testing.T) {
	e := newEnv(t)
	e.host.failOn = map[string]string{"deploy-helper stage": "stage failed"}
	_, st := e.install(e.request())
	if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "stage failed") {
		t.Fatalf("status %+v", st)
	}
	lines := strings.Join(e.cmdLines(), "\n")
	if !strings.Contains(lines, "rm -f INC INC.checksums INC.minisig") {
		t.Fatalf("incoming не вычищен:\n%s", lines)
	}
}

func TestNoPackageForArch(t *testing.T) {
	e := newEnv(t)
	e.host.extraFn = func(_, line string) (string, int, bool) {
		if strings.HasPrefix(line, "/usr/bin/dpkg --print-architecture") {
			return "arm64\n", 0, true
		}
		return "", 0, false
	}
	_, st := e.install(e.request())
	if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "arm64") {
		t.Fatalf("status %+v", st)
	}
}

func TestCloseCancelsAndRollsBack(t *testing.T) {
	e := newEnv(t)
	e.health.block = true
	id, err := e.inst.Install(context.Background(), e.request())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(e.health.called()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("job не дошёл до проверки")
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.inst.Close()
	st, err := e.inst.Status(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != store.InstallRolledBack {
		t.Fatalf("status %+v", st)
	}
}

func TestEventsBacklogLiveAndReconnect(t *testing.T) {
	e := newEnv(t)
	gate := make(chan struct{})
	e.host.extraFn = func(_, line string) (string, int, bool) {
		if strings.HasPrefix(line, "/usr/bin/env DEBIAN_FRONTEND=noninteractive /usr/bin/dpkg --force-confdef --force-confold -i") {
			<-gate // держим задачу на шаге 3
		}
		return "", 0, false
	}
	id, err := e.inst.Install(context.Background(), e.request())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	backlog, live, err := e.inst.Events(ctx, id, 0)
	if err != nil || len(backlog) < 7 {
		t.Fatalf("backlog %d %v", len(backlog), err)
	}
	cut := backlog[len(backlog)/2].Seq
	close(gate)

	var got []Event
	for ev := range live {
		got = append(got, ev)
		if ev.Kind == EventDone {
			break
		}
	}
	if len(got) == 0 || got[len(got)-1].Kind != EventDone {
		t.Fatalf("live: %d событий, нет done", len(got))
	}
	// Переподключение с Last-Event-ID: ровно пропущенные события, без дублей.
	re, ch, err := e.inst.Events(ctx, id, cut)
	if err != nil {
		t.Fatal(err)
	}
	if _, open := <-ch; open {
		t.Fatal("для завершённой задачи канал должен быть закрыт")
	}
	all := e.allEvents(id)
	var want []Event
	for _, ev := range all {
		if ev.Seq > cut {
			want = append(want, ev)
		}
	}
	if !reflect.DeepEqual(re, want) {
		t.Fatalf("reconnect: %d vs %d событий", len(re), len(want))
	}
	if _, _, err := e.inst.Events(ctx, "nope", 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := e.inst.Status(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestEventsSubscriberCancel(t *testing.T) {
	e := newEnv(t)
	gate := make(chan struct{})
	e.host.extraFn = func(_, line string) (string, int, bool) {
		if strings.HasPrefix(line, "/usr/bin/env DEBIAN_FRONTEND=noninteractive /usr/bin/dpkg --force-confdef --force-confold -i") {
			<-gate
		}
		return "", 0, false
	}
	id, _ := e.inst.Install(context.Background(), e.request())
	ctx, cancel := context.WithCancel(context.Background())
	_, live, err := e.inst.Events(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-live:
			if !ok {
				close(gate)
				return
			}
		case <-deadline:
			t.Fatal("канал не закрылся после отмены контекста")
		}
	}
}

func TestSlowSubscriberDropped(t *testing.T) {
	st := newEnv(t).st
	_ = st.InstallJobs().Create(context.Background(), store.InstallJob{ID: "j", Host: "h:1", Kind: "install", State: store.InstallRunning})
	l := &liveJob{id: "j", bg: context.Background(), repo: st.InstallJobs(), log: nil, subs: map[chan Event]struct{}{}, done: make(chan struct{})}
	ch := make(chan Event, 1)
	l.subs[ch] = struct{}{}
	l.emit(Event{Kind: EventLog, Message: "1"})
	l.emit(Event{Kind: EventLog, Message: "2"}) // буфер полон → подписчик закрыт
	n := 0
	for range ch {
		n++
	}
	if n != 1 || len(l.subs) != 0 {
		t.Fatalf("n=%d subs=%d", n, len(l.subs))
	}
}

func TestNewValidatesConfig(t *testing.T) {
	e := newEnv(t)
	base := Config{Store: e.st, CA: e.ca, Health: e.health, ServerKey: e.serverKey, PackagesDir: e.pkgDir, Verifier: e.verifier}
	if _, err := New(Config{}); err == nil {
		t.Fatal("пустой конфиг принят")
	}
	c := base
	c.PackagesDir = ""
	if _, err := New(c); err == nil {
		t.Fatal("без PackagesDir принят")
	}
	c = base
	c.Verifier = nil
	if _, err := New(c); err == nil {
		t.Fatal("без Verifier принят")
	}
	c = base
	c.RemoteTmpDir = "tmp/../x"
	if _, err := New(c); err == nil {
		t.Fatal("плохой RemoteTmpDir принят")
	}
	c = base
	c.AllowedClientSAN = "a b"
	if _, err := New(c); err == nil {
		t.Fatal("плохой SAN принят")
	}
	in, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	in.Close()
}

func TestAgentIDIsAlwaysSetByServerNotCSR(t *testing.T) {
	// CSR фейка содержит CN=evil-cn; SAN выставляет pki — проверяем, что выпущен agent/ams-2.
	e := newEnv(t)
	e.install(e.request())
	certs, _ := e.st.Certs().ListByAgent(context.Background(), "ams-2")
	if len(certs) != 1 || certs[0].Subject != "spiffe://tgproxy/agent/ams-2" {
		t.Fatalf("certs %+v", certs)
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
