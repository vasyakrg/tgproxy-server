//go:build integration

package installer

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Запуск: go test -tags integration -run Integration -v ./internal/server/installer/
// Нужны docker и deb (TGPROXY_DEB или dist/tgproxy_*_amd64.deb после `make deb`).

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// mtlsHealth — настоящая проверка: mTLS от имени сервера к /_agent/status.
type mtlsHealth struct{ ca *pki.Authority }

func (h mtlsHealth) Check(ctx context.Context, agentURL, agentID string) error {
	cert, err := h.ca.ServerCert(ctx)
	if err != nil {
		return err
	}
	cfg, err := pki.ClientTLSConfig(*cert, h.ca.Pool(), pki.VerifyAgentPeer(h.ca.Pool(), agentID))
	if err != nil {
		return err
	}
	cfg.NextProtos = nil
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, agentURL+"/_agent/status", nil)
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func TestIntegrationInstallAgentInDebianSystemd(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker недоступен")
	}
	if err := exec.CommandContext(context.Background(), "docker", "info").Run(); err != nil {
		t.Skip("docker daemon недоступен")
	}
	// По умолчанию — платформа docker-хоста: amd64-бинарь под Rosetta падает в systemd-юните с hardening
	// (/proc/sys/vm/mmap_min_addr), поэтому на Apple Silicon нужен arm64-deb (см. packaging/ci/smoke.sh).
	arch := "amd64"
	if out, _ := exec.CommandContext(context.Background(), "docker", "info", "--format", "{{.Architecture}}").Output(); strings.Contains(string(out), "aarch64") || strings.Contains(string(out), "arm64") {
		arch = "arm64"
	}
	if a := os.Getenv("IT_ARCH"); a != "" {
		arch = a
	}
	platform := "linux/" + arch
	// Подписанный dev-набор (`make dev-packages`): deb собран с вшитым dev-pubkey, поэтому
	// deploy-helper на хосте принимает подпись dev-ключа. Вне dev-набора stage отказал бы.
	pkgDir := os.Getenv("TGPROXY_DEV_PACKAGES")
	if pkgDir == "" {
		pkgDir = "../../../dev/data/packages"
	}
	pubFile := os.Getenv("TGPROXY_DEV_PUBKEY")
	if pubFile == "" {
		pubFile = "../../../dev/data/minisign.pub"
	}
	pubRaw, err := os.ReadFile(pubFile)
	if err != nil {
		t.Skip("нет dev-ключа " + pubFile + ": make dev-packages")
	}
	devPub, err := verify.ParsePublicKey(string(pubRaw))
	if err != nil {
		t.Fatal(err)
	}
	set, err := findPackages(pkgDir, "")
	if err != nil {
		t.Skip("нет подписанных пакетов: make dev-packages (" + err.Error() + ")")
	}
	debPath, _, ok := set.path(arch)
	if !ok {
		t.Skip("в " + pkgDir + " нет deb для " + arch + ": make dev-packages")
	}
	data, err := os.ReadFile(debPath)
	if err != nil {
		t.Fatal(err)
	}
	checksums, err := os.ReadFile(filepath.Join(set.dir, "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sigFile, err := os.ReadFile(filepath.Join(set.dir, "checksums.txt.minisig"))
	if err != nil {
		t.Fatal(err)
	}
	verifier := verify.Verifier{Keys: []verify.PublicKey{devPub}}
	ver := set.version

	image := "tgproxy-installer-it:local"
	docker(t, "build", "-q", "--platform", platform, "-t", image, "-f", "testdata/Dockerfile.sshd-systemd", "testdata")
	sshPort, agentPort := freePort(t), freePort(t)
	name := fmt.Sprintf("tgproxy-installer-it-%d", os.Getpid())
	docker(t, "run", "-d", "--platform", platform, "--name", name, "--privileged", "--cgroupns=host",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp",
		"-p", fmt.Sprintf("127.0.0.1:%d:22", sshPort), "-p", fmt.Sprintf("127.0.0.1:%d:%d", agentPort, agentPort), image)
	t.Cleanup(func() { _ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run() })

	ctx := context.Background()
	target := Target{Host: "127.0.0.1", Port: sshPort, User: "admin"}
	var algo, fp string
	deadline := time.Now().Add(90 * time.Second)
	for {
		var err error
		if algo, fp, err = ProbeHostKey(ctx, target); err == nil {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.CommandContext(context.Background(), "docker", "logs", "--tail", "30", name).CombinedOutput()
			t.Fatalf("sshd не поднялся: %v\n%s", err, logs)
		}
		time.Sleep(time.Second)
	}
	t.Logf("host key: %s %s", algo, fp)

	// systemd должен быть готов (enable --now).
	for i := 0; i < 60; i++ {
		out, _ := exec.CommandContext(context.Background(), "docker", "exec", name, "systemctl", "is-system-running").Output()
		if s := strings.TrimSpace(string(out)); s == "running" || s == "degraded" {
			break
		}
		time.Sleep(time.Second)
	}

	e := newEnv(t, func(c *Config) {
		c.RemoteTmpDir = "/tmp"
		c.HealthTimeout = 40 * time.Second
		c.StepTimeout = 5 * time.Minute
	})
	hc := mtlsHealth{ca: e.ca}
	srvKey, err := LoadOrCreateServerKey(filepath.Join(t.TempDir(), "ssh"))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := New(Config{
		Store: e.st, CA: e.ca, Health: hc, Alerter: e.alerts, ServerKey: srvKey, PackagesDir: pkgDir, Verifier: verifier,
		HealthTimeout: 40 * time.Second, StepTimeout: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inst.Close)

	req := Request{
		Name: "it-1", Host: "127.0.0.1", SSHPort: sshPort, User: "admin", AgentPort: agentPort, Weight: 50,
		Auth: Auth{Password: []byte("adminpw")}, ConfirmedFingerprint: fp,
	}
	runJob := func(r Request) JobStatus {
		id, err := inst.Install(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
		defer cancel()
		if err := inst.Wait(wctx, id); err != nil {
			t.Fatal(err)
		}
		st, _ := inst.Status(ctx, id)
		if st.State != store.InstallDone {
			jl, _ := exec.CommandContext(ctx, "docker", "exec", name, "journalctl", "-u", "tgproxy-agent", "--no-pager", "-n", "30").CombinedOutput()
			t.Logf("journal tgproxy-agent:\n%s", jl)
			evs, _, _ := inst.Events(ctx, id, 0)
			for _, ev := range evs {
				t.Logf("%s %-7s %s", ev.Step, ev.Kind, ev.Message)
			}
		}
		return st
	}

	st := runJob(req)
	if st.State != store.InstallDone {
		t.Fatalf("установка не завершилась: %+v", st)
	}
	if out := docker(t, "exec", name, "systemctl", "is-active", "tgproxy-agent"); out != "active" {
		t.Fatalf("tgproxy-agent: %q", out)
	}
	if out := docker(t, "exec", name, "visudo", "-c"); !strings.Contains(out, "parsed OK") {
		t.Fatalf("visudo -c: %s", out)
	}
	if out := docker(t, "exec", name, "stat", "-c", "%U:%G %a", "/etc/tgproxy/tls/agent.key"); out != "tgproxy:tgproxy 600" {
		t.Fatalf("права ключа агента: %q", out)
	}
	if out := docker(t, "exec", name, "stat", "-c", "%U:%G %a", "/etc/tgproxy/tls/agent.crt"); out != "root:tgproxy 640" {
		t.Fatalf("права сертификата: %q", out)
	}
	// Установщик положил подписанную копию в доверенный кэш хоста (через deploy-helper stage).
	if out := docker(t, "exec", name, "sh", "-c", "stat -c '%U:%G %a %n' "+packagesDir+" "+packagesDir+"/"+ver+" "+packagesDir+"/"+ver+"/*"); !strings.Contains(out, "root:root 755 "+packagesDir+"\n") ||
		!strings.Contains(out, "checksums.txt.minisig") || !strings.Contains(out, ".deb") {
		t.Fatalf("доверенный кэш хоста:\n%s", out)
	}
	if out, _ := exec.CommandContext(ctx, "docker", "exec", name, "ls", "/var/lib/tgproxy/packages").CombinedOutput(); !strings.Contains(string(out), "No such file") {
		t.Fatalf("устаревший /var/lib/tgproxy/packages существует: %s", out)
	}
	ag, err := e.st.Agents().Get(ctx, "it-1")
	if err != nil || ag.Weight != 50 {
		t.Fatalf("agent %+v %v", ag, err)
	}

	// tgproxy-deploy: разрешён только deploy-helper; любой обход — отказ.
	policy := HostKeyPolicy{Repo: e.st.HostKeys(), Timeout: 10 * time.Second}
	dcl, err := Dial(ctx, Target{Host: "127.0.0.1", Port: sshPort, User: deployUser}, Auth{Signer: srvKey}, policy)
	if err != nil {
		t.Fatalf("вход tgproxy-deploy: %v", err)
	}
	defer func() { _ = dcl.Close() }()
	run := func(cmd string) (int, string) {
		s, err := dcl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		out, err := s.CombinedOutput(cmd)
		code := 0
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitStatus()
		} else if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s -> %d | %s", cmd, code, strings.TrimSpace(string(out)))
		return code, string(out)
	}
	const hlp = "sudo -n /usr/bin/tgproxy deploy-helper "

	// Разрешённый путь: unit, stage из incoming (SFTP от имени deploy), install.
	for _, ok := range []string{hlp + "unit status", hlp + "unit restart", hlp + "unit is-active"} {
		if code, _ := run(ok); code != 0 {
			t.Errorf("разрешённая команда отклонена: %s", ok)
		}
	}
	sc, err := sftp.NewClient(dcl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sc.Close() }()
	put := func(name string, body []byte) {
		f, err := sc.Create(incomingDir + "/" + name)
		if err != nil {
			t.Fatalf("sftp create %s: %v", name, err)
		}
		_, _ = f.Write(body)
		_ = f.Close()
	}
	putRelease := func(base string, body []byte) {
		put(base, body)
		put(base+".checksums", checksums)
		put(base+".minisig", sigFile)
	}
	putRelease("up.deb", data)
	if code, _ := run(hlp + "stage " + incomingDir + "/up.deb " + ver); code != 0 {
		t.Fatal("stage отклонён")
	}
	if code, _ := run(hlp + "install " + ver); code != 0 {
		t.Fatal("install отклонён")
	}

	// Отказы. Код 2 — хелпер отверг ввод; 1 — sudo не пустил вообще.
	for _, bad := range []struct {
		cmd  string
		code int
	}{
		{hlp + "install '" + ver + " /tmp/evil.deb'", 2},
		{hlp + "install '../../../tmp/evil'", 2},
		{hlp + "install " + ver + " /tmp/evil.deb", 2},
		{hlp + "install '" + ver + "/../x'", 2},
		{hlp + "install 9.9.9", 1}, // корректная версия, но такого пакета нет
		{hlp + "stage /tmp/up.deb " + ver, 2},
		{hlp + "stage " + incomingDir + "/../tmp/up.deb " + ver, 2},
		{hlp + "unit link", 2},
		{hlp + "unit start ssh", 2},
		{hlp + "unit 'start ssh'", 2},
		{hlp + "unit edit", 2},
		{hlp, 1}, // sudoers требует хотя бы один аргумент
		{"sudo -n /usr/bin/systemctl link /tmp/evil.service tgproxy-agent", 1},
		{"sudo -n /usr/bin/systemctl start ssh", 1},
		{"sudo -n /usr/bin/systemctl restart tgproxy-agent", 1},
		{"sudo -n /usr/bin/dpkg -i " + packagesDir + "/" + ver + "/tgproxy_" + ver + "_" + arch + ".deb", 1},
		{"sudo -n /bin/sh -c id", 1},
		{"sudo -n /usr/bin/tgproxy agent csr --key /etc/x --id x", 1},
	} {
		if code, _ := run(bad.cmd); code != bad.code {
			t.Errorf("%s: код %d, ожидался %d", bad.cmd, code, bad.code)
		}
	}
	// Симлинк в incoming на чужой файл, подмена deb (1 байт), чужая подпись, даунгрейд/чужая версия →
	// stage отказывает, доверенный кэш не меняется.
	if err := sc.Symlink("/etc/shadow", incomingDir+"/ln.deb"); err != nil {
		t.Fatal(err)
	}
	put("ln.deb.checksums", checksums)
	put("ln.deb.minisig", sigFile)
	if code, _ := run(hlp + "stage " + incomingDir + "/ln.deb " + ver); code == 0 {
		t.Error("stage по симлинку разрешён")
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)/2] ^= 1
	putRelease("bad.deb", tampered)
	if code, _ := run(hlp + "stage " + incomingDir + "/bad.deb " + ver); code == 0 {
		t.Error("stage с изменённым deb разрешён")
	}
	_, foreign, _ := minisign.GenerateKey(rand.Reader)
	rd := minisign.NewReader(bytes.NewReader(checksums))
	_, _ = io.Copy(io.Discard, rd)
	put("alien.deb", data)
	put("alien.deb.checksums", checksums)
	put("alien.deb.minisig", rd.SignWithComments(foreign, "timestamp:1", "alien"))
	if code, _ := run(hlp + "stage " + incomingDir + "/alien.deb " + ver); code == 0 {
		t.Error("stage с чужой подписью разрешён")
	}
	// Подписанный checksums другой версии не подходит под запрошенную.
	putRelease("wrongver.deb", data)
	if code, _ := run(hlp + "stage " + incomingDir + "/wrongver.deb 9.9.9"); code == 0 {
		t.Error("stage версии 9.9.9 с чужим deb разрешён")
	}
	if out := docker(t, "exec", name, "sh", "-c", "ls "+packagesDir); strings.Contains(out, "9.9.9") {
		t.Errorf("в packages попал посторонний файл: %s", out)
	}
	if code, _ := run(hlp + "install " + ver); code != 0 {
		t.Error("доверенный кэш испорчен отклонёнными stage")
	}
	// deploy не может писать в packages напрямую.
	if f, err := sc.Create(packagesDir + "/tgproxy_6.6.6_" + arch + ".deb"); err == nil {
		_ = f.Close()
		t.Error("deploy записал файл в packages")
	}
	_ = dcl.Close()

	// Повторная установка на уже настроенный хост (пакет и пользователь на месте) с провалом проверки:
	// откат не трогает пакет и пользователя, агент выключен.
	hc2 := &fakeHealth{err: errors.New("telegram недоступен")}
	inst2, err := New(Config{
		Store: e.st, CA: e.ca, Health: hc2, Alerter: e.alerts, ServerKey: srvKey, PackagesDir: pkgDir, Verifier: verifier,
		HealthTimeout: 2 * time.Second, HealthInterval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer inst2.Close()
	// Хост переустанавливают под другим именем: запись it-1 удалена из реестра.
	if err := e.st.Agents().Delete(ctx, "it-1"); err != nil {
		t.Fatal(err)
	}
	req2 := req
	req2.Name = "it-2"
	req2.Auth = Auth{Password: []byte("adminpw")}
	id2, err := inst2.Install(ctx, req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = inst2.Wait(ctx, id2)
	st2, _ := inst2.Status(ctx, id2)
	if st2.State != store.InstallRolledBack {
		t.Fatalf("it-2: %+v", st2)
	}
	evs2, _, _ := inst2.Events(ctx, id2, 0)
	for _, ev := range evs2 {
		if ev.Kind == EventLog {
			t.Logf("it-2 %s: %s", ev.Step, ev.Message)
		}
	}
	if out := docker(t, "exec", name, "dpkg-query", "-W", "-f=${db:Status-Abbrev}", "tgproxy"); !strings.HasPrefix(out, "ii") {
		t.Fatalf("откат удалил заранее установленный пакет: %q", out)
	}
	if out, _ := exec.CommandContext(context.Background(), "docker", "exec", name, "systemctl", "is-enabled", "tgproxy-agent").Output(); strings.TrimSpace(string(out)) == "enabled" {
		t.Fatal("агент остался включённым после отката")
	}
	if _, err := e.st.Agents().Get(ctx, "it-2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("it-2 остался в БД: %v", err)
	}

	// Подмена host key: перегенерируем ключи sshd → отказ + алерт.
	docker(t, "exec", name, "sh", "-c", "rm -f /etc/ssh/ssh_host_* && ssh-keygen -A && systemctl restart ssh")
	time.Sleep(2 * time.Second)
	_, err = Dial(ctx, target, Auth{Password: []byte("adminpw")}, HostKeyPolicy{Repo: e.st.HostKeys(), AgentID: "it-1", Alerter: e.alerts, Timeout: 10 * time.Second})
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("после подмены ключа: %v", err)
	}
	if got := e.alerts.got(); len(got) != 1 || got[0][0] != "it-1" {
		t.Fatalf("алерты: %v", got)
	}
}
