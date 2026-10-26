//go:build integration

package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Запуск: go test -tags integration -run IntegrationEmergency -v ./internal/server/installer/
// Нужны docker и ДВЕ подписанные dev-ключом версии в dev/data/packages (`make dev-packages`, затем
// ещё раз с другой версией сборки): установка версией A, затем аварийное обновление на B.

func TestIntegrationEmergencyUpdateInDebianSystemd(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker недоступен")
	}
	if err := exec.CommandContext(context.Background(), "docker", "info").Run(); err != nil {
		t.Skip("docker daemon недоступен")
	}
	arch := "amd64"
	if out, _ := exec.CommandContext(context.Background(), "docker", "info", "--format", "{{.Architecture}}").Output(); strings.Contains(string(out), "aarch64") || strings.Contains(string(out), "arm64") {
		arch = "arm64"
	}
	if a := os.Getenv("IT_ARCH"); a != "" {
		arch = a
	}
	platform := "linux/" + arch
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
	var vers []string
	ents, _ := os.ReadDir(pkgDir)
	for _, en := range ents {
		if !en.IsDir() {
			continue
		}
		if set, ferr := findPackages(pkgDir, en.Name()); ferr == nil {
			if _, _, ok := set.path(arch); ok {
				vers = append(vers, en.Name())
			}
		}
	}
	sort.Slice(vers, func(i, j int) bool { return compareVersions(vers[i], vers[j]) < 0 })
	if len(vers) < 2 {
		t.Skipf("в %s нужны две версии deb для %s (сейчас %v): make dev-packages дважды", pkgDir, arch, vers)
	}
	verA, verB := vers[0], vers[len(vers)-1]
	verifier := verify.Verifier{Keys: []verify.PublicKey{devPub}}

	image := "tgproxy-installer-it:local"
	docker(t, "build", "-q", "--platform", platform, "-t", image, "-f", "testdata/Dockerfile.sshd-systemd", "testdata")
	sshPort, agentPort := freePort(t), freePort(t)
	name := fmt.Sprintf("tgproxy-emergency-it-%d", os.Getpid())
	docker(t, "run", "-d", "--platform", platform, "--name", name, "--privileged", "--cgroupns=host",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp",
		"-p", fmt.Sprintf("127.0.0.1:%d:22", sshPort), "-p", fmt.Sprintf("127.0.0.1:%d:%d", agentPort, agentPort), image)
	t.Cleanup(func() { _ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run() })

	ctx := context.Background()
	var fp string
	deadline := time.Now().Add(90 * time.Second)
	for {
		var perr error
		if _, fp, perr = ProbeHostKey(ctx, Target{Host: "127.0.0.1", Port: sshPort, User: "admin"}); perr == nil {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.CommandContext(context.Background(), "docker", "logs", "--tail", "30", name).CombinedOutput()
			t.Fatalf("sshd не поднялся: %v\n%s", perr, logs)
		}
		time.Sleep(time.Second)
	}
	for i := 0; i < 60; i++ {
		out, _ := exec.CommandContext(context.Background(), "docker", "exec", name, "systemctl", "is-system-running").Output()
		if s := strings.TrimSpace(string(out)); s == "running" || s == "degraded" {
			break
		}
		time.Sleep(time.Second)
	}

	e := newEnv(t)
	srvKey, err := LoadOrCreateServerKey(filepath.Join(t.TempDir(), "ssh"))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := New(Config{
		Store: e.st, CA: e.ca, Health: mtlsHealth{ca: e.ca}, Alerter: e.alerts, ServerKey: srvKey, PackagesDir: pkgDir, Verifier: verifier,
		HealthTimeout: 60 * time.Second, StepTimeout: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inst.Close)

	wait := func(id string) JobStatus {
		t.Helper()
		wctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
		defer cancel()
		if err := inst.Wait(wctx, id); err != nil {
			t.Fatal(err)
		}
		st, _ := inst.Status(ctx, id)
		if st.State != store.InstallDone {
			evs, _, _ := inst.Events(ctx, id, 0)
			for _, ev := range evs {
				t.Logf("%s %-7s %s", ev.Step, ev.Kind, ev.Message)
			}
		}
		return st
	}
	installed := func() string {
		out := docker(t, "exec", name, "dpkg-query", "-W", "-f=${Version}", "tgproxy")
		return strings.ReplaceAll(out, "~", "-")
	}

	// 1. Установка версией A.
	id, err := inst.Install(ctx, Request{
		Name: "it-em", Host: "127.0.0.1", SSHPort: sshPort, User: "admin", AgentPort: agentPort, Weight: 50,
		Auth: Auth{Password: []byte("adminpw")}, ConfirmedFingerprint: fp, PackageVersion: verA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := wait(id); st.State != store.InstallDone {
		t.Fatalf("установка %s: %+v", verA, st)
	}
	if got := installed(); got != verA {
		t.Fatalf("после установки версия %q, ожидалась %q", got, verA)
	}

	// 2. Аварийное обновление A → B: только tgproxy-deploy и серверный ключ, админских кредов нет.
	id, err = inst.EmergencyUpdate(ctx, "it-em", verB)
	if err != nil {
		t.Fatal(err)
	}
	st := wait(id)
	if st.State != store.InstallDone || st.Kind != JobKindEmergency {
		t.Fatalf("аварийное обновление: %+v", st)
	}
	if got := installed(); got != verB {
		t.Fatalf("после аварийного обновления версия %q, ожидалась %q", got, verB)
	}
	if out := docker(t, "exec", name, "systemctl", "is-active", "tgproxy-agent"); out != "active" {
		t.Fatalf("tgproxy-agent: %q", out)
	}
	if err := (mtlsHealth{ca: e.ca}).Check(ctx, "https://127.0.0.1:"+fmt.Sprint(agentPort), "it-em"); err != nil {
		t.Fatalf("агент на %s не отвечает по mTLS: %v", verB, err)
	}
	// Доверенный кэш хоста пополнен версией B через deploy-helper stage.
	if out := docker(t, "exec", name, "ls", packagesDir+"/"+verB); !strings.Contains(out, "checksums.txt.minisig") {
		t.Fatalf("кэш хоста для %s: %s", verB, out)
	}
	// incoming пуст (хелпер удалил свои входные файлы).
	if out := docker(t, "exec", name, "sh", "-c", "ls -A "+incomingDir+" | wc -l"); strings.TrimSpace(out) != "0" {
		t.Fatalf("в incoming остались файлы: %s", out)
	}

	// 3. Даунгрейд на A хелпер отвергает: задача падает, версия B на месте, incoming вычищен.
	id, err = inst.EmergencyUpdate(ctx, "it-em", verA)
	if err != nil {
		t.Fatal(err)
	}
	if st := wait(id); st.State == store.InstallDone {
		t.Fatalf("даунгрейд принят: %+v", st)
	}
	if got := installed(); got != verB {
		t.Fatalf("после отклонённого даунгрейда версия %q, ожидалась %q", got, verB)
	}
	if out := docker(t, "exec", name, "sh", "-c", "ls -A "+incomingDir+" | wc -l"); strings.TrimSpace(out) != "0" {
		t.Fatalf("после отказа в incoming остались файлы: %s", out)
	}
}
