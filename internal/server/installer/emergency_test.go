package installer

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// emergencyEnv — окружение с уже установленным агентом (SSH-цель и ключ хоста закреплены установкой).
// Каталог приёма на «хосте» заменён на temp-каталог: SFTP фейкового sshd пишет в локальную ФС.
func emergencyEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	opts = append([]envOpt{func(c *Config) { c.remoteIncoming = c.RemoteTmpDir }}, opts...)
	e := newEnv(t, opts...)
	req := e.request()
	req.PackageVersion = "1.3.0"
	if _, st := e.install(req); st.State != store.InstallDone {
		t.Fatalf("установка: %+v", st)
	}
	return e
}

func (e *env) emergency(version string) (string, JobStatus) {
	e.t.Helper()
	id, err := e.inst.EmergencyUpdate(context.Background(), "ams-2", version)
	if err != nil {
		e.t.Fatalf("EmergencyUpdate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := e.inst.Wait(ctx, id); err != nil {
		e.t.Fatalf("Wait: %v", err)
	}
	st, err := e.inst.Status(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return id, st
}

// newFiles — файлы в каталоге приёма «хоста», появившиеся после снимка before.
func (e *env) newFiles(before map[string]bool) []string {
	var out []string
	ents, _ := os.ReadDir(e.rtmp)
	for _, en := range ents {
		if !before[en.Name()] {
			out = append(out, en.Name())
		}
	}
	return out
}

func (e *env) snapshotFiles() map[string]bool {
	m := map[string]bool{}
	ents, _ := os.ReadDir(e.rtmp)
	for _, en := range ents {
		m[en.Name()] = true
	}
	return m
}

// newCmds — команды хоста после установки.
func (e *env) newCmds(skip int) []string {
	all := e.cmdLines()
	return all[skip:]
}

func TestInstallStoresSSHTarget(t *testing.T) {
	e := emergencyEnv(t)
	ag, err := e.st.Agents().Get(context.Background(), "ams-2")
	if err != nil || ag.SSHHost != "127.0.0.1" || ag.SSHPort != e.host.port() {
		t.Fatalf("ssh target: %+v err=%v", ag, err)
	}
}

func TestEmergencyUpdateSuccess(t *testing.T) {
	e := emergencyEnv(t)
	skip := len(e.host.commands())
	before := e.snapshotFiles()
	id, st := e.emergency("v1.4.1") // «v» срезается

	if st.State != store.InstallDone || st.Error != "" || st.Kind != JobKindEmergency || st.AgentID != "ams-2" || st.FinishedAt == nil {
		t.Fatalf("status %+v", st)
	}
	wantLabels := []string{
		"SSH-подключение под tgproxy-deploy, ключ хоста сверен",
		"Проверка подписи и загрузка пакета tgproxy 1.4.1",
		"Перенос в доверенный кэш хоста (deploy-helper stage)",
		"Установка пакета 1.4.1 (deploy-helper install)",
		"Перезапуск tgproxy-agent",
		"Проверка mTLS и доступа к Telegram",
	}
	if len(st.Steps) != len(wantLabels) {
		t.Fatalf("steps %+v", st.Steps)
	}
	for k, s := range st.Steps {
		if s.Label != wantLabels[k] || s.Status != StepOK {
			t.Fatalf("step %d: %+v", k, s)
		}
	}
	eq(t, e.newCmds(skip), []string{
		"[tgproxy-deploy] /usr/bin/dpkg --print-architecture",
		"[tgproxy-deploy] /usr/bin/sha256sum TMP",
		"[tgproxy-deploy] sudo -n /usr/bin/tgproxy deploy-helper stage TMP 1.4.1",
		"[tgproxy-deploy] sudo -n /usr/bin/tgproxy deploy-helper install 1.4.1",
		"[tgproxy-deploy] sudo -n /usr/bin/tgproxy deploy-helper unit restart",
		"[tgproxy-deploy] sudo -n /usr/bin/tgproxy deploy-helper unit is-active",
	})
	// Никаких админских кредов и команд вне deploy-helper (кроме arch/sha256).
	for _, c := range e.host.commands()[skip:] {
		if c.User != deployUser {
			t.Fatalf("команда не под %s: %s", deployUser, c)
		}
	}
	if got := e.health.called(); len(got) != 2 || got[1] != "https://127.0.0.1:8443|ams-2" {
		t.Fatalf("health %v", got)
	}

	// В incoming ушли ровно три файла релиза: deb, .checksums, .minisig.
	var deb string
	added := e.newFiles(before)
	if len(added) != 3 {
		t.Fatalf("в incoming ожидалось 3 новых файла: %v", added)
	}
	for _, n := range added {
		if !strings.Contains(n, ".") {
			deb = filepath.Join(e.rtmp, n)
		}
	}
	if deb == "" {
		t.Fatalf("deb не найден: %v", added)
	}
	rel := filepath.Join(e.pkgDir, "1.4.1")
	for dst, src := range map[string]string{
		deb: "tgproxy_1.4.1_amd64.deb", deb + ".checksums": "checksums.txt", deb + ".minisig": "checksums.txt.minisig",
	} {
		got, err1 := os.ReadFile(dst)
		want, err2 := os.ReadFile(filepath.Join(rel, src))
		if err1 != nil || err2 != nil || string(got) != string(want) {
			t.Fatalf("%s != %s (%v %v)", dst, src, err1, err2)
		}
	}

	evs := e.allEvents(id)
	if last := evs[len(evs)-1]; last.Kind != EventDone || !strings.Contains(last.Message, "1.4.1") {
		t.Fatalf("последнее событие %+v", last)
	}
}

func TestEmergencyUpdateHostKeyMismatch(t *testing.T) {
	e := emergencyEnv(t)
	skip := len(e.host.commands())
	before := e.snapshotFiles()
	e.host.setHostKey(newHostKey(t))
	_, st := e.emergency("1.4.1")
	if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "host key mismatch") {
		t.Fatalf("status %+v", st)
	}
	if len(e.host.commands()) != skip {
		t.Fatalf("при подмене ключа на хост ушли команды: %v", e.newCmds(skip))
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(e.host.port()))
	got := e.alerts.got()
	if len(got) != 1 || got[0] != [2]string{"ams-2", addr} {
		t.Fatalf("alerts %v", got)
	}
	if added := e.newFiles(before); len(added) != 0 {
		t.Fatalf("на хост что-то загружено: %v", added)
	}
}

func TestEmergencyUpdateForeignSignatureUploadsNothing(t *testing.T) {
	e := emergencyEnv(t)
	skip := len(e.host.commands())
	before := e.snapshotFiles()
	_, other, _ := minisign.GenerateKey(rand.Reader)
	writeRelease(t, e.pkgDir, "1.5.0", other, map[string]string{"amd64": "deb-body-1.5.0"})
	_, st := e.emergency("1.5.0")
	if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "подпись") {
		t.Fatalf("status %+v", st)
	}
	eq(t, e.newCmds(skip), []string{"[tgproxy-deploy] /usr/bin/dpkg --print-architecture"})
	if added := e.newFiles(before); len(added) != 0 {
		t.Fatalf("на хост что-то загружено: %v", added)
	}
}

func TestEmergencyUpdateTamperedDebUploadsNothing(t *testing.T) {
	e := emergencyEnv(t)
	skip := len(e.host.commands())
	p := filepath.Join(e.pkgDir, "1.4.1", "tgproxy_1.4.1_amd64.deb")
	if err := os.WriteFile(p, []byte("deb-body-evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, st := e.emergency("1.4.1")
	if st.State != store.InstallRolledBack || !strings.Contains(st.Error, "sha256") {
		t.Fatalf("status %+v", st)
	}
	if len(e.newCmds(skip)) != 1 {
		t.Fatalf("cmds %v", e.newCmds(skip))
	}
}

func TestEmergencyUpdateHelperFailureCleansUp(t *testing.T) {
	e := emergencyEnv(t)
	e.host.mu.Lock()
	e.host.failOn = map[string]string{"deploy-helper stage": "stage failed"}
	e.host.mu.Unlock()
	skip := len(e.host.commands())
	id, st := e.emergency("1.4.1")
	if st.State != store.InstallFailed || !strings.Contains(st.Error, "stage failed") {
		t.Fatalf("status %+v", st)
	}
	lines := strings.Join(e.newCmds(skip), "\n")
	if !strings.Contains(lines, "[tgproxy-deploy] /usr/bin/rm -f TMP TMP.checksums TMP.minisig") {
		t.Fatalf("incoming не вычищен:\n%s", lines)
	}
	if strings.Contains(lines, "deploy-helper install") || strings.Contains(lines, "unit restart") {
		t.Fatalf("шаги после неудачного stage выполнены:\n%s", lines)
	}
	evs := e.allEvents(id)
	if last := evs[len(evs)-1]; last.Kind != EventError || !strings.Contains(last.Message, "проверьте хост") {
		t.Fatalf("последнее событие %+v", last)
	}
}

func TestEmergencyUpdateHealthFailure(t *testing.T) {
	e := emergencyEnv(t)
	e.health.mu.Lock()
	e.health.err = errors.New("tls: handshake failure")
	e.health.mu.Unlock()
	_, st := e.emergency("1.4.1")
	if st.State != store.InstallFailed || !strings.Contains(st.Error, "mTLS") {
		t.Fatalf("status %+v", st)
	}
}

func TestEmergencyUpdateRejects(t *testing.T) {
	t.Run("агент без ssh_host", func(t *testing.T) {
		e := emergencyEnv(t)
		if _, err := e.st.Agents().Create(context.Background(), store.Agent{ID: "legacy", Name: "legacy", URL: "https://10.0.0.9:8443", Mode: store.ModeDial, Weight: 1}); err != nil {
			t.Fatal(err)
		}
		conns := e.host.connCount()
		if _, err := e.inst.EmergencyUpdate(context.Background(), "legacy", "1.4.1"); !errors.Is(err, ErrNoSSHTarget) {
			t.Fatalf("err = %v", err)
		}
		if e.host.connCount() != conns {
			t.Fatal("были подключения")
		}
	})
	t.Run("неизвестный агент", func(t *testing.T) {
		e := emergencyEnv(t)
		if _, err := e.inst.EmergencyUpdate(context.Background(), "ghost", "1.4.1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("ключ хоста не закреплён", func(t *testing.T) {
		e := emergencyEnv(t)
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(e.host.port()))
		if err := e.st.HostKeys().Delete(context.Background(), addr); err != nil {
			t.Fatal(err)
		}
		var unk *ErrHostKeyUnknown
		if _, err := e.inst.EmergencyUpdate(context.Background(), "ams-2", "1.4.1"); !errors.As(err, &unk) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("плохая версия и нет релиза", func(t *testing.T) {
		e := emergencyEnv(t)
		for _, v := range []string{"", "1.4", "1.4.1; rm -rf /", "../1.4.1"} {
			if _, err := e.inst.EmergencyUpdate(context.Background(), "ams-2", v); err == nil {
				t.Fatalf("версия %q принята", v)
			}
		}
		if _, err := e.inst.EmergencyUpdate(context.Background(), "ams-2", "9.9.9"); err == nil {
			t.Fatal("несуществующий релиз принят")
		}
	})
	t.Run("второе обновление того же агента", func(t *testing.T) {
		e := emergencyEnv(t)
		e.health.mu.Lock()
		e.health.block = true
		e.health.mu.Unlock()
		id, err := e.inst.EmergencyUpdate(context.Background(), "ams-2", "1.4.1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.inst.EmergencyUpdate(context.Background(), "ams-2", "1.4.1"); !errors.Is(err, ErrEmergencyBusy) {
			t.Fatalf("err = %v", err)
		}
		e.inst.Close()
		_ = id
	})
}
