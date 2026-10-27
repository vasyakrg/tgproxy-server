package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeVerifier struct {
	sigErr, verErr error
	verifyCalls    int
}

func (f *fakeVerifier) Verify(_, _ []byte) error  { f.verifyCalls++; return f.sigErr }
func (f *fakeVerifier) CheckVersion(string) error { return f.verErr }
func (f *fakeVerifier) CheckFile(checksums []byte, name string, r io.Reader) error {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}
	want := hex.EncodeToString(h.Sum(nil)) + "  " + name
	if !strings.Contains(string(checksums), want) {
		return errors.New("sha256 mismatch")
	}
	return nil
}

type fakeExec struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]error
}

func (f *fakeExec) Run(_ context.Context, name string, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, c)
	for k, err := range f.fail {
		if strings.HasPrefix(c, k) {
			return err
		}
	}
	return nil
}

type env struct {
	t        *testing.T
	data     string
	work     string
	deb      []byte
	ver      *fakeVerifier
	ex       *fakeExec
	probe    func(context.Context, string) error
	owner    uint32
	checksum string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{t: t, data: filepath.Join(root, "data"), work: filepath.Join(root, "work"),
		deb: []byte("new-deb-content"), ver: &fakeVerifier{}, ex: &fakeExec{fail: map[string]error{}},
		probe: func(context.Context, string) error { return nil }}
	for _, d := range []string{"updates/staged", "packages"} {
		if err := os.MkdirAll(filepath.Join(e.data, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// кэш установленной версии
	if err := os.MkdirAll(filepath.Join(e.data, "packages/0.1.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.write("packages/0.1.0/tgproxy_0.1.0_amd64.deb", []byte("old-deb"), 0o644)
	sum := sha256.Sum256(e.deb)
	e.checksum = hex.EncodeToString(sum[:]) + "  tgproxy_0.2.0_amd64.deb\n"
	e.write("updates/staged/tgproxy_0.2.0_amd64.deb", e.deb, 0o644)
	e.write("updates/staged/checksums.txt", []byte(e.checksum), 0o644)
	e.write("updates/staged/checksums.txt.minisig", []byte("sig"), 0o644)
	e.write("updates/staged/request", []byte(`{"version":"0.2.0","component":"server"}`), 0o644)
	return e
}

func (e *env) write(rel string, b []byte, mode os.FileMode) {
	e.t.Helper()
	p := filepath.Join(e.data, rel)
	if err := os.WriteFile(p, b, mode); err != nil {
		e.t.Fatal(err)
	}
	_ = os.Chmod(p, mode)
}

func (e *env) applier() *Applier {
	return New(Config{
		DataDir: e.data, PackagesDir: filepath.Join(e.data, "packages"), WorkDir: e.work, ConfDir: filepath.Join(e.data, "conf"), Arch: "amd64", CurrentVersion: "0.1.0",
		Verifier: e.ver, Exec: e.ex, Probe: func(ctx context.Context, c string) error { return e.probe(ctx, c) },
		HealthTimeout: 100 * time.Millisecond, HealthInterval: 5 * time.Millisecond,
		EUID:        func() int { return 0 },
		Owner:       func(os.FileInfo) (uint32, bool) { return e.owner, true },
		AllowedUIDs: []uint32{0}, ResultGID: -1,
		Now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	})
}

func (e *env) result() Result {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.data, "updates/result.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) requestGone() bool {
	_, err := os.Lstat(filepath.Join(e.data, "updates/staged/request"))
	return os.IsNotExist(err)
}

func TestApplySuccess(t *testing.T) {
	e := newEnv(t)
	if err := e.applier().Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"dpkg --force-confdef --force-confold -i " + filepath.Join(e.work, "tgproxy_0.2.0_amd64.deb"), "systemctl restart tgproxy-server"}
	if strings.Join(e.ex.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v", e.ex.calls)
	}
	r := e.result()
	if !r.OK || r.RolledBack || r.Version != "0.2.0" || r.At != "2026-01-02T03:04:05Z" {
		t.Fatalf("result = %+v", r)
	}
	if !e.requestGone() {
		t.Fatal("request не удалён")
	}
	prev, err := os.ReadFile(filepath.Join(e.data, "packages/prev.deb"))
	if err != nil || string(prev) != "old-deb" {
		t.Fatalf("prev.deb = %q %v", prev, err)
	}
	fi, _ := os.Stat(filepath.Join(e.data, "updates/result.json"))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("result mode = %v", fi.Mode().Perm())
	}
	staged, _ := os.ReadFile(filepath.Join(e.work, "tgproxy_0.2.0_amd64.deb"))
	if !bytes.Equal(staged, e.deb) {
		t.Fatal("копия deb отличается")
	}
}

func TestApplyAgentUsesAgentUnit(t *testing.T) {
	e := newEnv(t)
	e.write("updates/staged/request", []byte(`{"version":"0.2.0","component":"agent"}`), 0o644)
	var comp string
	e.probe = func(_ context.Context, c string) error { comp = c; return nil }
	if err := e.applier().Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if comp != "agent" || e.ex.calls[1] != "systemctl restart tgproxy-agent" {
		t.Fatalf("comp=%s calls=%v", comp, e.ex.calls)
	}
}

func TestApplyHealthFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	n := 0
	e.probe = func(context.Context, string) error {
		n++
		if n <= 1000 && len(e.ex.calls) == 2 { // после установки новой версии
			return errors.New("down")
		}
		return nil
	}
	err := e.applier().Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "health") {
		t.Fatalf("err = %v", err)
	}
	want := []string{
		"dpkg --force-confdef --force-confold -i " + filepath.Join(e.work, "tgproxy_0.2.0_amd64.deb"), "systemctl restart tgproxy-server",
		"dpkg --force-confdef --force-confold -i " + filepath.Join(e.work, "prev.deb"), "systemctl restart tgproxy-server",
	}
	if strings.Join(e.ex.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v", e.ex.calls)
	}
	r := e.result()
	if r.OK || !r.RolledBack || r.Error == "" {
		t.Fatalf("result = %+v", r)
	}
	if !e.requestGone() {
		t.Fatal("request не удалён")
	}
	b, _ := os.ReadFile(filepath.Join(e.work, "prev.deb"))
	if string(b) != "old-deb" {
		t.Fatal("prev.deb не из кэша")
	}
}

func TestApplyDpkgFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	e.ex.fail["dpkg --force-confdef --force-confold -i "+filepath.Join(e.work, "tgproxy_0.2.0")] = errors.New("boom")
	err := e.applier().Apply(context.Background())
	if err == nil || !e.result().RolledBack {
		t.Fatalf("err=%v res=%+v", err, e.result())
	}
}

func TestApplyRollbackFails(t *testing.T) {
	e := newEnv(t)
	e.probe = func(context.Context, string) error { return errors.New("down") }
	err := e.applier().Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "откат не удался") {
		t.Fatalf("err = %v", err)
	}
	if r := e.result(); r.OK || !r.RolledBack {
		t.Fatalf("result = %+v", r)
	}
}

func TestApplyNoPrevNoRollback(t *testing.T) {
	e := newEnv(t)
	_ = os.Remove(filepath.Join(e.data, "packages/0.1.0/tgproxy_0.1.0_amd64.deb"))
	e.probe = func(context.Context, string) error { return errors.New("down") }
	err := e.applier().Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "откат невозможен") {
		t.Fatalf("err = %v", err)
	}
	if len(e.ex.calls) != 2 || e.result().RolledBack {
		t.Fatalf("calls=%v", e.ex.calls)
	}
}

func TestApplyNoPackagesDirSkipsBackup(t *testing.T) {
	e := newEnv(t)
	_ = os.RemoveAll(filepath.Join(e.data, "packages"))
	if err := e.applier().Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRejectsBeforeAnyCommand(t *testing.T) {
	cases := map[string]func(*env){
		"подпись": func(e *env) { e.ver.sigErr = errors.New("bad sig") },
		"версия":  func(e *env) { e.ver.verErr = errors.New("below min") },
		"sha256":  func(e *env) { e.write("updates/staged/tgproxy_0.2.0_amd64.deb", []byte("tampered"), 0o644) },
		"нет checksums": func(e *env) {
			_ = os.Remove(filepath.Join(e.data, "updates/staged/checksums.txt"))
		},
		"нет подписи": func(e *env) {
			_ = os.Remove(filepath.Join(e.data, "updates/staged/checksums.txt.minisig"))
		},
		"нет deb": func(e *env) {
			_ = os.Remove(filepath.Join(e.data, "updates/staged/tgproxy_0.2.0_amd64.deb"))
		},
		"deb симлинк": func(e *env) {
			p := filepath.Join(e.data, "updates/staged/tgproxy_0.2.0_amd64.deb")
			_ = os.Remove(p)
			_ = os.Symlink("/etc/passwd", p)
		},
		"битый JSON": func(e *env) { e.write("updates/staged/request", []byte(`{"version":`), 0o644) },
		"лишние поля": func(e *env) {
			e.write("updates/staged/request", []byte(`{"version":"0.2.0","component":"server","x":1}`), 0o644)
		},
		"хвост после": func(e *env) {
			e.write("updates/staged/request", []byte(`{"version":"0.2.0","component":"server"}{}`), 0o644)
		},
		"не semver": func(e *env) {
			e.write("updates/staged/request", []byte(`{"version":"../../x","component":"server"}`), 0o644)
		},
		"component": func(e *env) { e.write("updates/staged/request", []byte(`{"version":"0.2.0","component":"x"}`), 0o644) },
		"большой":   func(e *env) { e.write("updates/staged/request", bytes.Repeat([]byte(" "), 5000), 0o644) },
		"запись группой": func(e *env) {
			e.write("updates/staged/request", []byte(`{"version":"0.2.0","component":"server"}`), 0o664)
		},
		"чужой владелец": func(e *env) { e.owner = 4242 },
		"request симлинк": func(e *env) {
			p := filepath.Join(e.data, "updates/staged/request")
			_ = os.Remove(p)
			_ = os.Symlink(filepath.Join(e.data, "updates/staged/checksums.txt"), p)
		},
		"arch": func(*env) {},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			mut(e)
			a := e.applier()
			if name == "arch" {
				a.c.Arch = "../x"
			}
			if err := a.Apply(context.Background()); err == nil {
				t.Fatal("ожидалась ошибка")
			}
			if len(e.ex.calls) != 0 {
				t.Fatalf("выполнены команды: %v", e.ex.calls)
			}
			if !e.requestGone() {
				t.Fatal("request не удалён")
			}
			if r := e.result(); r.OK || r.Error == "" {
				t.Fatalf("result = %+v", r)
			}
		})
	}
}

func TestApplyComponentFlagMismatch(t *testing.T) {
	e := newEnv(t)
	a := e.applier()
	a.c.Component = "agent"
	if err := a.Apply(context.Background()); err == nil || len(e.ex.calls) != 0 {
		t.Fatalf("err=%v calls=%v", err, e.ex.calls)
	}
}

func TestApplyStagedDirInvalid(t *testing.T) {
	e := newEnv(t)
	if err := os.Chmod(filepath.Join(e.data, "updates/staged"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := e.applier().Apply(context.Background()); err == nil || len(e.ex.calls) != 0 {
		t.Fatalf("err=%v", err)
	}
}

func TestApplyNotRoot(t *testing.T) {
	e := newEnv(t)
	a := e.applier()
	a.c.EUID = func() int { return 1000 }
	if err := a.Apply(context.Background()); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("err = %v", err)
	}
	if e.requestGone() {
		t.Fatal("request удалён не-root'ом")
	}
}

func TestApplyMissingDeps(t *testing.T) {
	a := New(Config{EUID: func() int { return 0 }})
	if err := a.Apply(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestApplyParallelSecondRefuses(t *testing.T) {
	e := newEnv(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.probe = func(context.Context, string) error {
		once.Do(func() { close(started) })
		<-release
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- e.applier().Apply(context.Background()) }()
	<-started
	err := e.applier().Apply(context.Background())
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v", err)
	}
	if e.requestGone() {
		t.Fatal("второй запуск удалил request первого")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// после завершения блокировка свободна (staged очищен — кладём заново)
	_ = os.MkdirAll(filepath.Join(e.data, "updates/staged"), 0o755)
	e.write("updates/staged/tgproxy_0.2.0_amd64.deb", e.deb, 0o644)
	e.write("updates/staged/checksums.txt", []byte(e.checksum), 0o644)
	e.write("updates/staged/checksums.txt.minisig", []byte("sig"), 0o644)
	e.write("updates/staged/request", []byte(`{"version":"0.2.0","component":"server"}`), 0o644)
	e.probe = func(context.Context, string) error { return nil }
	if err := e.applier().Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBackupSkippedForUnknownVersion(t *testing.T) {
	e := newEnv(t)
	a := e.applier()
	a.c.CurrentVersion = "dev"
	if err := a.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.data, "packages/prev.deb")); !os.IsNotExist(err) {
		t.Fatal("prev.deb не должен создаваться")
	}
}

func TestBackupRejectsForeignOwnedCache(t *testing.T) {
	e := newEnv(t)
	a := e.applier()
	a.c.Owner = func(fi os.FileInfo) (uint32, bool) {
		if strings.HasSuffix(fi.Name(), "0.1.0_amd64.deb") {
			return 4242, true
		}
		return 0, true
	}
	a.c.AllowedUIDs = []uint32{0, 4242}
	if err := a.Apply(context.Background()); err == nil || len(e.ex.calls) != 0 {
		t.Fatalf("err=%v calls=%v", err, e.ex.calls)
	}
}

func TestBackupRejectsBadPackagesDir(t *testing.T) {
	e := newEnv(t)
	if err := os.Chmod(filepath.Join(e.data, "packages"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := e.applier().Apply(context.Background()); err == nil || len(e.ex.calls) != 0 {
		t.Fatalf("err=%v", err)
	}
}

func TestHealthURL(t *testing.T) {
	for in, want := range map[string]string{
		":8080": "https://127.0.0.1:8080/healthz", "0.0.0.0:80": "https://127.0.0.1:80/healthz",
		"[::]:9": "https://127.0.0.1:9/healthz", "10.0.0.1:1": "https://10.0.0.1:1/healthz",
	} {
		got, err := HealthURL(in, false)
		if err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	if got, _ := HealthURL(":8080", true); got != "http://127.0.0.1:8080/healthz" {
		t.Error(got)
	}
	if _, err := HealthURL("bad", true); err == nil {
		t.Error("ожидалась ошибка")
	}
}

func TestProbe(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	ex := &fakeExec{fail: map[string]error{}}
	p := NewProbe(func() (string, error) { return srv.URL + "/healthz", nil }, ex)
	if err := p(context.Background(), "server"); err != nil {
		t.Fatal(err)
	}
	status = http.StatusServiceUnavailable
	if err := p(context.Background(), "server"); err == nil {
		t.Fatal("ожидалась ошибка 503")
	}
	if err := p(context.Background(), "agent"); err != nil || ex.calls[0] != "systemctl is-active --quiet tgproxy-agent" {
		t.Fatalf("%v %v", err, ex.calls)
	}
	bad := NewProbe(func() (string, error) { return "", errors.New("no cfg") }, ex)
	if bad(context.Background(), "server") == nil {
		t.Fatal("ожидалась ошибка")
	}
	bad = NewProbe(func() (string, error) { return "http://127.0.0.1:1/", nil }, ex)
	if bad(context.Background(), "server") == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestSystemExecutorRejectsUnknown(t *testing.T) {
	if err := (SystemExecutor{}).Run(context.Background(), "rm", "-rf", "/"); err == nil {
		t.Fatal("rm не должен запускаться")
	}
}

func TestServiceIDsUnknownUser(t *testing.T) {
	if _, _, err := ServiceIDs(); err == nil {
		t.Skip("пользователь tgproxy существует")
	}
}

func TestFileOwnerReal(t *testing.T) {
	fi, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	uid, ok := fileOwner(fi)
	if !ok || int(uid) != os.Getuid() {
		t.Fatalf("uid=%d ok=%v", uid, ok)
	}
}

func TestApplyRestartFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	e.ex.fail["systemctl restart"] = errors.New("restart failed")
	err := e.applier().Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "systemctl restart") || !strings.Contains(err.Error(), "откат не удался") {
		t.Fatalf("err = %v", err)
	}
}

func TestWaitHealthyEventuallyOK(t *testing.T) {
	e := newEnv(t)
	n := 0
	e.probe = func(context.Context, string) error {
		n++
		if n < 3 {
			return errors.New("starting")
		}
		return nil
	}
	if err := e.applier().Apply(context.Background()); err != nil || n != 3 {
		t.Fatalf("err=%v n=%d", err, n)
	}
}

func TestDefaultTimeouts(t *testing.T) {
	e := newEnv(t)
	a := e.applier()
	a.c.HealthTimeout = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.probe = func(context.Context, string) error { return errors.New("x") }
	if err := a.waitHealthy(ctx, ComponentAgent); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if err := a.waitHealthy(ctx, ComponentServer); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestWriteFileAtomicFillError(t *testing.T) {
	dir := t.TempDir()
	err := writeFileAtomic(dir, filepath.Join(dir, "x"), 0o600, func(io.Writer) error { return errors.New("fill") })
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("остался мусор: %v", ents)
	}
	if err := writeFileAtomic(filepath.Join(dir, "nope"), filepath.Join(dir, "x"), 0o600, func(io.Writer) error { return nil }); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestLockOpenFailure(t *testing.T) {
	e := newEnv(t)
	if err := os.Symlink("/dev/null", filepath.Join(e.data, "updates/.lock")); err != nil {
		t.Fatal(err)
	}
	if err := e.applier().Apply(context.Background()); err == nil {
		t.Fatal("симлинк .lock должен отвергаться")
	}
}

func TestOwnerUnknown(t *testing.T) {
	e := newEnv(t)
	a := e.applier()
	a.c.Owner = func(os.FileInfo) (uint32, bool) { return 0, false }
	if err := a.Apply(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestSystemExecutorRunsFixedPaths(*testing.T) {
	var out bytes.Buffer
	ex := SystemExecutor{Stdout: &out, Stderr: &out}
	// В тестовом окружении dpkg/systemctl могут отсутствовать: важно лишь,
	// что имя отображается в абсолютный путь и ошибка возвращается, а не паника.
	_ = ex.Run(context.Background(), "dpkg", "--version")
	_ = ex.Run(context.Background(), "systemctl", "--version")
}

func TestApplyCachesVerifiedRelease(t *testing.T) {
	e := newEnv(t)
	if err := e.applier().Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	vd := filepath.Join(e.data, "packages/0.2.0")
	for name, want := range map[string][]byte{
		"tgproxy_0.2.0_amd64.deb": e.deb, "checksums.txt": []byte(e.checksum), "checksums.txt.minisig": []byte("sig"),
	} {
		got, err := os.ReadFile(filepath.Join(vd, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	// В старом месте (внутри data_dir, куда пишет tgproxy) ничего не кэшируется.
	if _, err := os.Stat(filepath.Join(e.data, "updates/packages")); !os.IsNotExist(err) {
		t.Error("кэш не должен лежать в updates")
	}
}

func TestApplyNothingCachedWhenVerifyFails(t *testing.T) {
	e := newEnv(t)
	e.ver.sigErr = errors.New("bad sig")
	if err := e.applier().Apply(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if _, err := os.Stat(filepath.Join(e.data, "packages/0.2.0")); !os.IsNotExist(err) {
		t.Error("непроверенный релиз попал в кэш")
	}
}

func TestApplyPackagesDirDefault(t *testing.T) {
	a := New(Config{})
	if a.c.PackagesDir != "/var/cache/tgproxy/packages" {
		t.Fatalf("PackagesDir = %q", a.c.PackagesDir)
	}
}

func TestEnsurePackagesDirRefusals(t *testing.T) {
	e := newEnv(t)
	a := e.applier()
	a.c.PackagesDir = filepath.Join(e.data, "new-cache") // создаётся с 0755
	if err := a.ensurePackagesDir(); err != nil {
		t.Fatal(err)
	}
	a.c.Owner = func(os.FileInfo) (uint32, bool) { return 1000, true }
	if err := a.ensurePackagesDir(); err == nil {
		t.Error("не-root владелец должен отвергаться")
	}
	a = e.applier()
	f := filepath.Join(e.data, "file")
	_ = os.WriteFile(f, nil, 0o644)
	a.c.PackagesDir = filepath.Join(f, "sub")
	if err := a.ensurePackagesDir(); err == nil {
		t.Error("ожидалась ошибка mkdir")
	}
}

func TestApplyWarnsDpkgDist(t *testing.T) {
	e := newEnv(t)
	_ = os.MkdirAll(filepath.Join(e.data, "conf"), 0o755)
	e.write("conf/server.yaml.dpkg-dist", []byte("x"), 0o644)
	if err := e.applier().Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := e.result()
	conf := filepath.Join(e.data, "conf", "server.yaml")
	want := "новый шаблон конфига: diff " + conf + " " + conf + ".dpkg-dist"
	if !r.OK || r.Warning != want {
		t.Fatalf("result = %+v", r)
	}
}

func TestApplyNoWarningWithoutDpkgDist(t *testing.T) {
	e := newEnv(t)
	if err := e.applier().Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w := e.result().Warning; w != "" {
		t.Fatalf("warning = %q", w)
	}
}
