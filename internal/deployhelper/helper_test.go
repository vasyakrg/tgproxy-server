package deployhelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type fixture struct {
	t        *testing.T
	h        *Helper
	pkgs     string
	incoming string
	out, err bytes.Buffer
	calls    []string
	arch     string
	runErr   error
	foreign  map[string]bool // пути, владелец которых «не root»
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := t.TempDir()
	f := &fixture{t: t, pkgs: filepath.Join(d, "packages"), incoming: filepath.Join(d, "incoming"), arch: "amd64", foreign: map[string]bool{}}
	for _, p := range []string{f.pkgs, f.incoming} {
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h := New(&f.out, &f.err)
	h.PackagesDir, h.IncomingDir = f.pkgs, f.incoming
	h.EUID = func() int { return 0 }
	h.Owner = func(fi os.FileInfo) (uint32, bool) {
		if f.foreign[fi.Name()] {
			return 1000, true
		}
		return 0, true
	}
	h.Verifier = SHA256Verifier{Owner: h.Owner}
	h.Run = func(_ context.Context, stdout, _ io.Writer, name string, args ...string) error {
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		if name == dpkgPath && len(args) == 1 {
			_, _ = io.WriteString(stdout, f.arch+"\n")
		}
		return f.runErr
	}
	f.h = h
	return f
}

func (f *fixture) main(args ...string) int { return f.h.Main(context.Background(), args) }

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (f *fixture) writeIncoming(name string, body []byte, sha string) string {
	f.t.Helper()
	p := filepath.Join(f.incoming, name)
	must(f.t, os.WriteFile(p, body, 0o600))
	if sha != "" {
		must(f.t, os.WriteFile(p+".sha256", []byte(sha+"  "+name+"\n"), 0o600))
	}
	return p
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) debFile(v string) string { return filepath.Join(f.pkgs, "tgproxy_"+v+"_amd64.deb") }

func (f *fixture) installed(v string, body []byte, sha string) {
	f.t.Helper()
	must(f.t, os.WriteFile(f.debFile(v), body, 0o644))
	if sha != "" {
		must(f.t, os.WriteFile(f.debFile(v)+".sha256", []byte(sha+"  x\n"), 0o644))
	}
}

func TestNotRoot(t *testing.T) {
	f := newFixture(t)
	f.h.EUID = func() int { return 1000 }
	if c := f.main("unit", "status"); c != 1 || len(f.calls) != 0 {
		t.Fatalf("code %d calls %v", c, f.calls)
	}
}

func TestUsageRejected(t *testing.T) {
	f := newFixture(t)
	bad := [][]string{
		nil, {"bogus"}, {"install"}, {"install", "1.0.0", "x"}, {"stage", "a"}, {"stage", "a", "b", "c"},
		{"unit"}, {"unit", "start", "x"}, {"unit", "link"}, {"unit", "mask"}, {"unit", "edit"}, {"unit", "START"}, {"unit", ""},
		{"install", "1.0.0 /tmp/evil.deb"}, {"install", "../1.0.0"}, {"install", "1.0"}, {"install", "01.0.0"},
		{"install", "1.0.0/../../x"}, {"install", "1.0.0;id"}, {"install", "1.0.0+build"}, {"install", "$(id)"},
		{"install", "1.0.0-"}, {"install", "1.0.0-a b"}, {"install", ""}, {"install", "v1.0.0"},
	}
	for _, a := range bad {
		if c := f.main(a...); c != ExitUsage {
			t.Errorf("%q: код %d, want 2", a, c)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("команды выполнены на невалидном вводе: %v", f.calls)
	}
}

func TestUnitVerbs(t *testing.T) {
	f := newFixture(t)
	want := map[string]string{
		"start": "/usr/bin/systemctl start tgproxy-agent", "stop": "/usr/bin/systemctl stop tgproxy-agent",
		"restart": "/usr/bin/systemctl restart tgproxy-agent", "status": "/usr/bin/systemctl status tgproxy-agent",
		"is-active": "/usr/bin/systemctl is-active tgproxy-agent",
		"enable":    "/usr/bin/systemctl enable --now tgproxy-agent", "disable": "/usr/bin/systemctl disable --now tgproxy-agent",
	}
	for verb, cmd := range want {
		f.calls = nil
		if c := f.main("unit", verb); c != 0 || len(f.calls) != 1 || f.calls[0] != cmd {
			t.Errorf("%s: code %d calls %v", verb, c, f.calls)
		}
	}
	f.runErr = errors.New("boom")
	if c := f.main("unit", "start"); c != 1 || !strings.Contains(f.err.String(), "boom") {
		t.Fatalf("code %d %q", c, f.err.String())
	}
}

func TestInstallOK(t *testing.T) {
	f := newFixture(t)
	body := []byte("deb")
	f.installed("1.4.1", body, sum(body))
	if c := f.main("install", "1.4.1"); c != 0 {
		t.Fatalf("code %d: %s", c, f.err.String())
	}
	want := "/usr/bin/dpkg -i " + f.debFile("1.4.1")
	if len(f.calls) != 2 || f.calls[1] != want {
		t.Fatalf("calls %v", f.calls)
	}
	// prerelease тоже допустим
	f.installed("0.0.1-snapshot", body, sum(body))
	if c := f.main("install", "0.0.1-snapshot"); c != 0 {
		t.Fatalf("snapshot: %d %s", c, f.err.String())
	}
}

func TestInstallRefusals(t *testing.T) {
	body := []byte("deb")
	cases := map[string]func(f *fixture){
		"нет файла":      func(_ *fixture) {},
		"нет sha256":     func(f *fixture) { f.installed("1.0.0", body, "") },
		"чужой sha256":   func(f *fixture) { f.installed("1.0.0", body, sum([]byte("other"))) },
		"мусор в sha256": func(f *fixture) { f.installed("1.0.0", body, "zz") },
		"hex не hex": func(f *fixture) {
			f.installed("1.0.0", body, strings.Repeat("g", 64))
		},
		"симлинк": func(f *fixture) {
			realFile := filepath.Join(filepath.Dir(f.pkgs), "realFile.deb")
			must(f.t, os.WriteFile(realFile, body, 0o644))
			must(f.t, os.Symlink(realFile, f.debFile("1.0.0")))
			must(f.t, os.WriteFile(f.debFile("1.0.0")+".sha256", []byte(sum(body)), 0o644))
		},
		"не root владелец": func(f *fixture) {
			f.installed("1.0.0", body, sum(body))
			f.foreign[filepath.Base(f.debFile("1.0.0"))] = true
		},
		"sha256 не root": func(f *fixture) {
			f.installed("1.0.0", body, sum(body))
			f.foreign[filepath.Base(f.debFile("1.0.0"))+".sha256"] = true
		},
		"group-writable": func(f *fixture) {
			f.installed("1.0.0", body, sum(body))
			must(f.t, os.Chmod(f.debFile("1.0.0"), 0o664))
		},
		"sha256 writable": func(f *fixture) {
			f.installed("1.0.0", body, sum(body))
			must(f.t, os.Chmod(f.debFile("1.0.0")+".sha256", 0o666))
		},
		"каталог — файл": func(f *fixture) {
			must(f.t, os.Mkdir(f.debFile("1.0.0"), 0o755))
		},
		"fifo": func(f *fixture) {
			must(f.t, syscall.Mkfifo(f.debFile("1.0.0"), 0o644))
		},
		"packages writable прочими": func(f *fixture) {
			f.installed("1.0.0", body, sum(body))
			must(f.t, os.Chmod(f.pkgs, 0o777))
		},
		"packages не root": func(f *fixture) {
			f.installed("1.0.0", body, sum(body))
			f.foreign["packages"] = true
		},
		"packages симлинк": func(f *fixture) {
			f.installed("1.0.0", body, sum(body))
			link := f.pkgs + "-link"
			must(f.t, os.Symlink(f.pkgs, link))
			f.h.PackagesDir = link
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			setup(f)
			c := f.main("install", "1.0.0")
			if c == 0 {
				t.Fatal("установка разрешена")
			}
			for _, call := range f.calls {
				if strings.Contains(call, " -i ") {
					t.Fatalf("dpkg -i вызван: %v", f.calls)
				}
			}
		})
	}
}

func TestInstallArchErrors(t *testing.T) {
	f := newFixture(t)
	f.arch = "AMD 64;"
	if c := f.main("install", "1.0.0"); c != 1 {
		t.Fatalf("code %d", c)
	}
	f = newFixture(t)
	f.runErr = errors.New("no dpkg")
	if c := f.main("install", "1.0.0"); c != 1 {
		t.Fatalf("code %d", c)
	}
}

func TestInstallDpkgFailure(t *testing.T) {
	f := newFixture(t)
	body := []byte("deb")
	f.installed("1.0.0", body, sum(body))
	f.h.Run = func(_ context.Context, stdout, _ io.Writer, _ string, args ...string) error {
		if len(args) == 1 {
			_, _ = io.WriteString(stdout, "amd64")
			return nil
		}
		return errors.New("dpkg failed")
	}
	if c := f.main("install", "1.0.0"); c != 1 {
		t.Fatalf("code %d", c)
	}
}

func TestStageOK(t *testing.T) {
	f := newFixture(t)
	body := []byte("new-deb-body")
	p := f.writeIncoming("up-1.deb", body, sum(body))
	if c := f.main("stage", p, "1.4.1"); c != 0 {
		t.Fatalf("code %d: %s", c, f.err.String())
	}
	got, err := os.ReadFile(f.debFile("1.4.1"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("deb: %q %v", got, err)
	}
	if fi, _ := os.Stat(f.debFile("1.4.1")); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("входной файл не удалён")
	}
	ents, _ := os.ReadDir(f.pkgs)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".stage-") || strings.HasSuffix(e.Name(), ".new") {
			t.Fatalf("мусор в packages: %s", e.Name())
		}
	}
	// после stage install проходит проверку sha256
	f.calls = nil
	if c := f.main("install", "1.4.1"); c != 0 {
		t.Fatalf("install после stage: %d %s", c, f.err.String())
	}
}

func TestStageRefusals(t *testing.T) {
	body := []byte("body")
	good := sum(body)
	cases := map[string]func(f *fixture) []string{
		"вне incoming": func(f *fixture) []string {
			p := filepath.Join(f.pkgs, "x.deb")
			must(f.t, os.WriteFile(p, body, 0o600))
			must(f.t, os.WriteFile(p+".sha256", []byte(good), 0o600))
			return []string{p, "1.0.0"}
		},
		"подкаталог": func(f *fixture) []string {
			return []string{f.incoming + "/sub/x.deb", "1.0.0"}
		},
		"..": func(f *fixture) []string {
			f.writeIncoming("x.deb", body, good)
			return []string{f.incoming + "/../incoming/x.deb", "1.0.0"}
		},
		"относительный": func(_ *fixture) []string { return []string{"x.deb", "1.0.0"} },
		"плохое имя": func(f *fixture) []string {
			return []string{f.incoming + "/a b.deb", "1.0.0"}
		},
		"плохая версия": func(f *fixture) []string {
			p := f.writeIncoming("x.deb", body, good)
			return []string{p, "1.0.0/../x"}
		},
		"симлинк": func(f *fixture) []string {
			secret := filepath.Join(filepath.Dir(f.incoming), "secret")
			must(f.t, os.WriteFile(secret, body, 0o600))
			p := filepath.Join(f.incoming, "x.deb")
			must(f.t, os.Symlink(secret, p))
			must(f.t, os.WriteFile(p+".sha256", []byte(good), 0o600))
			return []string{p, "1.0.0"}
		},
		"симлинк sha256": func(f *fixture) []string {
			p := f.writeIncoming("x.deb", body, "")
			realFile := filepath.Join(filepath.Dir(f.incoming), "realFile.sha")
			must(f.t, os.WriteFile(realFile, []byte(good), 0o600))
			must(f.t, os.Symlink(realFile, p+".sha256"))
			return []string{p, "1.0.0"}
		},
		"нет sha256": func(f *fixture) []string {
			return []string{f.writeIncoming("x.deb", body, ""), "1.0.0"}
		},
		"неверная сумма": func(f *fixture) []string {
			return []string{f.writeIncoming("x.deb", body, sum([]byte("other"))), "1.0.0"}
		},
		"мусорная сумма": func(f *fixture) []string {
			return []string{f.writeIncoming("x.deb", body, "abc"), "1.0.0"}
		},
		"нет файла": func(f *fixture) []string { return []string{f.incoming + "/none.deb", "1.0.0"} },
		"incoming не root": func(f *fixture) []string {
			f.foreign["incoming"] = true
			return []string{f.writeIncoming("x.deb", body, good), "1.0.0"}
		},
		"incoming симлинк": func(f *fixture) []string {
			link := f.incoming + "-link"
			must(f.t, os.Symlink(f.incoming, link))
			f.h.IncomingDir = link
			return []string{link + "/x.deb", "1.0.0"}
		},
		"incoming writable прочими": func(f *fixture) []string {
			p := f.writeIncoming("x.deb", body, good)
			must(f.t, os.Chmod(f.incoming, 0o777))
			return []string{p, "1.0.0"}
		},
		"packages отсутствует": func(f *fixture) []string {
			p := f.writeIncoming("x.deb", body, good)
			must(f.t, os.Remove(f.pkgs))
			return []string{p, "1.0.0"}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			args := setup(f)
			if c := f.main(append([]string{"stage"}, args...)...); c == 0 {
				t.Fatal("stage разрешён")
			}
			ents, _ := os.ReadDir(f.pkgs)
			for _, e := range ents {
				if strings.HasPrefix(e.Name(), "tgproxy_") || strings.HasPrefix(e.Name(), ".stage-") {
					t.Fatalf("в packages появился %s", e.Name())
				}
			}
		})
	}
}

func TestStageOversizeAndArchFailure(t *testing.T) {
	f := newFixture(t)
	body := []byte("x")
	p := f.writeIncoming("x.deb", body, sum(body))
	f.runErr = errors.New("no dpkg")
	if c := f.main("stage", p, "1.0.0"); c != 1 {
		t.Fatalf("code %d", c)
	}
}

func TestStageSumFileWriteFailure(t *testing.T) {
	f := newFixture(t)
	body := []byte("x")
	p := f.writeIncoming("x.deb", body, sum(body))
	// на месте итогового .sha256 лежит каталог: rename не пройдёт, deb не должен появиться
	must(t, os.Mkdir(f.debFile("1.0.0")+".sha256", 0o755))
	must(t, os.WriteFile(filepath.Join(f.debFile("1.0.0")+".sha256", "keep"), nil, 0o644))
	if c := f.main("stage", p, "1.0.0"); c == 0 {
		t.Fatal("ожидалась ошибка")
	}
	if _, err := os.Stat(f.debFile("1.0.0")); err == nil {
		t.Fatal("deb появился без контрольной суммы")
	}
	if _, err := os.Stat(f.debFile("1.0.0") + ".new"); err == nil {
		t.Fatal(".new не убран")
	}
}

func TestWriteAtomicErrors(t *testing.T) {
	d := t.TempDir()
	if err := writeAtomic(filepath.Join(d, "missing"), filepath.Join(d, "x"), func(io.Writer) error { return nil }); err == nil {
		t.Fatal("нет каталога")
	}
	if err := writeAtomic(d, filepath.Join(d, "x"), func(io.Writer) error { return fmt.Errorf("fill") }); err == nil {
		t.Fatal("fill error")
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 0 {
		t.Fatalf("остался временный файл: %v", ents)
	}
	if err := writeAtomic(d, filepath.Join(d, "nodir", "x"), func(io.Writer) error { return nil }); err == nil {
		t.Fatal("rename error")
	}
}

func TestDefaultsAndExecRun(t *testing.T) {
	var o, e bytes.Buffer
	h := New(&o, &e)
	if h.PackagesDir != "/var/lib/tgproxy/packages" || h.IncomingDir != "/var/lib/tgproxy-incoming" {
		t.Fatal("пути по умолчанию")
	}
	if _, ok := h.Owner(mustStat(t, t.TempDir())); !ok {
		t.Fatal("owner")
	}
	if _, ok := fileOwner(fakeInfo{mustStat(t, "/")}); ok {
		t.Fatal("Sys без Stat_t должен давать false")
	}
	if err := execRun(context.Background(), &o, &e, "/bin/echo", "hi"); err != nil || !strings.Contains(o.String(), "hi") {
		t.Fatalf("execRun: %v %q", err, o.String())
	}
	if err := execRun(context.Background(), &o, &e, "/bin/sh", "-c", "exit 3"); err == nil {
		t.Fatal("exit 3 без ошибки")
	}
	if h.rootOwned(fakeInfo{mustStat(t, "/")}) {
		t.Fatal("rootOwned при !ok")
	}
}

type fakeInfo struct{ os.FileInfo }

func (fakeInfo) Sys() any { return nil }

func mustStat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func TestReadSum(t *testing.T) {
	for _, in := range []string{"", "   ", "short", strings.Repeat("z", 64)} {
		if _, err := readSum(strings.NewReader(in)); err == nil {
			t.Errorf("%q принят", in)
		}
	}
	h := strings.Repeat("AB", 32)
	got, err := readSum(strings.NewReader(h + "  file\n"))
	if err != nil || got != strings.ToLower(h) {
		t.Fatalf("%q %v", got, err)
	}
}

func TestVerifierOwnerUnknown(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.deb")
	must(t, os.WriteFile(p, []byte("x"), 0o644))
	must(t, os.WriteFile(p+".sha256", []byte(sum([]byte("x"))), 0o644))
	f, _ := os.Open(p)
	defer func() { _ = f.Close() }()
	v := SHA256Verifier{Owner: func(os.FileInfo) (uint32, bool) { return 0, false }}
	if err := v.Verify(p, f); err == nil {
		t.Fatal("владелец неизвестен — должен быть отказ")
	}
	v = SHA256Verifier{Owner: func(os.FileInfo) (uint32, bool) { return 0, true }}
	if err := v.Verify(p, f); err != nil {
		t.Fatal(err)
	}
}
