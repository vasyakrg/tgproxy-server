package deployhelper

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
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
	key      minisign.PrivateKey
	other    minisign.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := t.TempDir()
	f := &fixture{t: t, pkgs: filepath.Join(d, "packages"), incoming: filepath.Join(d, "incoming"), arch: "amd64", foreign: map[string]bool{}}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	must(t, err)
	_, other, err := minisign.GenerateKey(rand.Reader)
	must(t, err)
	f.key, f.other = priv, other
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
	h.Verifier = verify.Verifier{Keys: []verify.PublicKey{pub}, MinVersion: "1.0.0"}
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

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func signWith(k minisign.PrivateKey, msg []byte) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	_, _ = io.Copy(io.Discard, r)
	return r.SignWithComments(k, "timestamp:1 file:checksums.txt", "t")
}

// relFiles — подписанный релиз версии v с телом deb.
type relFiles struct {
	deb, sums, sig []byte
}

func (f *fixture) release(v string, deb []byte) relFiles {
	sums := []byte(sum(deb) + "  tgproxy_" + v + "_amd64.deb\n")
	return relFiles{deb: deb, sums: sums, sig: signWith(f.key, sums)}
}

// writeIncoming кладёт три файла релиза в incoming и возвращает путь deb.
func (f *fixture) writeIncoming(name string, r relFiles) string {
	f.t.Helper()
	p := filepath.Join(f.incoming, name)
	must(f.t, os.WriteFile(p, r.deb, 0o600))
	must(f.t, os.WriteFile(p+ChecksumsSuffix, r.sums, 0o600))
	must(f.t, os.WriteFile(p+SigSuffix, r.sig, 0o600))
	return p
}

func (f *fixture) verDir(v string) string { return filepath.Join(f.pkgs, v) }
func (f *fixture) debFile(v string) string {
	return filepath.Join(f.verDir(v), "tgproxy_"+v+"_amd64.deb")
}

// installed раскладывает релиз прямо в доверенный кэш (как после stage).
func (f *fixture) installed(v string, r relFiles) {
	f.t.Helper()
	must(f.t, os.MkdirAll(f.verDir(v), 0o755))
	must(f.t, os.WriteFile(f.debFile(v), r.deb, 0o644))
	must(f.t, os.WriteFile(filepath.Join(f.verDir(v), "checksums.txt"), r.sums, 0o644))
	must(f.t, os.WriteFile(filepath.Join(f.verDir(v), "checksums.txt.minisig"), r.sig, 0o644))
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
		{"unit"}, {"unit", "start", "x"}, {"unit", "link"}, {"unit", "mask"}, {"unit", "edit"}, {"unit", "START"}, {"unit", ""}, {"unit", "enable-update", "x"}, {"unit", "disable-update"}, {"unit", "enable-update;"},
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
		"enable-update": "/usr/bin/systemctl enable --now tgproxy-update-agent.path", "is-active-update": "/usr/bin/systemctl is-active tgproxy-update-agent.path",
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
	f.installed("1.4.1", f.release("1.4.1", []byte("deb")))
	if c := f.main("install", "1.4.1"); c != 0 {
		t.Fatalf("code %d: %s", c, f.err.String())
	}
	want := "/usr/bin/dpkg -i " + f.debFile("1.4.1")
	if len(f.calls) != 2 || f.calls[1] != want {
		t.Fatalf("calls %v", f.calls)
	}
	// prerelease выше нижней границы тоже допустим
	f.h.Verifier = verify.Verifier{Keys: f.h.Verifier.(verify.Verifier).Keys}
	f.installed("0.0.1-snapshot", f.release("0.0.1-snapshot", []byte("deb")))
	if c := f.main("install", "0.0.1-snapshot"); c != 0 {
		t.Fatalf("snapshot: %d %s", c, f.err.String())
	}
}

func TestInstallRefusals(t *testing.T) {
	cases := map[string]func(f *fixture){
		"нет файла": func(_ *fixture) {},
		"чужая подпись": func(f *fixture) {
			r := f.release("1.0.0", []byte("deb"))
			r.sig = signWith(f.other, r.sums)
			f.installed("1.0.0", r)
		},
		"изменён 1 байт deb": func(f *fixture) {
			r := f.release("1.0.0", []byte("deb"))
			r.deb = []byte("dEb")
			f.installed("1.0.0", r)
		},
		"checksums подменены под новый deb": func(f *fixture) {
			r := f.release("1.0.0", []byte("deb"))
			r.deb = []byte("evil")
			r.sums = []byte(sum(r.deb) + "  tgproxy_1.0.0_amd64.deb\n")
			f.installed("1.0.0", r)
		},
		"даунгрейд ниже установленной": func(f *fixture) {
			f.h.Verifier = verify.Verifier{Keys: f.h.Verifier.(verify.Verifier).Keys, MinVersion: "2.0.0"}
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
		},
		"нет подписи": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			must(f.t, os.Remove(filepath.Join(f.verDir("1.0.0"), "checksums.txt.minisig")))
		},
		"нет checksums": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			must(f.t, os.Remove(filepath.Join(f.verDir("1.0.0"), "checksums.txt")))
		},
		"deb не в checksums": func(f *fixture) {
			r := f.release("1.0.0", []byte("deb"))
			r.sums = []byte(sum(r.deb) + "  other.deb\n")
			r.sig = signWith(f.key, r.sums)
			f.installed("1.0.0", r)
		},
		"мусорная подпись": func(f *fixture) {
			r := f.release("1.0.0", []byte("deb"))
			r.sig = []byte("junk")
			f.installed("1.0.0", r)
		},
		"симлинк": func(f *fixture) {
			r := f.release("1.0.0", []byte("deb"))
			f.installed("1.0.0", r)
			realFile := filepath.Join(filepath.Dir(f.pkgs), "realFile.deb")
			must(f.t, os.WriteFile(realFile, r.deb, 0o644))
			must(f.t, os.Remove(f.debFile("1.0.0")))
			must(f.t, os.Symlink(realFile, f.debFile("1.0.0")))
		},
		"не root владелец deb": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			f.foreign[filepath.Base(f.debFile("1.0.0"))] = true
		},
		"checksums не root": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			f.foreign["checksums.txt"] = true
		},
		"подпись не root": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			f.foreign["checksums.txt.minisig"] = true
		},
		"group-writable": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			must(f.t, os.Chmod(f.debFile("1.0.0"), 0o664))
		},
		"каталог — файл": func(f *fixture) {
			must(f.t, os.MkdirAll(f.debFile("1.0.0"), 0o755))
		},
		"fifo": func(f *fixture) {
			must(f.t, os.MkdirAll(f.verDir("1.0.0"), 0o755))
			must(f.t, syscall.Mkfifo(f.debFile("1.0.0"), 0o644))
		},
		"packages writable прочими": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			must(f.t, os.Chmod(f.pkgs, 0o777))
		},
		"каталог версии writable прочими": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			must(f.t, os.Chmod(f.verDir("1.0.0"), 0o777))
		},
		"packages не root": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
			f.foreign["packages"] = true
		},
		"packages симлинк": func(f *fixture) {
			f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
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
	f.installed("1.0.0", f.release("1.0.0", []byte("deb")))
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
	r := f.release("1.4.1", body)
	p := f.writeIncoming("up-1.deb", r)
	if c := f.main("stage", p, "1.4.1"); c != 0 {
		t.Fatalf("code %d: %s", c, f.err.String())
	}
	got, err := os.ReadFile(f.debFile("1.4.1"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("deb: %q %v", got, err)
	}
	for n, want := range map[string][]byte{"checksums.txt": r.sums, "checksums.txt.minisig": r.sig} {
		if b, err := os.ReadFile(filepath.Join(f.verDir("1.4.1"), n)); err != nil || !bytes.Equal(b, want) {
			t.Fatalf("%s: %q %v", n, b, err)
		}
	}
	if fi, _ := os.Stat(f.debFile("1.4.1")); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	for _, x := range []string{p, p + ChecksumsSuffix, p + SigSuffix} {
		if _, err := os.Stat(x); !os.IsNotExist(err) {
			t.Fatalf("входной файл %s не удалён", x)
		}
	}
	ents, _ := os.ReadDir(f.verDir("1.4.1"))
	if len(ents) != 3 {
		t.Fatalf("в каталоге версии лишнее: %v", ents)
	}
	// после stage install проходит повторную проверку
	f.calls = nil
	if c := f.main("install", "1.4.1"); c != 0 {
		t.Fatalf("install после stage: %d %s", c, f.err.String())
	}
	// повторный stage той же версии идемпотентен
	p = f.writeIncoming("up-2.deb", r)
	if c := f.main("stage", p, "1.4.1"); c != 0 {
		t.Fatalf("повторный stage: %d %s", c, f.err.String())
	}
}

func TestStageRefusals(t *testing.T) {
	body := []byte("body")
	cases := map[string]func(f *fixture) []string{
		"вне incoming": func(f *fixture) []string {
			p := filepath.Join(f.pkgs, "x.deb")
			must(f.t, os.WriteFile(p, body, 0o600))
			return []string{p, "1.0.0"}
		},
		"подкаталог": func(f *fixture) []string { return []string{f.incoming + "/sub/x.deb", "1.0.0"} },
		"..": func(f *fixture) []string {
			f.writeIncoming("x.deb", f.release("1.0.0", body))
			return []string{f.incoming + "/../incoming/x.deb", "1.0.0"}
		},
		"относительный": func(_ *fixture) []string { return []string{"x.deb", "1.0.0"} },
		"плохое имя":    func(f *fixture) []string { return []string{f.incoming + "/a b.deb", "1.0.0"} },
		"плохая версия": func(f *fixture) []string {
			return []string{f.writeIncoming("x.deb", f.release("1.0.0", body)), "1.0.0/../x"}
		},
		"чужая подпись": func(f *fixture) []string {
			r := f.release("1.0.0", body)
			r.sig = signWith(f.other, r.sums)
			return []string{f.writeIncoming("x.deb", r), "1.0.0"}
		},
		"даунгрейд": func(f *fixture) []string {
			f.h.Verifier = verify.Verifier{Keys: f.h.Verifier.(verify.Verifier).Keys, MinVersion: "3.0.0"}
			return []string{f.writeIncoming("x.deb", f.release("1.0.0", body)), "1.0.0"}
		},
		"несовпадение sha256": func(f *fixture) []string {
			r := f.release("1.0.0", body)
			r.deb = []byte("bodz") // 1 байт
			return []string{f.writeIncoming("x.deb", r), "1.0.0"}
		},
		"подписанный checksums другой версии": func(f *fixture) []string {
			return []string{f.writeIncoming("x.deb", f.release("2.0.0", body)), "1.0.0"}
		},
		"симлинк": func(f *fixture) []string {
			secret := filepath.Join(filepath.Dir(f.incoming), "secret")
			must(f.t, os.WriteFile(secret, body, 0o600))
			r := f.release("1.0.0", body)
			p := f.writeIncoming("x.deb", r)
			must(f.t, os.Remove(p))
			must(f.t, os.Symlink(secret, p))
			return []string{p, "1.0.0"}
		},
		"симлинк checksums": func(f *fixture) []string {
			r := f.release("1.0.0", body)
			p := f.writeIncoming("x.deb", r)
			realFile := filepath.Join(filepath.Dir(f.incoming), "realFile.sums")
			must(f.t, os.WriteFile(realFile, r.sums, 0o600))
			must(f.t, os.Remove(p+ChecksumsSuffix))
			must(f.t, os.Symlink(realFile, p+ChecksumsSuffix))
			return []string{p, "1.0.0"}
		},
		"нет checksums": func(f *fixture) []string {
			p := f.writeIncoming("x.deb", f.release("1.0.0", body))
			must(f.t, os.Remove(p+ChecksumsSuffix))
			return []string{p, "1.0.0"}
		},
		"нет подписи": func(f *fixture) []string {
			p := f.writeIncoming("x.deb", f.release("1.0.0", body))
			must(f.t, os.Remove(p+SigSuffix))
			return []string{p, "1.0.0"}
		},
		"нет файла": func(f *fixture) []string { return []string{f.incoming + "/none.deb", "1.0.0"} },
		"incoming не root": func(f *fixture) []string {
			f.foreign["incoming"] = true
			return []string{f.writeIncoming("x.deb", f.release("1.0.0", body)), "1.0.0"}
		},
		"incoming симлинк": func(f *fixture) []string {
			link := f.incoming + "-link"
			must(f.t, os.Symlink(f.incoming, link))
			f.h.IncomingDir = link
			return []string{link + "/x.deb", "1.0.0"}
		},
		"incoming writable прочими": func(f *fixture) []string {
			p := f.writeIncoming("x.deb", f.release("1.0.0", body))
			must(f.t, os.Chmod(f.incoming, 0o777))
			return []string{p, "1.0.0"}
		},
		"packages отсутствует": func(f *fixture) []string {
			p := f.writeIncoming("x.deb", f.release("1.0.0", body))
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
				if e.IsDir() {
					if sub, _ := os.ReadDir(filepath.Join(f.pkgs, e.Name())); len(sub) != 0 {
						t.Fatalf("в кэше остались файлы %v", sub)
					}
				}
			}
		})
	}
}

func TestStageArchFailure(t *testing.T) {
	f := newFixture(t)
	p := f.writeIncoming("x.deb", f.release("1.0.0", []byte("x")))
	f.runErr = errors.New("no dpkg")
	if c := f.main("stage", p, "1.0.0"); c != 1 {
		t.Fatalf("code %d", c)
	}
}

func TestStageDebRenameFailureCleansMetadata(t *testing.T) {
	f := newFixture(t)
	p := f.writeIncoming("x.deb", f.release("1.0.0", []byte("x")))
	// на месте итогового deb лежит непустой каталог: rename не пройдёт, метаданные не остаются
	must(t, os.MkdirAll(filepath.Join(f.debFile("1.0.0"), "keep"), 0o755))
	if c := f.main("stage", p, "1.0.0"); c == 0 {
		t.Fatal("ожидалась ошибка")
	}
	if _, err := os.Stat(f.debFile("1.0.0") + ".new"); err == nil {
		t.Fatal(".new не убран")
	}
}

func TestStageVersionDirNotCreatable(t *testing.T) {
	f := newFixture(t)
	p := f.writeIncoming("x.deb", f.release("1.0.0", []byte("x")))
	must(t, os.WriteFile(f.verDir("1.0.0"), nil, 0o644)) // на месте каталога — файл
	if c := f.main("stage", p, "1.0.0"); c == 0 {
		t.Fatal("ожидалась ошибка")
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
	if h.PackagesDir != "/var/cache/tgproxy/packages" || h.IncomingDir != "/var/lib/tgproxy-incoming" {
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

func TestEmbeddedVerifier(t *testing.T) {
	// Боевой Verifier строится из вшитых ключей: чужая подпись отвергается.
	v := embeddedVerifier()
	if _, ok := v.(verify.Verifier); !ok {
		t.Fatalf("%T", v)
	}
	if err := v.Verify([]byte("x"), []byte("junk")); err == nil {
		t.Fatal("мусорная подпись принята")
	}
	fv := failVerifier{errors.New("bad keys")}
	if fv.Verify(nil, nil) == nil || fv.CheckFile(nil, "", nil) == nil || fv.CheckVersion("1.0.0") == nil {
		t.Fatal("failVerifier должен отказывать всегда")
	}
}
