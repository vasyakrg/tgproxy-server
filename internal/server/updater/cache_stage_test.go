package updater

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCache(t *testing.T) {
	c := Cache{Dir: filepath.Join(t.TempDir(), "dl"), Arch: "amd64"}
	if c.Has("1.0.0") {
		t.Fatal("пустой кэш")
	}
	tmp, err := c.CreateTemp()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tmp.WriteString("deb")
	_ = tmp.Close()
	if err := c.Commit(tmp.Name(), "1.0.0", []byte("sums"), []byte("sig")); err != nil {
		t.Fatal(err)
	}
	if !c.Has("1.0.0") {
		t.Fatal("релиз должен быть в кэше")
	}
	want := filepath.Join(c.Dir, "1.0.0", "tgproxy_1.0.0_amd64.deb")
	if c.DebPath("1.0.0") != want {
		t.Errorf("DebPath = %s", c.DebPath("1.0.0"))
	}
	if string(readFile(t, want)) != "deb" || string(readFile(t, c.ChecksumsPath("1.0.0"))) != "sums" || string(readFile(t, c.SigPath("1.0.0"))) != "sig" {
		t.Error("содержимое релиза в кэше")
	}
	fi, _ := os.Stat(c.DebPath("1.0.0"))
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("perm = %v", fi.Mode().Perm())
	}
	// Без deb набор неполный.
	_ = os.Remove(c.DebPath("1.0.0"))
	if c.Has("1.0.0") {
		t.Error("без deb Has должен быть false")
	}
	// Commit tmp вне каталога кэша.
	other := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(other, []byte("x"), 0o600)
	if err := c.Commit(other, "4.0.0", nil, nil); err == nil {
		t.Error("tmp вне кэша — ожидалась ошибка")
	}
	// Commit несуществующего tmp.
	if err := c.Commit(filepath.Join(c.Dir, ".dl-none"), "5.0.0", nil, nil); err == nil {
		t.Error("ожидалась ошибка")
	}
	// Каталог версии не создать: на его месте файл.
	_ = os.WriteFile(filepath.Join(c.Dir, "6.0.0"), nil, 0o600)
	tmp2, _ := c.CreateTemp()
	_ = tmp2.Close()
	if err := c.Commit(tmp2.Name(), "6.0.0", nil, nil); err == nil {
		t.Error("ожидалась ошибка mkdir")
	}
	// CreateTemp в недоступном месте.
	bad := Cache{Dir: filepath.Join(other, "sub"), Arch: "amd64"}
	if _, err := bad.CreateTemp(); err == nil {
		t.Error("ожидалась ошибка")
	}
	c.CleanTemp()
	(Cache{Dir: filepath.Join(t.TempDir(), "absent")}).CleanTemp()
}

func TestWriteAtomicFailure(t *testing.T) {
	dir := t.TempDir()
	if err := writeAtomic(filepath.Join(dir, "nodir", "f"), func(io.Writer) error { return nil }); err == nil {
		t.Error("ожидалась ошибка")
	}
	err := writeAtomic(filepath.Join(dir, "f"), func(io.Writer) error { return os.ErrInvalid })
	if err == nil {
		t.Fatal("ожидалась ошибка fill")
	}
	if l := leftovers(t, dir); len(l) != 0 {
		t.Errorf("остался temp: %v", l)
	}
}

func TestStager(t *testing.T) {
	root := t.TempDir()
	deb := filepath.Join(root, "x.deb")
	_ = os.WriteFile(deb, []byte("deb"), 0o600)
	s := Stager{Dir: filepath.Join(root, "updates")}
	files := StageFiles{Req: Request{Version: "1.0.0", Component: "server"}, Deb: deb, DebName: "x.deb", Checksums: []byte("c"), Sig: []byte("s")}

	if p, err := s.Pending(); p != nil || err != nil {
		t.Fatalf("p=%v err=%v", p, err)
	}
	// Мусорный staged без request заменяется.
	_ = os.MkdirAll(s.StagedDir(), 0o750)
	_ = os.WriteFile(filepath.Join(s.StagedDir(), "junk"), []byte("x"), 0o600)
	if err := s.Stage(files); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(s.StagedDir(), "junk")) || !exists(filepath.Join(s.StagedDir(), RequestName)) {
		t.Error("staged не заменён целиком")
	}
	if p, err := s.Pending(); err != nil || p == nil || p.Version != "1.0.0" {
		t.Fatalf("p=%v err=%v", p, err)
	}
	if err := s.Stage(files); err != ErrPending {
		t.Fatalf("err = %v", err)
	}
	// Повреждённый request.
	_ = os.WriteFile(filepath.Join(s.StagedDir(), RequestName), []byte("{"), 0o600)
	if _, err := s.Pending(); err == nil {
		t.Error("ожидалась ошибка JSON")
	}
	if err := s.Stage(files); err == nil {
		t.Error("с повреждённым request Stage не должен перетирать")
	}
}

func TestStagerFailureLeavesNothing(t *testing.T) {
	root := t.TempDir()
	s := Stager{Dir: filepath.Join(root, "updates")}
	err := s.Stage(StageFiles{Req: Request{Version: "1"}, DebName: "x.deb", Deb: filepath.Join(root, "absent.deb")})
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if l := leftovers(t, s.Dir); len(l) != 0 {
		t.Errorf("остатки: %v", l)
	}
	// Updates — это файл, а не каталог.
	f := filepath.Join(root, "file")
	_ = os.WriteFile(f, nil, 0o600)
	if err := (Stager{Dir: f}).Stage(StageFiles{}); err == nil {
		t.Error("ожидалась ошибка")
	}
	// Источник deb без прав на запись назначения: имя с разделителем.
	deb := filepath.Join(root, "d.deb")
	_ = os.WriteFile(deb, []byte("x"), 0o600)
	if err := s.Stage(StageFiles{DebName: "no/such/x.deb", Deb: deb}); err == nil {
		t.Error("ожидалась ошибка")
	}
	s.CleanStaging()
}
