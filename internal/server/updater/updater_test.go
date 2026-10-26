package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

func TestStageHappyPath(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), func(c *Config) { c.MinVersion = "1.0.0" })
	rel, err := e.u.Check(context.Background())
	if err != nil || rel.Version != "1.1.0" {
		t.Fatalf("Check: %v %+v", err, rel)
	}
	if st := e.u.Status(); st.Available != "1.1.0" || st.Notes != "notes" || st.CheckedAt.IsZero() || st.LastError != "" {
		t.Fatalf("status = %+v", st)
	}
	if err := e.u.Stage(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	art := e.src.files
	deb := DebName("1.1.0", "amd64")
	dl := filepath.Join(e.packages, "1.1.0")
	if got := readFile(t, filepath.Join(dl, deb)); !bytes.Equal(got, art[deb]) {
		t.Error("deb в кэше загрузок не совпал")
	}
	if !bytes.Equal(readFile(t, filepath.Join(dl, ChecksumsName)), art[ChecksumsName]) || !bytes.Equal(readFile(t, filepath.Join(dl, SigName)), art[SigName]) {
		t.Error("checksums/подпись в кэше загрузок")
	}
	staged := filepath.Join(e.updates, "staged")
	for _, n := range []string{deb, ChecksumsName, SigName, RequestName} {
		if !exists(filepath.Join(staged, n)) {
			t.Errorf("в staged нет %s", n)
		}
	}
	// request читает `tgproxy update apply`: строго {"version","component"}.
	if raw := string(readFile(t, filepath.Join(staged, RequestName))); raw != `{"version":"1.1.0","component":"server"}` {
		t.Errorf("request = %s", raw)
	}
	if got := e.u.Status().Staged; got != "1.1.0" {
		t.Errorf("Staged = %q", got)
	}
	// Повторное «Установить» не создаёт второй request.
	if err := e.u.Stage(context.Background(), "1.1.0"); !errors.Is(err, ErrPending) {
		t.Fatalf("второй Stage: %v", err)
	}
	if l := leftovers(t, e.updates); len(l) != 1 || l[0] != "staged" {
		t.Errorf("updates = %v", l)
	}
	if l := leftovers(t, e.packages); len(l) != 1 || l[0] != "1.1.0" {
		t.Errorf("downloads = %v", l)
	}
}

func TestStageSecondaryKeyAccepted(t *testing.T) {
	e := newEnv(t, signedBy(secondary, "1.1.0", t), nil)
	if err := e.u.Stage(context.Background(), "1.1.0"); err != nil {
		t.Fatalf("подпись ротационным ключом: %v", err)
	}
}

func TestStageForeignKeyRejected(t *testing.T) {
	e := newEnv(t, func(_, _ keys) artifacts { return makeArtifacts(t, newKeys(t), "1.1.0") }, nil)
	err := e.u.Stage(context.Background(), "1.1.0")
	if !errors.Is(err, verify.ErrBadSignature) {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, e)
	if e.u.Status().LastError == "" {
		t.Error("LastError не выставлен")
	}
	for _, n := range e.src.fetched {
		if strings.HasSuffix(n, ".deb") {
			t.Error("deb скачан до проверки подписи")
		}
	}
}

func TestStageTamperedDebRejected(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	deb := DebName("1.1.0", "amd64")
	tampered := append([]byte(nil), e.src.files[deb]...)
	tampered[100] ^= 1
	e.src.files[deb] = tampered
	err := e.u.Stage(context.Background(), "1.1.0")
	if !errors.Is(err, verify.ErrChecksum) {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, e)
}

func TestStageTamperedChecksumsRejected(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	e.src.files[ChecksumsName] = bytes.Replace(e.src.files[ChecksumsName], []byte("0"), []byte("1"), 1)
	if err := e.u.Stage(context.Background(), "1.1.0"); !errors.Is(err, verify.ErrBadSignature) {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, e)
}

func TestStageDowngradeBelowMin(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), func(c *Config) { c.MinVersion = "1.2.0"; c.Current = "1.0.0" })
	err := e.u.Stage(context.Background(), "1.1.0")
	if !errors.Is(err, verify.ErrDowngrade) {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, e)
	if len(e.src.fetched) != 0 {
		t.Errorf("скачивание не должно начинаться: %v", e.src.fetched)
	}
}

func TestStageNotNewer(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.0.0", t), nil)
	if err := e.u.Stage(context.Background(), "1.0.0"); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, e)
}

func TestStagePartialDownloadNotStaged(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	deb := DebName("1.1.0", "amd64")
	e.src.fetchFn = func(name string) (io.ReadCloser, error) {
		if name == deb {
			return truncRC{bytes.NewReader(e.src.files[deb][:len(e.src.files[deb])/2])}, nil
		}
		return nil, nil
	}
	err := e.u.Stage(context.Background(), "1.1.0")
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	assertNothingWritten(t, e)

	// Обрыв «чистым» EOF (короче, чем нужно) — тоже не проходит: сумма не совпадёт.
	e.src.fetchFn = func(name string) (io.ReadCloser, error) {
		if name == deb {
			return io.NopCloser(bytes.NewReader(e.src.files[deb][:10])), nil
		}
		return nil, nil
	}
	if err := e.u.Stage(context.Background(), "1.1.0"); !errors.Is(err, verify.ErrChecksum) {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, e)

	// Повтор после сбоя работает.
	e.src.fetchFn = nil
	if err := e.u.Stage(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
}

func TestStageCtxCancelMidDownload(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	ctx, cancel := context.WithCancel(context.Background())
	deb := DebName("1.1.0", "amd64")
	e.src.fetchFn = func(name string) (io.ReadCloser, error) {
		if name == deb {
			cancel()
			return nil, ctx.Err()
		}
		return nil, nil
	}
	if err := e.u.Stage(ctx, "1.1.0"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	assertNothingWritten(t, e)
}

func assertNothingWritten(t *testing.T, e *env) {
	t.Helper()
	if l := leftovers(t, e.packages); len(l) != 0 {
		t.Errorf("в кэше остались файлы: %v", l)
	}
	if l := leftovers(t, e.updates); len(l) != 0 {
		t.Errorf("в updates остались файлы: %v", l)
	}
	if exists(filepath.Join(e.updates, "staged")) {
		t.Error("staged создан")
	}
}

func TestStageVersionUnavailableAndMissingAssets(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	if err := e.u.Stage(context.Background(), "1.5.0"); !errors.Is(err, ErrVersionUnavailable) {
		t.Fatalf("err = %v", err)
	}
	e.src.relErr = errors.New("net down")
	if err := e.u.Stage(context.Background(), "1.1.0"); err == nil {
		t.Fatal("ожидалась ошибка источника")
	}
	e.src.relErr = nil
	for _, miss := range []string{ChecksumsName, SigName, DebName("1.1.0", "amd64")} {
		src := newMemSource(makeArtifacts(t, e.primary, "1.1.0"))
		var as []Asset
		for _, a := range src.rel.Assets {
			if a.Name != miss {
				as = append(as, a)
			}
		}
		src.rel.Assets = as
		e2 := newEnv(t, signedBy(primary, "1.1.0", t), nil)
		e2.u.SetSource(src, "github")
		e2.u.cfg.PubKeys = []verify.PublicKey{e.primary.pub}
		err := e2.u.Stage(context.Background(), "1.1.0")
		if err == nil {
			t.Errorf("%s: ожидалась ошибка", miss)
		}
	}
	// Нет строки deb в checksums.
	a := makeArtifacts(t, e.primary, "1.1.0")
	a.sums = []byte(strings.Repeat("0", 64) + "  other.deb\n")
	a.sig = e.primary.sign(a.sums)
	e3 := newEnv(t, func(_, _ keys) artifacts { return a }, func(c *Config) { c.PubKeys = []verify.PublicKey{e.primary.pub} })
	if err := e3.u.Stage(context.Background(), "1.1.0"); !errors.Is(err, verify.ErrNotListed) {
		t.Fatalf("err = %v", err)
	}
}

func TestStageReusesCacheButReverifies(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	deb := DebName("1.1.0", "amd64")
	if err := e.u.Stage(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	// Освобождаем очередь (как будто apply отработал).
	if err := os.RemoveAll(filepath.Join(e.updates, "staged")); err != nil {
		t.Fatal(err)
	}
	e.src.fetched = nil
	if err := e.u.Stage(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	for _, n := range e.src.fetched {
		if n == deb {
			t.Error("deb из кэша должен переиспользоваться")
		}
	}
	// Порча файла в кэше → перекачка.
	if err := os.RemoveAll(filepath.Join(e.updates, "staged")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.packages, "1.1.0", deb), []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.src.fetched = nil
	if err := e.u.Stage(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(e.packages, "1.1.0", deb)); !bytes.Equal(got, e.src.files[deb]) {
		t.Error("испорченный кэш не заменён")
	}
}

func TestStageOversize(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	deb := DebName("1.1.0", "amd64")
	for i := range e.src.rel.Assets {
		if e.src.rel.Assets[i].Name == deb {
			e.src.rel.Assets[i].Size = maxDebSize + 1
		}
	}
	if err := e.u.Stage(context.Background(), "1.1.0"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, e)

	// Метаданные больше лимита.
	e2 := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	e2.src.files[ChecksumsName] = bytes.Repeat([]byte("x"), maxMetaSize+10)
	if err := e2.u.Stage(context.Background(), "1.1.0"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestLimitedReader(t *testing.T) {
	l := &limitedReader{r: strings.NewReader("0123456789"), left: 4}
	b, err := io.ReadAll(l)
	if !errors.Is(err, ErrTooLarge) || string(b) != "0123" || !l.exceeded {
		t.Fatalf("b=%q err=%v", b, err)
	}
	l = &limitedReader{r: strings.NewReader("0123"), left: 4}
	if b, err = io.ReadAll(l); err != nil || string(b) != "0123" || l.exceeded {
		t.Fatalf("b=%q err=%v", b, err)
	}
}

func TestCheckErrorsAndStates(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), func(c *Config) { c.Current = "dev" })
	e.src.relErr = errors.New("boom")
	if _, err := e.u.Check(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if e.u.Status().LastError != "boom" {
		t.Errorf("status = %+v", e.u.Status())
	}
	e.src.relErr = nil
	e.src.rel.Version = "garbage"
	if _, err := e.u.Check(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка версии")
	}
	e.src.rel.Version = "1.1.0"
	if _, err := e.u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.u.Status().Available != "1.1.0" {
		t.Error("dev считается старше любой версии")
	}
	e.src.rel.Version = "0.9.0"
	e.u.cfg.Current = "1.0.0"
	if _, err := e.u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := e.u.Status(); st.Available != "" || st.LastError != "" {
		t.Errorf("status = %+v", st)
	}
}

func TestBusy(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	e.u.opMu.Lock()
	defer e.u.opMu.Unlock()
	if _, err := e.u.Check(context.Background()); !errors.Is(err, ErrBusy) {
		t.Errorf("Check: %v", err)
	}
	if err := e.u.Stage(context.Background(), "1.1.0"); !errors.Is(err, ErrBusy) {
		t.Errorf("Stage: %v", err)
	}
}

func TestSetSource(t *testing.T) {
	e := newEnv(t, signedBy(primary, "1.1.0", t), nil)
	if _, err := e.u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.u.SetSource(newMemSource(makeArtifacts(t, e.primary, "1.2.0")), "proxy")
	if st := e.u.Status(); st.Source != "proxy" || st.Available != "" {
		t.Errorf("status = %+v", st)
	}
	if err := e.u.Stage(context.Background(), "1.2.0"); err != nil {
		t.Fatal(err)
	}
	var req Request
	_ = json.Unmarshal(readFile(t, filepath.Join(e.updates, "staged", RequestName)), &req)
	if req.Version != "1.2.0" || req.Component != "server" {
		t.Errorf("request = %+v", req)
	}
}

func TestNewValidation(t *testing.T) {
	base := Config{Source: &memSource{}, DownloadsDir: "a", StagingDir: "b", Arch: "amd64", PubKeys: []verify.PublicKey{newKeys(t).pub}}
	cases := map[string]func(*Config){
		"нет источника": func(c *Config) { c.Source = nil },

		"нет staging": func(c *Config) { c.StagingDir = "" },
		"нет arch":    func(c *Config) { c.Arch = "" },
		"нет ключей":  func(c *Config) { c.PubKeys = nil },
		"плохой min":  func(c *Config) { c.MinVersion = "x" },
	}
	for n, mod := range cases {
		c := base
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: ожидалась ошибка", n)
		}
	}
	c := base
	c.Now = func() time.Time { return time.Unix(1, 0) }
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
}

func TestNewCleansLeftovers(t *testing.T) {
	root := t.TempDir()
	pk, up := filepath.Join(root, "u", "downloads"), filepath.Join(root, "u")
	_ = os.MkdirAll(pk, 0o750)
	_ = os.MkdirAll(filepath.Join(up, ".staging-123"), 0o750)
	_ = os.WriteFile(filepath.Join(pk, ".dl-123"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(pk, "keep.txt"), []byte("x"), 0o600)
	_, err := New(Config{Source: &memSource{}, DownloadsDir: pk, StagingDir: up, Arch: "amd64", PubKeys: []verify.PublicKey{newKeys(t).pub}})
	if err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(pk, ".dl-123")) || exists(filepath.Join(up, ".staging-123")) || !exists(filepath.Join(pk, "keep.txt")) {
		t.Error("остатки не почищены корректно")
	}
}
