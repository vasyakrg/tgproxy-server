package router_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/router"
)

type gauge struct {
	mu  sync.Mutex
	v   float64
	max float64
}

func (g *gauge) Add(d float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.v += d
	g.max = max(g.max, g.v)
}

func (g *gauge) val() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.v
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i*7%23)
	}
	return b
}

func bufReq(body io.ReadCloser, cl int64) *http.Request {
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://x/", nil)
	r.Body = body
	r.ContentLength = cl
	return r
}

func cfgBuf(t *testing.T, ram, disk int64) config.BufferConfig {
	t.Helper()
	return config.BufferConfig{RAMMax: ram, DiskMax: disk, BodyMax: 1 << 30, TmpDir: filepath.Join(t.TempDir(), "tmp")}
}

func tmpFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func readAll(t *testing.T, b router.Replayable) []byte {
	t.Helper()
	r, err := b.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRAMThreeReads(t *testing.T) {
	cfg := cfgBuf(t, 1024, 1<<20)
	data := payload(500)
	g := &gauge{}
	b, err := router.Wrap(bufReq(io.NopCloser(bytes.NewReader(data)), 500), cfg, router.WithGauge(g))
	if err != nil {
		t.Fatal(err)
	}
	if !b.Replayable() || b.Size() != 500 || g.val() != 500 {
		t.Fatalf("replayable=%v size=%d gauge=%v", b.Replayable(), b.Size(), g.val())
	}
	for range 3 {
		if got := readAll(t, b); !bytes.Equal(got, data) {
			t.Fatal("mismatch")
		}
	}
	if b.BytesConsumed() != 1500 {
		t.Fatalf("consumed %d", b.BytesConsumed())
	}
	if len(tmpFiles(t, cfg.TmpDir)) != 0 {
		t.Fatal("RAM buffer must not touch disk")
	}
	_ = b.Close()
	if g.val() != 0 {
		t.Fatalf("gauge after close %v", g.val())
	}
	if _, err := b.NewReader(); !errors.Is(err, router.ErrBufferClosed) {
		t.Fatalf("err %v", err)
	}
}

func TestDiskThreeReadsAndBoundaries(t *testing.T) {
	const chunk = 64 << 10
	for _, n := range []int{1025, chunk - 1, chunk, chunk + 1, 2 * chunk, 2*chunk + 5, 300000} {
		cfg := cfgBuf(t, 1024, 1<<20)
		data := payload(n)
		g := &gauge{}
		b, err := router.Wrap(bufReq(io.NopCloser(bytes.NewReader(data)), int64(n)), cfg, router.WithGauge(g))
		if err != nil {
			t.Fatal(err)
		}
		if !b.Replayable() || b.Size() != int64(n) || g.val() != float64(n) {
			t.Fatalf("n=%d replayable=%v size=%d gauge=%v", n, b.Replayable(), b.Size(), g.val())
		}
		if len(tmpFiles(t, cfg.TmpDir)) != 1 {
			t.Fatalf("n=%d want 1 tmp file", n)
		}
		for range 3 {
			if !bytes.Equal(readAll(t, b), data) {
				t.Fatalf("n=%d mismatch", n)
			}
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		if err := b.Close(); err != nil {
			t.Fatal("Close must be idempotent")
		}
		if len(tmpFiles(t, cfg.TmpDir)) != 0 || g.val() != 0 {
			t.Fatalf("n=%d leftover files=%v gauge=%v", n, tmpFiles(t, cfg.TmpDir), g.val())
		}
	}
}

func TestDiskConcurrentReaders(t *testing.T) {
	cfg := cfgBuf(t, 16, 1<<20)
	data := payload(200000)
	b, err := router.Wrap(bufReq(io.NopCloser(bytes.NewReader(data)), int64(len(data))), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !bytes.Equal(readAll(t, b), data) {
				t.Error("mismatch")
			}
		}()
	}
	wg.Wait()
}

func TestDiskNoPlaintextAndPerms(t *testing.T) {
	cfg := cfgBuf(t, 16, 1<<20)
	marker := []byte("SECRET-MARKER-0123456789-SECRET-MARKER")
	data := bytes.Repeat(marker, 5000) // ~190 КиБ
	b, err := router.Wrap(bufReq(io.NopCloser(bytes.NewReader(data)), int64(len(data))), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	files := tmpFiles(t, cfg.TmpDir)
	if len(files) != 1 {
		t.Fatal("want 1 tmp file")
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("SECRET-MARKER")) || bytes.Contains(raw, marker[:8]) {
		t.Fatal("plaintext found on disk")
	}
	if len(raw) <= len(data) {
		t.Fatal("ciphertext must carry GCM tags")
	}
	st, _ := os.Stat(files[0])
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", st.Mode())
	}
	dst, _ := os.Stat(cfg.TmpDir)
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", dst.Mode())
	}
}

func TestDiskTamperDetected(t *testing.T) {
	for name, mutate := range map[string]func(string){
		"flip": func(p string) {
			raw, _ := os.ReadFile(p)
			raw[100] ^= 0xff
			_ = os.WriteFile(p, raw, 0o600)
		},
		"truncate": func(p string) {
			raw, _ := os.ReadFile(p)
			_ = os.WriteFile(p, raw[:65536+16], 0o600) // ровно первый блок
		},
		"empty": func(p string) { _ = os.Truncate(p, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := cfgBuf(t, 16, 1<<20)
			data := payload(150000)
			b, err := router.Wrap(bufReq(io.NopCloser(bytes.NewReader(data)), int64(len(data))), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = b.Close() }()
			mutate(tmpFiles(t, cfg.TmpDir)[0])
			r, _ := b.NewReader()
			if _, err := io.ReadAll(r); err == nil {
				t.Fatal("tampering not detected")
			}
		})
	}
}

func TestCloseOnPanic(t *testing.T) {
	cfg := cfgBuf(t, 16, 1<<20)
	func() {
		defer func() { _ = recover() }()
		b, err := router.Wrap(bufReq(io.NopCloser(bytes.NewReader(payload(5000))), 5000), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = b.Close() }()
		if len(tmpFiles(t, cfg.TmpDir)) != 1 {
			t.Fatal("no tmp file")
		}
		panic("handler boom")
	}()
	if len(tmpFiles(t, cfg.TmpDir)) != 0 {
		t.Fatal("tmp file survived panic")
	}
}

func TestOverDiskMaxNotReplayable(t *testing.T) {
	cfg := cfgBuf(t, 16, 100)
	data := payload(5000)
	src := &closeTracker{Reader: bytes.NewReader(data)}
	g := &gauge{}
	b, err := router.Wrap(bufReq(src, 5000), cfg, router.WithGauge(g))
	if err != nil {
		t.Fatal(err)
	}
	if b.Replayable() || b.BytesConsumed() != 0 || b.Size() != 5000 || g.val() != 0 {
		t.Fatalf("replayable=%v consumed=%d", b.Replayable(), b.BytesConsumed())
	}
	if len(tmpFiles(t, cfg.TmpDir)) != 0 {
		t.Fatal("known-oversize body must not touch disk")
	}
	r, err := b.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	_ = r.Close()
	if !bytes.Equal(got, data) || b.BytesConsumed() != 5000 {
		t.Fatalf("consumed %d", b.BytesConsumed())
	}
	if src.closed {
		t.Fatal("reader Close must not close the source")
	}
	if _, err := b.NewReader(); !errors.Is(err, router.ErrNotReplayable) {
		t.Fatalf("second reader: %v", err)
	}
	_ = b.Close()
	if !src.closed {
		t.Fatal("Close must close the source")
	}
}

func TestChunkedBoundaries(t *testing.T) {
	const ram, disk = 1000, 200000
	cases := []struct {
		n          int
		replayable bool
		onDisk     bool
	}{
		{0, true, false},
		{ram - 1, true, false},
		{ram, true, false},
		{ram + 1, true, true},
		{disk, true, true},
		{disk + 1, false, true},
		{disk + 70000, false, true},
	}
	for _, c := range cases {
		cfg := cfgBuf(t, ram, disk)
		data := payload(c.n)
		src := &closeTracker{Reader: bytes.NewReader(data)}
		g := &gauge{}
		b, err := router.Wrap(bufReq(src, -1), cfg, router.WithGauge(g))
		if err != nil {
			t.Fatal(err)
		}
		if b.Replayable() != c.replayable {
			t.Fatalf("n=%d replayable=%v", c.n, b.Replayable())
		}
		if (len(tmpFiles(t, cfg.TmpDir)) == 1) != c.onDisk {
			t.Fatalf("n=%d onDisk mismatch", c.n)
		}
		if b.BytesConsumed() != 0 {
			t.Fatalf("n=%d consumed before read: %d", c.n, b.BytesConsumed())
		}
		reads := 1
		if c.replayable {
			reads = 3
		}
		for range reads {
			if !bytes.Equal(readAll(t, b), data) {
				t.Fatalf("n=%d mismatch", c.n)
			}
		}
		if c.n > 0 && g.max == 0 {
			t.Fatalf("n=%d gauge never grew", c.n)
		}
		_ = b.Close()
		if !src.closed || g.val() != 0 || len(tmpFiles(t, cfg.TmpDir)) != 0 {
			t.Fatalf("n=%d closed=%v gauge=%v files=%v", c.n, src.closed, g.val(), tmpFiles(t, cfg.TmpDir))
		}
	}
}

func TestEmptyBodies(t *testing.T) {
	cfg := cfgBuf(t, 16, 100)
	for _, body := range []io.ReadCloser{nil, http.NoBody} {
		b, err := router.Wrap(bufReq(body, 0), cfg)
		if err != nil || !b.Replayable() || b.Size() != 0 || len(readAll(t, b)) != 0 {
			t.Fatalf("%v %v", b, err)
		}
	}
}

func TestWrapErrors(t *testing.T) {
	cfg := cfgBuf(t, 16, 1000)
	src := &closeTracker{Reader: errReader{}}
	if _, err := router.Wrap(bufReq(src, -1), cfg); err == nil || !src.closed {
		t.Fatalf("read error not reported (closed=%v)", src.closed)
	}
	// ошибка источника посреди переливки на диск
	src = &closeTracker{Reader: io.MultiReader(bytes.NewReader(payload(100)), errReader{})}
	cfg2 := cfgBuf(t, 16, 1000)
	if _, err := router.Wrap(bufReq(src, -1), cfg2); err == nil || !src.closed {
		t.Fatal("spool error not reported")
	}
	if len(tmpFiles(t, cfg2.TmpDir)) != 0 {
		t.Fatal("tmp file leaked after spool error")
	}
	// TmpDir — обычный файл: каталог не создать
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg3 := config.BufferConfig{RAMMax: 16, DiskMax: 1000, TmpDir: filepath.Join(blocker, "sub")}
	src = &closeTracker{Reader: bytes.NewReader(payload(100))}
	if _, err := router.Wrap(bufReq(src, 100), cfg3); err == nil || !src.closed {
		t.Fatal("tmp dir error not reported")
	}
}

func TestDefaultTmpDir(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	cfg := config.BufferConfig{RAMMax: 16, DiskMax: 1000}
	b, err := router.Wrap(bufReq(io.NopCloser(bytes.NewReader(payload(100))), 100), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpFiles(t, filepath.Join(root, "tgproxy"))) != 1 {
		t.Fatal("default tmp dir not used")
	}
	_ = b.Close()
	if err := router.CleanupTmpDir(""); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupTmpDir(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"tgp-1.buf", "tgp-2.buf", "keep.txt", "tgp-3.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "tgp-dir.buf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := router.CleanupTmpDir(dir); err != nil {
		t.Fatal(err)
	}
	left := tmpFiles(t, dir)
	if len(left) != 3 {
		t.Fatalf("left %v", left)
	}
	if err := router.CleanupTmpDir(filepath.Join(dir, "nope")); err != nil {
		t.Fatal(err)
	}
	// не каталог -> ошибка
	if err := router.CleanupTmpDir(filepath.Join(dir, "keep.txt")); err == nil {
		t.Fatal("want error for non-directory")
	}
}
