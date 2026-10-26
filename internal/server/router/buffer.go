package router

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

// Ошибки буфера.
var (
	// ErrNotReplayable — повторное чтение невоспроизводимого тела.
	ErrNotReplayable = errors.New("router: body is not replayable")
	// ErrBufferClosed — обращение к закрытому буферу.
	ErrBufferClosed = errors.New("router: buffer closed")
)

const (
	tmpPrefix = "tgp-"
	tmpSuffix = ".buf"
	tmpDirSub = "tgproxy"
)

// Gauge — счётчик буферизованных байт (метрика inflight_buffered_bytes, M3).
type Gauge interface{ Add(float64) }

// Replayable — тело запроса, которое можно отправить несколько раз.
type Replayable interface {
	// NewReader возвращает независимый читатель с начала тела. Для
	// невоспроизводимого тела — единственный раз.
	NewReader() (io.ReadCloser, error)
	// Size — длина тела в байтах; -1, если неизвестна.
	Size() int64
	// Replayable — можно ли читать тело повторно.
	Replayable() bool
	// BytesConsumed — сколько байт суммарно отдано читателям.
	BytesConsumed() int64
	// Close освобождает ресурсы (удаляет tmp-файл). Идемпотентен.
	Close() error
}

// Option настраивает Wrap.
type Option func(*options)

type options struct{ gauge Gauge }

// WithGauge подключает счётчик буферизованных байт.
func WithGauge(g Gauge) Option { return func(o *options) { o.gauge = g } }

// Wrap буферизует тело req: ≤RAMMax — в памяти, ≤DiskMax — в зашифрованном
// tmp-файле, больше (или неизвестная длина сверх лимита) — потоковое
// невоспроизводимое тело. Исходный req.Body закрывается буфером.
func Wrap(req *http.Request, cfg config.BufferConfig, opts ...Option) (Replayable, error) {
	var o options
	for _, f := range opts {
		f(&o)
	}
	body := req.Body
	if body == nil || body == http.NoBody {
		return newRAMBuffer(nil, o.gauge), nil
	}
	cl := req.ContentLength
	if cl > cfg.DiskMax {
		return newStream(body, cl, nil, o.gauge), nil
	}
	head, err := io.ReadAll(io.LimitReader(body, cfg.RAMMax+1))
	if err != nil {
		_ = body.Close()
		return nil, fmt.Errorf("router: read body: %w", err)
	}
	if int64(len(head)) <= cfg.RAMMax {
		_ = body.Close()
		return newRAMBuffer(head, o.gauge), nil
	}
	return spill(body, head, cl, cfg, o.gauge)
}

// spill переливает прочитанное и остаток тела на диск до DiskMax.
func spill(body io.ReadCloser, head []byte, cl int64, cfg config.BufferConfig, g Gauge) (Replayable, error) {
	d, err := newDiskBuffer(cfg.TmpDir, g)
	if err != nil {
		_ = body.Close()
		return nil, err
	}
	w := newEncWriter(d.f, d.c)
	_, err = w.Write(head)
	if err == nil {
		_, err = io.Copy(w, io.LimitReader(body, cfg.DiskMax-int64(len(head))+1))
	}
	if err == nil {
		err = w.finish()
	}
	if err != nil {
		_ = body.Close()
		_ = d.Close()
		return nil, fmt.Errorf("router: spool body: %w", err)
	}
	d.setSize(w.total)
	if w.total <= cfg.DiskMax {
		_ = body.Close()
		return d, nil
	}
	// Тело длиннее DiskMax: уже прочитанное отдаём с диска, остаток — из body.
	r, err := d.NewReader()
	if err != nil {
		_ = body.Close()
		_ = d.Close()
		return nil, err
	}
	s := newStream(&multiCloser{Reader: io.MultiReader(r, body), closers: []io.Closer{r, body}}, cl, d, nil)
	return s, nil
}

// CleanupTmpDir удаляет остатки буферов прошлого процесса (вызывать на старте).
func CleanupTmpDir(dir string) error {
	dir = tmpDir(dir)
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("router: cleanup tmp: %w", err)
	}
	var first error
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, tmpPrefix) || !strings.HasSuffix(n, tmpSuffix) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, n)); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func tmpDir(dir string) string {
	if dir == "" {
		return filepath.Join(os.TempDir(), tmpDirSub)
	}
	return dir
}

// tracker — общая часть: учёт отданных байт и gauge.
type tracker struct {
	consumed atomic.Int64
	gauge    Gauge
	held     atomic.Int64
}

func (t *tracker) hold(n int64) {
	t.held.Store(n)
	if t.gauge != nil && n != 0 {
		t.gauge.Add(float64(n))
	}
}

func (t *tracker) release() {
	if n := t.held.Swap(0); t.gauge != nil && n != 0 {
		t.gauge.Add(-float64(n))
	}
}

type countReader struct {
	io.Reader
	c *atomic.Int64
}

func (r countReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.c.Add(int64(n))
	return n, err
}

type readCloser struct {
	io.Reader
	close func() error
}

func (r readCloser) Close() error {
	if r.close == nil {
		return nil
	}
	return r.close()
}

type multiCloser struct {
	io.Reader
	closers []io.Closer
}

func (m *multiCloser) Close() error {
	var first error
	for _, c := range m.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// --- RAM ---

type ramBuffer struct {
	tracker
	data   []byte
	closed atomic.Bool
}

func newRAMBuffer(data []byte, g Gauge) *ramBuffer {
	b := &ramBuffer{data: data}
	b.gauge = g
	b.hold(int64(len(data)))
	return b
}

func (b *ramBuffer) NewReader() (io.ReadCloser, error) {
	if b.closed.Load() {
		return nil, ErrBufferClosed
	}
	return readCloser{Reader: countReader{bytes.NewReader(b.data), &b.consumed}}, nil
}
func (b *ramBuffer) Size() int64          { return int64(len(b.data)) }
func (b *ramBuffer) Replayable() bool     { return true }
func (b *ramBuffer) BytesConsumed() int64 { return b.consumed.Load() }
func (b *ramBuffer) Close() error {
	b.closed.Store(true)
	b.release()
	return nil
}

// --- disk ---

type diskBuffer struct {
	tracker
	f      *os.File
	c      *chunkCipher
	size   int64
	mu     sync.Mutex
	closed bool
}

func newDiskBuffer(dir string, g Gauge) (*diskBuffer, error) {
	dir = tmpDir(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("router: tmp dir: %w", err)
	}
	c, err := newChunkCipher()
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, tmpPrefix+"*"+tmpSuffix) // 0600
	if err != nil {
		return nil, fmt.Errorf("router: tmp file: %w", err)
	}
	d := &diskBuffer{f: f, c: c}
	d.gauge = g
	return d, nil
}

func (d *diskBuffer) setSize(n int64) {
	d.size = n
	d.hold(n)
}

func (d *diskBuffer) NewReader() (io.ReadCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, ErrBufferClosed
	}
	r := newEncReader(d.f, d.c, d.size)
	return readCloser{Reader: countReader{r, &d.consumed}}, nil
}
func (d *diskBuffer) Size() int64          { return d.size }
func (d *diskBuffer) Replayable() bool     { return true }
func (d *diskBuffer) BytesConsumed() int64 { return d.consumed.Load() }
func (d *diskBuffer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	d.release()
	cerr := d.f.Close()
	if err := os.Remove(d.f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return cerr
}

// --- non-replayable ---

// stream — потоковое тело без повтора. spool (если есть) — диск с уже
// прочитанным началом; он удаляется в Close.
type stream struct {
	tracker
	src   io.ReadCloser
	size  int64
	spool *diskBuffer
	used  atomic.Bool
}

func newStream(src io.ReadCloser, size int64, spool *diskBuffer, g Gauge) *stream {
	s := &stream{src: src, size: size, spool: spool}
	s.gauge = g
	return s
}

func (s *stream) NewReader() (io.ReadCloser, error) {
	if !s.used.CompareAndSwap(false, true) {
		return nil, ErrNotReplayable
	}
	// Закрытие читателя не закрывает источник: им владеет stream.
	return readCloser{Reader: countReader{s.src, &s.consumed}}, nil
}
func (s *stream) Size() int64          { return s.size }
func (s *stream) Replayable() bool     { return false }
func (s *stream) BytesConsumed() int64 { return s.consumed.Load() }
func (s *stream) Close() error {
	err := s.src.Close()
	if s.spool != nil {
		if e := s.spool.Close(); err == nil {
			err = e
		}
	}
	return err
}
