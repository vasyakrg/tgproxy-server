package router

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// chunkSize — размер открытого текста одного блока на диске.
const chunkSize = 64 << 10

// errCorrupt — блок на диске не прошёл проверку подлинности.
var errCorrupt = errors.New("router: buffer chunk authentication failed")

// chunkCipher — AES-256-GCM поблочно. Ключ случайный, живёт только в памяти.
// Nonce = 4 случайных байта (префикс буфера) + 8 байт счётчика блока.
// AAD = признак последнего блока: усечённый файл не пройдёт проверку.
type chunkCipher struct {
	aead   cipher.AEAD
	prefix [4]byte
}

func newChunkCipher() (*chunkCipher, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("router: buffer key: %w", err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("router: buffer cipher: %w", err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, fmt.Errorf("router: buffer gcm: %w", err)
	}
	c := &chunkCipher{aead: aead}
	if _, err := rand.Read(c.prefix[:]); err != nil {
		return nil, fmt.Errorf("router: buffer nonce: %w", err)
	}
	return c, nil
}

func (c *chunkCipher) nonce(idx int64) []byte {
	n := make([]byte, c.aead.NonceSize())
	copy(n, c.prefix[:])
	binary.BigEndian.PutUint64(n[len(c.prefix):], uint64(idx)) // #nosec G115 -- idx >= 0
	return n
}

func finalAAD(final bool) []byte {
	if final {
		return []byte{1}
	}
	return []byte{0}
}

func (c *chunkCipher) seal(dst, plain []byte, idx int64, final bool) []byte {
	return c.aead.Seal(dst, c.nonce(idx), plain, finalAAD(final))
}

func (c *chunkCipher) open(dst, ct []byte, idx int64, final bool) ([]byte, error) {
	out, err := c.aead.Open(dst, c.nonce(idx), ct, finalAAD(final))
	if err != nil {
		return nil, errCorrupt
	}
	return out, nil
}

// encWriter режет поток на блоки по chunkSize и пишет их зашифрованными.
// Последний блок всегда помечается final, поэтому блок пишется только когда
// известно, что за ним есть ещё данные, либо в finish.
type encWriter struct {
	w     io.Writer
	c     *chunkCipher
	buf   []byte
	out   []byte
	idx   int64
	total int64
}

func newEncWriter(w io.Writer, c *chunkCipher) *encWriter {
	return &encWriter{w: w, c: c, buf: make([]byte, 0, chunkSize)}
}

func (e *encWriter) flush(final bool) error {
	e.out = e.c.seal(e.out[:0], e.buf, e.idx, final)
	e.idx++
	e.buf = e.buf[:0]
	_, err := e.w.Write(e.out)
	return err
}

func (e *encWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		if len(e.buf) == chunkSize {
			if err := e.flush(false); err != nil {
				return n, err
			}
		}
		k := min(chunkSize-len(e.buf), len(p))
		e.buf = append(e.buf, p[:k]...)
		p = p[k:]
		n += k
		e.total += int64(k)
	}
	return n, nil
}

// finish пишет последний (final) блок.
func (e *encWriter) finish() error {
	if len(e.buf) == 0 {
		return nil
	}
	return e.flush(true)
}

// encReader читает зашифрованные блоки из ra и отдаёт открытый текст.
// Независим от других читателей: ReadAt не двигает общий offset.
type encReader struct {
	ra     io.ReaderAt
	c      *chunkCipher
	chunks int64 // всего блоков
	idx    int64
	ct     []byte
	plain  []byte
	cur    []byte
	err    error
}

func newEncReader(ra io.ReaderAt, c *chunkCipher, size int64) *encReader {
	return &encReader{
		ra: ra, c: c,
		chunks: (size + chunkSize - 1) / chunkSize,
		ct:     make([]byte, chunkSize+c.aead.Overhead()),
		plain:  make([]byte, 0, chunkSize),
	}
}

func (r *encReader) Read(p []byte) (int, error) {
	for len(r.cur) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.idx >= r.chunks {
			r.err = io.EOF
			continue
		}
		r.fill()
	}
	n := copy(p, r.cur)
	r.cur = r.cur[n:]
	return n, nil
}

func (r *encReader) fill() {
	stride := int64(chunkSize + r.c.aead.Overhead())
	n, err := r.ra.ReadAt(r.ct, r.idx*stride)
	if n == 0 || (err != nil && !errors.Is(err, io.EOF)) {
		if err == nil || errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		r.err = err
		return
	}
	final := r.idx == r.chunks-1
	plain, err := r.c.open(r.plain[:0], r.ct[:n], r.idx, final)
	if err != nil {
		r.err = err
		return
	}
	r.idx++
	r.cur = plain
}
