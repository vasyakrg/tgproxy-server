package updater

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
	"sync"
	"testing"

	"aead.dev/minisign"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

type keys struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func newKeys(t *testing.T) keys {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys{pub, priv}
}

// sign имитирует `minisign -S` (prehashed ED).
func (k keys) sign(msg []byte) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	_, _ = io.Copy(io.Discard, r)
	return r.SignWithComments(k.priv, "timestamp:1 file:checksums.txt", "t")
}

// artifacts — подписанный релиз: deb + checksums.txt + .minisig.
type artifacts struct {
	version string
	deb     []byte
	sums    []byte
	sig     []byte
}

func makeArtifacts(t *testing.T, signer keys, version string) artifacts {
	t.Helper()
	deb := bytes.Repeat([]byte("deb-"+version+"-"), 5000)
	h := sha256.Sum256(deb)
	sums := fmt.Sprintf("%s  %s\n%s  tgproxy_%s_linux_amd64.tar.gz\n",
		hex.EncodeToString(h[:]), DebName(version, "amd64"), strings.Repeat("0", 64), version)
	return artifacts{version: version, deb: deb, sums: []byte(sums), sig: signer.sign([]byte(sums))}
}

func (a artifacts) files() map[string][]byte {
	return map[string][]byte{
		DebName(a.version, "amd64"): a.deb,
		ChecksumsName:               a.sums,
		SigName:                     a.sig,
	}
}

// memSource — Source из памяти с хуками для ошибок и обрывов.
type memSource struct {
	mu      sync.Mutex
	rel     Release
	relErr  error
	files   map[string][]byte
	fetchFn func(name string) (io.ReadCloser, error) // переопределяет выдачу
	fetched []string
}

func newMemSource(a artifacts) *memSource {
	s := &memSource{files: a.files()}
	s.rel = Release{Version: a.version, Tag: "v" + a.version, Notes: "notes"}
	for n, b := range s.files {
		s.rel.Assets = append(s.rel.Assets, Asset{Name: n, Size: int64(len(b))})
	}
	return s
}

func (s *memSource) Latest(context.Context) (Release, error) { return s.rel, s.relErr }

func (s *memSource) Fetch(_ context.Context, a Asset) (io.ReadCloser, error) {
	s.mu.Lock()
	s.fetched = append(s.fetched, a.Name)
	fn := s.fetchFn
	s.mu.Unlock()
	if fn != nil {
		if rc, err := fn(a.Name); rc != nil || err != nil {
			return rc, err
		}
	}
	b, ok := s.files[a.Name]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// truncRC отдаёт часть данных и затем ошибку (обрыв соединения).
type truncRC struct {
	r io.Reader
}

func (t truncRC) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}
func (truncRC) Close() error { return nil }

type env struct {
	pk        []verify.PublicKey
	packages  string
	updates   string
	u         *Updater
	src       *memSource
	primary   keys
	secondary keys
}

func newEnv(t *testing.T, art func(primary, secondary keys) artifacts, mod func(*Config)) *env {
	t.Helper()
	e := &env{primary: newKeys(t), secondary: newKeys(t)}
	e.pk = []verify.PublicKey{e.primary.pub, e.secondary.pub}
	root := t.TempDir()
	e.packages = filepath.Join(root, "packages")
	e.updates = filepath.Join(root, "updates")
	e.src = newMemSource(art(e.primary, e.secondary))
	cfg := Config{
		Source: e.src, SourceName: "github", DownloadsDir: e.packages, StagingDir: e.updates,
		Arch: "amd64", PubKeys: e.pk, Current: "1.0.0",
	}
	if mod != nil {
		mod(&cfg)
	}
	u, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.u = u
	return e
}

func signedBy(which func(p, s keys) keys, version string, t *testing.T) func(p, s keys) artifacts {
	return func(p, s keys) artifacts { return makeArtifacts(t, which(p, s), version) }
}

func primary(p, _ keys) keys   { return p }
func secondary(_, s keys) keys { return s }

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// leftovers перечисляет файлы в каталоге (для проверки «ничего не осталось»).
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}
