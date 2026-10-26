package installer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

const (
	adminPassword = "S3cr3t-Adm1n-Pw!"
	keyPassphrase = "pass-PHRASE-42"
)

// ---- фейковый sshd ----

type cmdRec struct {
	User  string
	Line  string
	Stdin string
}

func (c cmdRec) String() string { return "[" + c.User + "] " + c.Line }

type fakeHost struct {
	t        *testing.T
	ln       net.Listener
	cfg      *ssh.ServerConfig
	hostPub  ssh.PublicKey
	mu       sync.Mutex
	cmds     []cmdRec
	files    map[string][]byte
	conns    int
	adminKey ssh.PublicKey
	srvKey   ssh.PublicKey
	deployOK bool
	// failOn: подстрока команды → код выхода 1 и stderr из failErr.
	failOn  map[string]string
	extraFn func(user, line string) (out string, code int, handled bool)
	wrongSH bool
}

func newHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sg
}

func startFakeHost(t *testing.T, hostKey ssh.Signer, adminKey, srvKey ssh.PublicKey) *fakeHost {
	t.Helper()
	h := &fakeHost{t: t, hostPub: hostKey.PublicKey(), files: map[string][]byte{}, adminKey: adminKey, srvKey: srvKey, failOn: map[string]string{}}
	h.cfg = &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "admin" && string(pw) == adminPassword {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			switch {
			case (c.User() == "admin" || c.User() == "root") && h.adminKey != nil && bytes.Equal(key.Marshal(), h.adminKey.Marshal()):
				return nil, nil
			case c.User() == deployUser && h.deployOK && bytes.Equal(key.Marshal(), h.srvKey.Marshal()):
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	h.cfg.AddHostKey(hostKey)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns++
			h.mu.Unlock()
			go h.serve(nc)
		}
	}()
	return h
}

func (h *fakeHost) config() *ssh.ServerConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg
}

func (h *fakeHost) setHostKey(k ssh.Signer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg = cloneWithKey(h.cfg, k)
}

func (h *fakeHost) port() int {
	_, p, _ := net.SplitHostPort(h.ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return n
}

func (h *fakeHost) connCount() int { h.mu.Lock(); defer h.mu.Unlock(); return h.conns }

func (h *fakeHost) serve(nc net.Conn) {
	defer func() { _ = nc.Close() }()
	conn, chans, reqs, err := ssh.NewServerConn(nc, h.config())
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go h.session(conn.User(), ch, creqs)
	}
}

func (h *fakeHost) session(user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var p struct{ Cmd string }
			_ = ssh.Unmarshal(req.Payload, &p)
			_ = req.Reply(true, nil)
			stdin, _ := io.ReadAll(ch)
			out, errOut, code := h.exec(user, p.Cmd, string(stdin))
			_, _ = ch.Write([]byte(out))
			_, _ = ch.Stderr().Write([]byte(errOut))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			return
		case "subsystem":
			var p struct{ Name string }
			_ = ssh.Unmarshal(req.Payload, &p)
			if p.Name != "sftp" {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			srv, err := sftp.NewServer(ch)
			if err == nil {
				_ = srv.Serve()
			}
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (h *fakeHost) exec(user, line, stdin string) (out, errOut string, code int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cmds = append(h.cmds, cmdRec{User: user, Line: line, Stdin: stdin})
	base := line
	for _, p := range []string{"sudo -n ", "sudo -S -p '' "} {
		base = strings.TrimPrefix(base, p)
	}
	for sub, msg := range h.failOn {
		if strings.Contains(base, sub) {
			return "", msg, 1
		}
	}
	if h.extraFn != nil {
		if o, c, ok := h.extraFn(user, base); ok {
			return o, "", c
		}
	}
	f := strings.Fields(base)
	switch {
	case strings.HasPrefix(base, "/usr/bin/dpkg --print-architecture"):
		return "amd64\n", "", 0
	case strings.HasPrefix(base, "/usr/bin/dpkg-query"):
		return "", "dpkg-query: no packages found matching tgproxy", 1
	case strings.HasPrefix(base, "/usr/bin/id -u"):
		return "", "id: no such user", 1
	case strings.HasPrefix(base, "/usr/bin/install -D"):
		src, dst := f[len(f)-2], f[len(f)-1]
		data, err := os.ReadFile(src)
		if err != nil {
			return "", err.Error(), 1
		}
		h.files[dst] = data
		if strings.HasSuffix(dst, "/authorized_keys") {
			h.deployOK = true
		}
		return "", "", 0
	case strings.HasPrefix(base, "/usr/bin/sha256sum "):
		data, ok := h.files[f[1]]
		if !ok {
			data, _ = os.ReadFile(f[1])
		}
		sum := sha256.Sum256(data)
		hs := hex.EncodeToString(sum[:])
		if h.wrongSH {
			hs = strings.Repeat("0", 64)
		}
		return hs + "  " + f[1] + "\n", "", 0
	case strings.HasPrefix(base, "/usr/bin/rm -f "):
		for _, p := range f[2:] {
			delete(h.files, p)
		}
		return "", "", 0
	case strings.HasPrefix(base, "/usr/bin/tgproxy agent csr"):
		return fakeCSR(h.t), "", 0
	case strings.HasPrefix(base, "/usr/bin/tgproxy deploy-helper unit is-active"):
		return "active\n", "", 0
	}
	return "", "", 0
}

func (h *fakeHost) commands() []cmdRec {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]cmdRec(nil), h.cmds...)
}

func fakeCSR(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil-cn"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// ---- прочие фейки ----

type fakeAlerter struct {
	mu    sync.Mutex
	calls [][2]string
}

func (a *fakeAlerter) HostKeyMismatch(_ context.Context, agentID, host string) {
	a.mu.Lock()
	a.calls = append(a.calls, [2]string{agentID, host})
	a.mu.Unlock()
}

func (a *fakeAlerter) got() [][2]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][2]string(nil), a.calls...)
}

type fakeHealth struct {
	mu    sync.Mutex
	calls []string
	err   error
	block bool
}

func (h *fakeHealth) Check(ctx context.Context, url, id string) error {
	h.mu.Lock()
	h.calls = append(h.calls, url+"|"+id)
	err, block := h.err, h.block
	h.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (h *fakeHealth) called() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

// logBuf — slog в буфер для проверки отсутствия секретов.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// ---- окружение ----

type env struct {
	t         *testing.T
	st        *memtest.Store
	host      *fakeHost
	inst      *Installer
	ca        *pki.Authority
	pkgDir    string
	signer    minisign.PrivateKey
	verifier  verify.Verifier
	rtmp      string
	health    *fakeHealth
	alerts    *fakeAlerter
	serverKey ssh.Signer
	adminPEM  []byte
	logs      *logBuf
	hostKey   ssh.Signer
}

type envOpt func(*Config)

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	e := &env{t: t, st: memtest.New(), health: &fakeHealth{}, alerts: &fakeAlerter{}, logs: &logBuf{}}
	e.hostKey = newHostKey(t)
	e.serverKey = newHostKey(t)

	_, adminPriv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(adminPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	e.adminPEM = pem.EncodeToMemory(blk)
	adminSigner, _ := ssh.NewSignerFromKey(adminPriv)

	e.host = startFakeHost(t, e.hostKey, adminSigner.PublicKey(), e.serverKey.PublicKey())

	dir, err := os.MkdirTemp("", "inst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e.pkgDir = filepath.Join(dir, "packages")
	e.rtmp = filepath.Join(dir, "rtmp")
	for _, d := range []string{e.pkgDir, e.rtmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e.signer, e.verifier = priv, verify.Verifier{Keys: []verify.PublicKey{pub}}
	writeRelease(t, e.pkgDir, "1.4.1", priv, map[string]string{"amd64": "deb-body-1.4.1"})
	writeRelease(t, e.pkgDir, "1.3.0", priv, map[string]string{"amd64": "deb-body-1.3.0"})

	kekPath := filepath.Join(dir, "kek")
	if err := pki.GenerateKEK(kekPath); err != nil {
		t.Fatal(err)
	}
	kek, err := pki.LoadKEK(kekPath)
	if err != nil {
		t.Fatal(err)
	}
	e.ca, err = pki.LoadOrInit(context.Background(), e.st.Certs(), kek, pki.Options{})
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Store: e.st, CA: e.ca, Health: e.health, Alerter: e.alerts, ServerKey: e.serverKey,
		PackagesDir: e.pkgDir, Verifier: e.verifier, RemoteTmpDir: e.rtmp,
		DialTimeout: 5 * time.Second, StepTimeout: 30 * time.Second,
		HealthTimeout: 300 * time.Millisecond, HealthInterval: 20 * time.Millisecond,
		Logger: slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, o := range opts {
		o(&cfg)
	}
	e.inst, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.inst.Close)
	return e
}

// writeRelease кладёт подписанный релиз в кэш загрузок:
// <dir>/<v>/{tgproxy_<v>_<arch>.deb, checksums.txt, checksums.txt.minisig}.
func writeRelease(t *testing.T, dir, version string, key minisign.PrivateKey, debs map[string]string) {
	t.Helper()
	vd := filepath.Join(dir, version)
	if err := os.MkdirAll(vd, 0o755); err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	for arch, body := range debs {
		name := "tgproxy_" + version + "_" + arch + ".deb"
		if err := os.WriteFile(filepath.Join(vd, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(body))
		sums.WriteString(hex.EncodeToString(h[:]) + "  " + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(vd, "checksums.txt"), []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	r := minisign.NewReader(strings.NewReader(sums.String()))
	_, _ = io.Copy(io.Discard, r)
	sig := r.SignWithComments(key, "timestamp:1 file:checksums.txt", "t")
	if err := os.WriteFile(filepath.Join(vd, "checksums.txt.minisig"), sig, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *env) fingerprint() string { return ssh.FingerprintSHA256(e.hostKey.PublicKey()) }

func (e *env) pin() {
	e.t.Helper()
	k := e.hostKey.PublicKey()
	err := e.st.HostKeys().Put(context.Background(), store.HostKey{
		Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(e.host.port())), Algo: k.Type(),
		Fingerprint: ssh.FingerprintSHA256(k), PublicKey: k.Marshal(),
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) request() Request {
	return Request{
		Name: "ams-2", Host: "127.0.0.1", SSHPort: e.host.port(), User: "admin", AgentPort: 8443, Weight: 100,
		Auth:                 Auth{PrivateKeyPEM: append([]byte(nil), e.adminPEM...)},
		ConfirmedFingerprint: e.fingerprint(),
	}
}

// install запускает задачу и ждёт завершения.
func (e *env) install(req Request) (string, JobStatus) {
	e.t.Helper()
	id, err := e.inst.Install(context.Background(), req)
	if err != nil {
		e.t.Fatalf("Install: %v", err)
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

var (
	tmpRe = regexp.MustCompile(`/[A-Za-z0-9._/-]*/rtmp/tgproxy-[0-9a-f]{16}`)
	incRe = regexp.MustCompile(`/var/lib/tgproxy-incoming/tgproxy-[0-9a-f]{16}`)
)

func (e *env) cmdLines() []string {
	var out []string
	for _, c := range e.host.commands() {
		out = append(out, incRe.ReplaceAllString(tmpRe.ReplaceAllString(c.String(), "TMP"), "INC"))
	}
	return out
}

func (e *env) allEvents(id string) []Event {
	e.t.Helper()
	evs, _, err := e.inst.Events(context.Background(), id, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	return evs
}

func nopLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func rsaKey() (ssh.PublicKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(&k.PublicKey)
}
