package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/server/enroll"
	"github.com/vasyakrg/tgproxy-server/internal/store/memtest"
)

type enrollEnv struct {
	srv   *httptest.Server
	ca    *pki.Authority
	svc   *enroll.Service
	hits  *atomic.Int32
	dir   string
	cfg   string
	store *memtest.Store
}

// newEnrollEnv поднимает TLS-сервер с реальным Authority и enroll.Service;
// цепочка сервера содержит CA (как должен собирать wiring gateway).
func newEnrollEnv(t *testing.T, withCAInChain bool, wrap func(http.Handler) http.Handler) *enrollEnv {
	t.Helper()
	st := memtest.New()
	kp := filepath.Join(t.TempDir(), "kek")
	if err := pki.GenerateKEK(kp); err != nil {
		t.Fatal(err)
	}
	kek, err := pki.LoadKEK(kp)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadOrInit(context.Background(), st.Certs(), kek, pki.Options{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.ServerCert(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cert := *leaf
	if withCAInChain {
		blk, _ := pem.Decode(ca.CertPEM())
		cert.Certificate = append(append([][]byte{}, leaf.Certificate...), blk.Bytes)
	}
	svc, err := enroll.New(enroll.Config{
		Enrollments: st.Enrollments(), Agents: st.Agents(), Audit: st.Audit(), CA: ca,
		GatewayURL: "https://placeholder:8444",
	})
	if err != nil {
		t.Fatal(err)
	}
	hits := &atomic.Int32{}
	h := svc.Handler()
	if wrap != nil {
		h = wrap(h)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h.ServeHTTP(w, r)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	return &enrollEnv{srv: srv, ca: ca, svc: svc, hits: hits, dir: dir, cfg: filepath.Join(dir, "agent.yaml"), store: st}
}

func (e *enrollEnv) writeConfig(t *testing.T) {
	t.Helper()
	body := "# comment kept\nlisten:\n  api: \":8443\"\nmode: dial\ntls:\n  cert_file: " + filepath.Join(e.dir, "tls/agent.crt") +
		"\n  key_file: " + filepath.Join(e.dir, "tls/agent.key") + "\n  ca_file: " + filepath.Join(e.dir, "tls/ca.crt") + "\n"
	if err := os.WriteFile(e.cfg, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func (e *enrollEnv) token(t *testing.T, name string) string {
	t.Helper()
	is, err := e.svc.IssueFor(context.Background(), enroll.IssueRequest{Name: name, InstalledOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	return is.Token
}

func (e *enrollEnv) opts(token string) EnrollOptions {
	return EnrollOptions{Server: e.srv.URL, Token: token, CAFingerprint: e.ca.CAFingerprint(), ConfigPath: e.cfg}
}

func TestEnrollEndToEnd(t *testing.T) {
	e := newEnrollEnv(t, true, nil)
	e.writeConfig(t)
	res, err := Enroll(context.Background(), e.opts(e.token(t, "nat-box")))
	if err != nil {
		t.Fatal(err)
	}
	if res.AgentID != "nat-box" {
		t.Errorf("agent id %q", res.AgentID)
	}
	st, err := os.Stat(res.KeyFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key: %v %v", st, err)
	}
	pair, err := tls.LoadX509KeyPair(res.CertFile, res.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if id, err := pki.AgentIDFromCert(leaf); err != nil || id != "nat-box" {
		t.Errorf("san %q %v", id, err)
	}
	if pk, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		t.Error("not P-256")
	}
	caPEM, _ := os.ReadFile(res.CAFile)
	if string(caPEM) != string(e.ca.CertPEM()) {
		t.Error("ca file mismatch")
	}
	raw, _ := os.ReadFile(e.cfg)
	for _, want := range []string{"# comment kept", "mode: reverse", "server_url: " + e.srv.URL} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config lacks %q:\n%s", want, raw)
		}
	}
}

func TestEnrollTokenReuse(t *testing.T) {
	e := newEnrollEnv(t, true, nil)
	e.writeConfig(t)
	tok := e.token(t, "a")
	if _, err := Enroll(context.Background(), e.opts(tok)); err != nil {
		t.Fatal(err)
	}
	_, err := Enroll(context.Background(), e.opts(tok))
	if err == nil || !strings.Contains(err.Error(), "invalid, expired or already used") || strings.Contains(err.Error(), tok) {
		t.Fatalf("err: %v", err)
	}
}

func TestEnrollWrongFingerprintNeverSendsToken(t *testing.T) {
	e := newEnrollEnv(t, true, nil)
	e.writeConfig(t)
	o := e.opts(e.token(t, "a"))
	o.CAFingerprint = "SHA256:" + strings.Repeat("A", 43)
	_, err := Enroll(context.Background(), o)
	if err == nil {
		t.Fatal("expected error")
	}
	if e.hits.Load() != 0 {
		t.Fatalf("request reached server: %d", e.hits.Load())
	}
	if _, serr := os.Stat(filepath.Join(e.dir, "tls/agent.key")); serr == nil {
		t.Error("key written despite failure")
	}
}

func TestEnrollServerWithoutCAInChain(t *testing.T) {
	e := newEnrollEnv(t, false, nil)
	e.writeConfig(t)
	if _, err := Enroll(context.Background(), e.opts(e.token(t, "a"))); err == nil || e.hits.Load() != 0 {
		t.Fatalf("err %v hits %d", err, e.hits.Load())
	}
}

func TestEnrollCreatesMinimalConfig(t *testing.T) {
	e := newEnrollEnv(t, true, nil)
	dir := t.TempDir()
	// без конфига пути по умолчанию недоступны для записи в тесте — проверяем через конфиг с tls, созданный заранее
	e.cfg = filepath.Join(dir, "sub", "agent.yaml")
	files, exists, err := agentTLSFiles(e.cfg)
	if err != nil || exists || files.KeyFile == "" {
		t.Fatalf("defaults: %+v %v %v", files, exists, err)
	}
	local := config.TLSFiles{CertFile: filepath.Join(dir, "c.crt"), KeyFile: filepath.Join(dir, "k.key"), CAFile: filepath.Join(dir, "ca.crt")}
	if err := writeMinimalAgentConfig(e.cfg, local, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(e.cfg)
	if !strings.Contains(string(raw), "mode: reverse") || !strings.Contains(string(raw), local.KeyFile) {
		t.Errorf("minimal config:\n%s", raw)
	}
}

func TestEnrollEmptyDirConfigLoads(t *testing.T) {
	e := newEnrollEnv(t, true, nil)
	dir := t.TempDir()
	local := config.TLSFiles{CertFile: filepath.Join(dir, "c.crt"), KeyFile: filepath.Join(dir, "k.key"), CAFile: filepath.Join(dir, "ca.crt")}
	cfg := filepath.Join(dir, "etc", "agent.yaml")
	if err := writeMinimalAgentConfig(cfg, local, nil); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveAgentConnection(cfg, config.AgentModeReverse, e.srv.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadAgent(cfg); err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
}

func TestEnrollConfigWithoutTLS(t *testing.T) {
	e := newEnrollEnv(t, true, nil)
	if err := os.WriteFile(e.cfg, []byte("mode: dial\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(context.Background(), e.opts(e.token(t, "a"))); err == nil || !strings.Contains(err.Error(), "no tls") {
		t.Fatalf("err %v", err)
	}
	if e.hits.Load() != 0 {
		t.Error("request sent before config check")
	}
	if err := os.WriteFile(e.cfg, []byte("tls: [1"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(context.Background(), e.opts("t")); err == nil {
		t.Error("bad yaml accepted")
	}
}

func TestEnrollInputValidation(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("A", 43)
	cases := map[string]EnrollOptions{
		"http":     {Server: "http://h:8444", Token: "t", CAFingerprint: fp},
		"path":     {Server: "https://h:8444/x", Token: "t", CAFingerprint: fp},
		"userinfo": {Server: "https://u@h:8444", Token: "t", CAFingerprint: fp},
		"notoken":  {Server: "https://h:8444", CAFingerprint: fp},
		"nofp":     {Server: "https://h:8444", Token: "t"},
		"badfp":    {Server: "https://h:8444", Token: "t", CAFingerprint: "SHA256:xx"},
		"hexfp":    {Server: "https://h:8444", Token: "t", CAFingerprint: "SHA256:!!!"},
	}
	for name, o := range cases {
		if _, err := Enroll(context.Background(), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnrollServerStatuses(t *testing.T) {
	for _, tc := range []struct {
		code int
		body string
		want string
	}{
		{429, `{"error":"x"}`, "too many attempts"},
		{422, `{"error":"bad key"}`, "bad key"},
		{500, `oops`, "unexpected response"},
		{200, `not json`, "bad response"},
	} {
		e := newEnrollEnv(t, true, func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			})
		})
		e.writeConfig(t)
		_, err := Enroll(context.Background(), e.opts("tok"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%d: %v", tc.code, err)
		}
	}
}

// Сервер, подписавший сертификат на чужой ключ / вернувший чужой CA, отвергается.
func TestEnrollRejectsTamperedResponse(t *testing.T) {
	other, _ := pki.NewCA("other", time.Hour)
	for name, tamper := range map[string]func(r *enrollResponse, e *enrollEnv){
		"foreign ca": func(r *enrollResponse, _ *enrollEnv) { r.CA = string(other.CertPEM()) },
		"no ca":      func(r *enrollResponse, _ *enrollEnv) { r.CA = "" },
		"no cert":    func(r *enrollResponse, _ *enrollEnv) { r.Cert = "" },
		"bad cert": func(r *enrollResponse, _ *enrollEnv) {
			r.Cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		},
		"wrong id": func(r *enrollResponse, _ *enrollEnv) { r.AgentID = "someone-else" },
		"foreign key": func(r *enrollResponse, e *enrollEnv) {
			csr, _, _ := pki.NewAgentCSR("nat-x")
			c, _, err := e.ca.SignAgentCSR(context.Background(), csr, "nat-x", 0)
			if err != nil {
				panic(err)
			}
			r.Cert = string(c)
		},
		"unchained cert": func(r *enrollResponse, _ *enrollEnv) {
			csr, _, _ := pki.NewAgentCSR("nat-x")
			c, _ := pki.IssueAgent(other, csr, "nat-x", 0)
			r.Cert = string(c)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var env *enrollEnv
			env = newEnrollEnv(t, true, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					rec := httptest.NewRecorder()
					next.ServeHTTP(rec, r)
					var resp enrollResponse
					_ = json.Unmarshal(rec.Body.Bytes(), &resp)
					tamper(&resp, env)
					_ = json.NewEncoder(w).Encode(resp)
				})
			})
			env.writeConfig(t)
			if _, err := Enroll(context.Background(), env.opts(env.token(t, "nat-x"))); err == nil {
				t.Fatal("tampered response accepted")
			}
			if _, serr := os.Stat(filepath.Join(env.dir, "tls/agent.key")); serr == nil {
				t.Error("key written for rejected response")
			}
		})
	}
}

func TestEnrollConnectionError(t *testing.T) {
	e := newEnrollEnv(t, true, nil)
	e.writeConfig(t)
	o := e.opts("t")
	e.srv.Close()
	o.Timeout = 2 * time.Second
	if _, err := Enroll(context.Background(), o); err == nil || strings.Contains(err.Error(), e.srv.URL+"/enroll") {
		t.Fatalf("err %v", err)
	}
}

func TestWriteEnrollFileErrors(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "file")
	_ = os.WriteFile(f, nil, 0o600)
	if err := writeEnrollFile(filepath.Join(f, "x"), []byte("a"), 0o600, nil); err == nil {
		t.Error("write under a file accepted")
	}
	if err := writeEnrollFile(filepath.Join(dir, "d", "ok"), []byte("a"), 0o600, nil); err != nil {
		t.Error(err)
	}
	// rename поверх каталога
	_ = os.Mkdir(filepath.Join(dir, "isdir"), 0o750)
	if err := writeEnrollFile(filepath.Join(dir, "isdir"), []byte("a"), 0o600, nil); err == nil {
		t.Error("rename over dir accepted")
	}
}

func TestSecretKeyUnique(t *testing.T) {
	// два enrollment подряд генерируют разные ключи
	e := newEnrollEnv(t, true, nil)
	e.writeConfig(t)
	r1, err := Enroll(context.Background(), e.opts(e.token(t, "k1")))
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := os.ReadFile(r1.KeyFile)
	r2, err := Enroll(context.Background(), e.opts(e.token(t, "k2")))
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := os.ReadFile(r2.KeyFile)
	if string(k1) == string(k2) {
		t.Error("same key reused")
	}
}

func fakeOwnerOps(euid int, users map[string]*user.User) (*ownerOps, *[]string) {
	var calls []string
	return &ownerOps{
		geteuid: func() int { return euid },
		lookup: func(n string) (*user.User, error) {
			if u, ok := users[n]; ok {
				return u, nil
			}
			return nil, user.UnknownUserError(n)
		},
		fchown: func(_ *os.File, uid, gid int) error {
			calls = append(calls, fmt.Sprintf("fchown %d:%d", uid, gid))
			return nil
		},
		lchown: func(p string, uid, gid int) error {
			calls = append(calls, fmt.Sprintf("lchown %s %d:%d", filepath.Base(p), uid, gid))
			return nil
		},
	}, &calls
}

func TestOwnerResolve(t *testing.T) {
	users := map[string]*user.User{"tgproxy": {Uid: "990", Gid: "991"}, "svc": {Uid: "5", Gid: "6"}}

	ops, calls := fakeOwnerOps(1000, users)
	own, err := ops.resolve("")
	if err != nil || own.config() != nil || own.data() != nil {
		t.Fatalf("non-root: %v %+v", err, own)
	}
	d := t.TempDir()
	if err := writeEnrollFile(filepath.Join(d, "x"), []byte("a"), 0o600, own.data()); err != nil {
		t.Fatal(err)
	}
	if err := own.ensureDir(filepath.Join(d, "sub"), true, own.data()); err != nil {
		t.Fatal(err)
	}
	if err := own.chownFile(filepath.Join(d, "x"), own.config()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Errorf("chown вызван не от root: %v", *calls)
	}

	ops, _ = fakeOwnerOps(0, users)
	own, err = ops.resolve("")
	if err != nil || own.config().uid != 0 || own.config().gid != 991 || own.data().uid != 990 || own.data().gid != 991 {
		t.Fatalf("root default: %v %+v", err, own)
	}
	if own, err = ops.resolve("svc"); err != nil || own.data().uid != 5 || own.config().gid != 6 || own.config().uid != 0 {
		t.Fatalf("root --service-user: %v %+v", err, own)
	}
	if _, err = ops.resolve("nobody-here"); err == nil || !strings.Contains(err.Error(), "nobody-here") {
		t.Errorf("нет пользователя: err=%v", err)
	}
	bad, _ := fakeOwnerOps(0, map[string]*user.User{"tgproxy": {Uid: "x", Gid: "1"}})
	if _, err = bad.resolve(""); err == nil {
		t.Error("нечисловой uid принят")
	}
}

func TestOwnerApply(t *testing.T) {
	ops, calls := fakeOwnerOps(0, map[string]*user.User{"tgproxy": {Uid: "990", Gid: "991"}})
	own, err := ops.resolve("")
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	if err := writeEnrollFile(filepath.Join(d, "agent.key"), []byte("k"), 0o600, own.data()); err != nil {
		t.Fatal(err)
	}
	if got := (*calls)[len(*calls)-1]; got != "fchown 990:991" {
		t.Errorf("fchown: %q", got)
	}
	// существующий каталог: при force=false не трогаем, при force=true чиним
	n := len(*calls)
	if err := own.ensureDir(d, false, own.data()); err != nil || len(*calls) != n {
		t.Errorf("force=false: %v %v", err, *calls)
	}
	if err := own.ensureDir(d, true, own.data()); err != nil || len(*calls) != n+1 {
		t.Errorf("force=true: %v %v", err, *calls)
	}
	// новый каталог chown-им даже без force
	n = len(*calls)
	if err := own.ensureDir(filepath.Join(d, "new"), false, own.config()); err != nil || (*calls)[n] != "lchown new 0:991" {
		t.Errorf("new dir: %v %v", err, *calls)
	}
	// симлинк и не-каталог отвергаются
	link := filepath.Join(d, "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	if err := own.ensureDir(link, true, own.data()); err == nil {
		t.Error("симлинк вместо каталога принят")
	}
	if err := own.chownFile(link, own.config()); err == nil {
		t.Error("симлинк вместо файла принят")
	}
	if err := own.chownFile(filepath.Join(d, "agent.key"), own.config()); err != nil || (*calls)[len(*calls)-1] != "lchown agent.key 0:991" {
		t.Errorf("chownFile: %v %v", err, *calls)
	}
}
