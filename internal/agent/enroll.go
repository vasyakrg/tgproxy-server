package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

// Умолчания enrollment.
const (
	DefaultAgentConfigPath = "/etc/tgproxy/agent.yaml"
	// DefaultServiceUser — системный пользователь юнита tgproxy-agent (User=/Group=).
	DefaultServiceUser = "tgproxy"
	defaultAgentTLSDir = "/var/lib/tgproxy/agent"
	enrollTimeout      = 30 * time.Second
	maxEnrollResponse  = 1 << 20
)

// EnrollOptions — параметры `tgproxy agent enroll`.
type EnrollOptions struct {
	Server        string // https://host:8444 (agent_gateway)
	Token         string
	CAFingerprint string // SHA256:<base64 raw>, как печатает сервер
	ConfigPath    string // по умолчанию /etc/tgproxy/agent.yaml
	// ServiceUser — пользователь/группа юнита агента; от root файлы отдаются ему
	// (по умолчанию DefaultServiceUser). Не от root — игнорируется.
	ServiceUser string
	Timeout     time.Duration
}

// EnrollResult — итог enrollment.
type EnrollResult struct {
	AgentID    string
	CertFile   string
	KeyFile    string
	CAFile     string
	ConfigPath string
}

type enrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

type enrollResponse struct {
	AgentID string `json:"agent_id"`
	Cert    string `json:"cert"`
	CA      string `json:"ca"`
}

// Enroll подключает агента к серверу по одноразовому токену: pinning CA по
// отпечатку (до отправки токена), локальная генерация ключа P-256, CSR,
// сохранение crt/key/ca и режима reverse в конфиг агента. Токен в ошибки и
// логи не попадает.
func Enroll(ctx context.Context, opts EnrollOptions) (*EnrollResult, error) {
	srv, err := parseEnrollServer(opts.Server)
	if err != nil {
		return nil, err
	}
	if opts.Token == "" {
		return nil, errors.New("enroll: token is required")
	}
	if err := validateFingerprint(opts.CAFingerprint); err != nil {
		return nil, err
	}
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = DefaultAgentConfigPath
	}
	files, cfgExists, err := agentTLSFiles(cfgPath)
	if err != nil {
		return nil, err
	}
	// Владелец определяется до сетевого запроса: нет пользователя — токен не сжигаем.
	own, err := defaultOwnerOps.resolve(opts.ServiceUser)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = enrollTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enroll: generate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "tgproxy-agent"},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("enroll: create csr: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	resp, err := postEnroll(ctx, srv, opts.CAFingerprint, enrollRequest{Token: opts.Token, CSR: string(csrPEM)})
	if err != nil {
		return nil, err
	}
	if err := verifyEnrollResponse(resp, opts.CAFingerprint, &key.PublicKey); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("enroll: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// Каталоги: TLS — данные сервиса (при повторном enroll права чинятся);
	// каталог конфига создаём root:<группа сервиса>, существующий не трогаем.
	if !cfgExists {
		if err := own.ensureDir(filepath.Dir(cfgPath), false, own.config()); err != nil {
			return nil, err
		}
	}
	for _, p := range []string{files.KeyFile, files.CertFile, files.CAFile} {
		if err := own.ensureDir(filepath.Dir(p), true, own.data()); err != nil {
			return nil, err
		}
	}
	// Ключ первым: если дальше что-то упадёт, пара «ключ без серта» безвредна.
	for _, f := range []struct {
		path string
		data []byte
		perm os.FileMode
	}{
		{files.KeyFile, keyPEM, 0o600},
		{files.CertFile, []byte(resp.Cert), 0o644},
		{files.CAFile, []byte(resp.CA), 0o644},
	} {
		if err := writeEnrollFile(f.path, f.data, f.perm, own.data()); err != nil {
			return nil, err
		}
	}
	if !cfgExists {
		if err := writeMinimalAgentConfig(cfgPath, files, own.config()); err != nil {
			return nil, err
		}
	}
	if err := config.SaveAgentConnection(cfgPath, config.AgentModeReverse, srv.String()); err != nil {
		return nil, fmt.Errorf("enroll: save config: %w", err)
	}
	// SaveAgentConnection пересоздаёт файл через temp+rename (владелец root) —
	// возвращаем root:<группа сервиса>.
	if err := own.chownFile(cfgPath, own.config()); err != nil {
		return nil, err
	}
	return &EnrollResult{AgentID: resp.AgentID, CertFile: files.CertFile, KeyFile: files.KeyFile, CAFile: files.CAFile, ConfigPath: cfgPath}, nil
}

func parseEnrollServer(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("enroll: --server must be https://host[:port], got %q", raw)
	}
	return &url.URL{Scheme: "https", Host: u.Host}, nil
}

func validateFingerprint(fp string) error {
	rest, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok {
		return errors.New("enroll: --ca-fingerprint must look like SHA256:<base64>")
	}
	if raw, err := base64.RawStdEncoding.DecodeString(rest); err != nil || len(raw) != 32 {
		return errors.New("enroll: --ca-fingerprint must look like SHA256:<base64>")
	}
	return nil
}

// pinnedTLSConfig: системные корни не используются. Цепочка сервера обязана
// содержать CA с заданным отпечатком; лист проверяется к этому CA и обязан
// иметь SAN spiffe://tgproxy/server.
func pinnedTLSConfig(fingerprint string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true, // #nosec G402 -- проверка в VerifyConnection: pinning CA по отпечатку
		VerifyConnection: func(cs tls.ConnectionState) error {
			pool := x509.NewCertPool()
			var found bool
			for _, c := range cs.PeerCertificates[min(1, len(cs.PeerCertificates)):] {
				if c.IsCA && pki.Fingerprint(c) == fingerprint {
					pool.AddCert(c)
					found = true
				}
			}
			if !found {
				return errors.New("enroll: server chain has no CA with the expected fingerprint")
			}
			return pki.VerifyServerPeer(pool)(cs)
		},
	}
}

func postEnroll(ctx context.Context, srv *url.URL, fingerprint string, body enrollRequest) (*enrollResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: pinnedTLSConfig(fingerprint), DisableKeepAlives: true, Proxy: nil}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.String()+"/enroll", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: request failed: %w", redactURLErr(err))
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxEnrollResponse))
	if err != nil {
		return nil, fmt.Errorf("enroll: read response: %w", err)
	}
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, errors.New("enroll: token is invalid, expired or already used")
	case http.StatusTooManyRequests:
		return nil, errors.New("enroll: too many attempts, retry in a minute")
	case http.StatusUnprocessableEntity:
		return nil, fmt.Errorf("enroll: server rejected csr: %s", serverMessage(data))
	default:
		return nil, fmt.Errorf("enroll: server returned %d: %s", res.StatusCode, serverMessage(data))
	}
	var out enrollResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("enroll: bad response: %w", err)
	}
	return &out, nil
}

func redactURLErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func serverMessage(data []byte) string {
	var m struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &m) == nil && m.Error != "" {
		return m.Error
	}
	return "unexpected response"
}

// verifyEnrollResponse: CA совпадает с pin, сертификат принадлежит нашему
// ключу, подписан этим CA и содержит SAN агента с выданным id.
func verifyEnrollResponse(r *enrollResponse, fingerprint string, pub *ecdsa.PublicKey) error {
	caBlk, _ := pem.Decode([]byte(r.CA))
	if caBlk == nil {
		return errors.New("enroll: response has no CA")
	}
	ca, err := x509.ParseCertificate(caBlk.Bytes)
	if err != nil || !ca.IsCA || pki.Fingerprint(ca) != fingerprint {
		return errors.New("enroll: CA in response does not match the pinned fingerprint")
	}
	certBlk, _ := pem.Decode([]byte(r.Cert))
	if certBlk == nil {
		return errors.New("enroll: response has no certificate")
	}
	cert, err := x509.ParseCertificate(certBlk.Bytes)
	if err != nil {
		return errors.New("enroll: bad certificate in response")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("enroll: certificate does not chain to the pinned CA: %w", err)
	}
	if cp, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !cp.Equal(pub) {
		return errors.New("enroll: certificate does not match the generated key")
	}
	if id, err := pki.AgentIDFromCert(cert); err != nil || id != r.AgentID {
		return errors.New("enroll: certificate SAN does not match agent_id")
	}
	return nil
}

// agentTLSFiles возвращает пути crt/key/ca из конфига агента. Нет файла —
// умолчания (рядом будет создан минимальный конфиг). Файл без секции tls — ошибка.
func agentTLSFiles(cfgPath string) (files config.TLSFiles, exists bool, err error) {
	data, err := os.ReadFile(cfgPath) // #nosec G304 -- путь конфига агента задаёт оператор
	if errors.Is(err, os.ErrNotExist) {
		return config.TLSFiles{
			CertFile: filepath.Join(defaultAgentTLSDir, "agent.crt"),
			KeyFile:  filepath.Join(defaultAgentTLSDir, "agent.key"),
			CAFile:   filepath.Join(defaultAgentTLSDir, "ca.crt"),
		}, false, nil
	}
	if err != nil {
		return files, false, fmt.Errorf("enroll: read config: %w", err)
	}
	var doc struct {
		TLS config.TLSFiles `yaml:"tls"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return files, true, fmt.Errorf("enroll: parse config: %w", err)
	}
	t := doc.TLS
	if t.CertFile == "" || t.KeyFile == "" || t.CAFile == "" {
		return files, true, fmt.Errorf("enroll: %s has no tls.cert_file/key_file/ca_file", cfgPath)
	}
	return t, true, nil
}

func writeMinimalAgentConfig(path string, f config.TLSFiles, cfgOwner *fileOwner) error {
	doc := map[string]any{
		"mode":   string(config.AgentModeReverse),
		"listen": map[string]string{"api": "127.0.0.1:8443", "metrics": "127.0.0.1:9101"},
		"tls":    f,
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return writeEnrollFile(path, data, 0o640, cfgOwner)
}

// fileOwner — uid/gid, которые выставляются на файл или каталог.
type fileOwner struct {
	uid, gid int
	fchown   func(f *os.File, uid, gid int) error
}

// ownerOps — внедряемые системные вызовы (в тестах подменяются, root не нужен).
type ownerOps struct {
	geteuid func() int
	lookup  func(name string) (*user.User, error)
	fchown  func(f *os.File, uid, gid int) error
	lchown  func(path string, uid, gid int) error
}

var defaultOwnerOps = &ownerOps{
	geteuid: os.Geteuid,
	lookup:  user.Lookup,
	fchown:  func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) },
	lchown:  os.Lchown,
}

// enrollOwners — результат resolve; nil-значение (не root) ничего не меняет.
type enrollOwners struct {
	ops           *ownerOps
	root, service fileOwner
	active        bool
}

// resolve: от root ищет пользователя сервиса (ошибка, если его нет), иначе
// возвращает «пустой» результат — владелец не трогается (dev/тесты).
func (o *ownerOps) resolve(serviceUser string) (*enrollOwners, error) {
	if o.geteuid() != 0 {
		return &enrollOwners{ops: o}, nil
	}
	if serviceUser == "" {
		serviceUser = DefaultServiceUser
	}
	u, err := o.lookup(serviceUser)
	if err != nil {
		return nil, fmt.Errorf("enroll: service user %q not found (пакет tgproxy не установлен? для нестандартной установки задайте --service-user): %w", serviceUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("enroll: bad uid %q of user %q", u.Uid, serviceUser)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("enroll: bad gid %q of user %q", u.Gid, serviceUser)
	}
	return &enrollOwners{ops: o, active: true, root: fileOwner{0, gid, o.fchown}, service: fileOwner{uid, gid, o.fchown}}, nil
}

// config — владелец agent.yaml и его каталога: root:<группа сервиса>.
func (e *enrollOwners) config() *fileOwner {
	if !e.active {
		return nil
	}
	return &e.root
}

// data — владелец data_dir и TLS-файлов: <сервис>:<группа сервиса>.
func (e *enrollOwners) data() *fileOwner {
	if !e.active {
		return nil
	}
	return &e.service
}

// chownFile меняет владельца обычного файла по пути (не симлинк).
func (e *enrollOwners) chownFile(path string, own *fileOwner) error {
	if own == nil {
		return nil
	}
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("enroll: %s is not a regular file", path)
	}
	if err := e.ops.lchown(path, own.uid, own.gid); err != nil {
		return fmt.Errorf("enroll: chown %s: %w", path, err)
	}
	return nil
}

// ensureDir создаёт каталог (0750) и выставляет владельца. Существующий каталог
// должен быть именно каталогом, не симлинком; его владелец меняется только при
// force (data_dir — чиним при повторном enroll; системные каталоги не трогаем).
func (e *enrollOwners) ensureDir(dir string, force bool, own *fileOwner) error {
	st, err := os.Lstat(dir)
	created := false
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
		created = true
		if st, err = os.Lstat(dir); err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
	case err != nil:
		return fmt.Errorf("enroll: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("enroll: %s is not a directory", dir)
	}
	if own == nil || (!created && !force) {
		return nil
	}
	if err := e.ops.lchown(dir, own.uid, own.gid); err != nil {
		return fmt.Errorf("enroll: chown %s: %w", dir, err)
	}
	return nil
}

// writeEnrollFile пишет файл через temp+rename с заданными правами. Если own != nil,
// владелец выставляется fchown на дескрипторе temp-файла до rename (без гонок и симлинков).
func writeEnrollFile(path string, data []byte, perm os.FileMode, own *fileOwner) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".enroll-*")
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("enroll: %w", err)
	}
	if own != nil {
		if err := own.fchown(tmp, own.uid, own.gid); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("enroll: chown: %w", err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("enroll: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	ok = true
	return nil
}
