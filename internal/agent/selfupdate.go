package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/release"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

// Самообновление агента (docs/architecture.md §4, §12; plan M6-T4).
//
// Сервер шлёт только версию и URL своего agent_gateway. Агент сам качает релиз
// (deb + checksums.txt + .minisig) по mTLS, проверяет minisign ВСТРОЕННЫМИ ключами
// и нижнюю границу версии (не ниже установленной) и кладёт проверенный релиз в
// updates/staged вместе с request. Дальше работает root-oneshot `tgproxy update
// apply` (повторная проверка, установка, health 60s, откат на prev.deb).
// Компрометация сервера не даёт RCE: подписанный чужой пакет агент не примет.

const (
	maxUpdateBody      = 4 << 10
	maxUpdateChecksums = 1 << 20
	maxUpdateSig       = 4 << 10
	maxUpdateDeb       = 512 << 20
	defaultUpdateTO    = 10 * time.Minute
	updateHeaderTO     = 30 * time.Second

	componentAgent = "agent"
	requestName    = "request"
	resultName     = "result.json"
)

// Состояния GET /_agent/update.
const (
	UpdateIdle        = "idle"
	UpdateDownloading = "downloading"
	UpdateStaged      = "staged"
	UpdateApplied     = "applied"
	UpdateFailed      = "failed"
)

var updateVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

// UpdateConfig — параметры самообновления; нулевые поля берут боевые значения
// (встроенные ключи, нижняя граница = установленная версия, runtime.GOARCH).
type UpdateConfig struct {
	Verifier *verify.Verifier // nil — встроенные ключи, MinVersion = текущая версия
	Arch     string
	Timeout  time.Duration // общий потолок загрузки; 0 — 10 минут
}

// WithUpdateConfig задаёт параметры самообновления (тесты).
func WithUpdateConfig(c UpdateConfig) Option { return func(a *Agent) { a.upd.cfg = c } }

// WithVersionFunc подменяет источник версии агента (только тесты: имитация
// перезапуска на новой версии).
func WithVersionFunc(f func() string) Option { return func(a *Agent) { a.upd.version = f } }

type selfUpdater struct {
	cfg     UpdateConfig
	version func() string

	mu     sync.Mutex
	busy   bool
	target string
	failed string // причина последней неудачи (до следующей попытки)
}

func (a *Agent) currentVersion() string {
	if a.upd.version != nil {
		return a.upd.version()
	}
	return buildinfo.Version
}

func (a *Agent) updateVerifier() (verify.Verifier, error) {
	if v := a.upd.cfg.Verifier; v != nil {
		return *v, nil
	}
	keys, err := release.EmbeddedPubKeys()
	if err != nil {
		return verify.Verifier{}, fmt.Errorf("встроенные ключи: %w", err)
	}
	floor := a.currentVersion()
	if _, err := verify.ParseVersion(floor); err != nil {
		floor = "" // dev-сборка: нижней границы нет
	}
	return verify.Verifier{Keys: keys, MinVersion: floor}, nil
}

func (a *Agent) currentMode() config.AgentMode { m, _, _, _ := a.mgr.snapshot(); return m }

func (a *Agent) updatesDir() string { return filepath.Join(a.cfg.DataDir, "updates") }

type updateRequest struct {
	Version    string `json:"version"`
	GatewayURL string `json:"gateway_url"`
}

type updateReply struct {
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
	Result  any    `json:"result,omitempty"`
}

func writeUpdateJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func updateErr(w http.ResponseWriter, code int, msg string) {
	writeUpdateJSON(w, code, updateReply{State: UpdateFailed, Error: msg})
}

// handleUpdate — POST /_agent/update {"version","gateway_url"}.
//
//	400 — не JSON / неверная форма; 422 — версия ниже нижней границы, подпись
//	или sha256 не сошлись (отказ действует и для команды сервера); 409 — другое
//	обновление в работе / уже поставлено в очередь / версия уже установлена;
//	502 — gateway недоступен; 202 — проверенный релиз в updates/staged, запрос создан.
//
// Запрос синхронный: ответ — вердикт проверки, а не обещание.
func (a *Agent) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUpdateBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !updateVersionRe.MatchString(req.Version) {
		updateErr(w, http.StatusBadRequest, "bad update request")
		return
	}
	// reverse/both-агент качает с СВОЕГО server_url (сервер туда и так подключён); gateway_url
	// из команды нужен только dial-агенту, у которого server_url нет.
	gwRaw := req.GatewayURL
	if _, own, _, _ := a.mgr.snapshot(); own != "" && wantConnector(a.currentMode()) {
		gwRaw = own
	}
	gw, err := parseServerURL(gwRaw)
	if err != nil {
		updateErr(w, http.StatusBadRequest, "gateway_url: want https://host[:port]")
		return
	}
	ver, err := a.updateVerifier()
	if err != nil {
		a.logger.Error("agent update: verifier", "err", err)
		updateErr(w, http.StatusInternalServerError, "verifier unavailable")
		return
	}
	if err := ver.CheckVersion(req.Version); err != nil {
		a.logger.Warn("agent update rejected", "version", req.Version, "reason", err)
		updateErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if cmp, err := verify.CompareVersions(a.currentVersion(), req.Version); err == nil && cmp == 0 {
		updateErr(w, http.StatusConflict, "version already installed")
		return
	}

	u := &a.upd
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		updateErr(w, http.StatusConflict, "update already in progress")
		return
	}
	if p, _ := a.pendingRequest(); p != nil {
		u.mu.Unlock()
		if p.Version == req.Version {
			writeUpdateJSON(w, http.StatusAccepted, updateReply{State: UpdateStaged, Version: req.Version})
			return
		}
		updateErr(w, http.StatusConflict, "another update is staged: "+p.Version)
		return
	}
	u.busy, u.target, u.failed = true, req.Version, ""
	u.mu.Unlock()

	err = a.downloadAndStage(r.Context(), gw, req.Version, ver)

	u.mu.Lock()
	u.busy = false
	if err != nil {
		u.failed = err.Error()
	}
	u.mu.Unlock()
	if err != nil {
		code := http.StatusBadGateway
		var ve *verifyError
		if errors.As(err, &ve) {
			code = http.StatusUnprocessableEntity
		}
		a.logger.Warn("agent update failed", "version", req.Version, "err", err)
		updateErr(w, code, err.Error())
		return
	}
	a.logger.Info("agent update staged", "version", req.Version)
	writeUpdateJSON(w, http.StatusAccepted, updateReply{State: UpdateStaged, Version: req.Version})
}

// verifyError — релиз получен, но не прошёл проверку подлинности.
type verifyError struct{ err error }

func (e *verifyError) Error() string { return e.err.Error() }
func (e *verifyError) Unwrap() error { return e.err }

type stagedRequest struct {
	Version   string `json:"version"`
	Component string `json:"component"`
}

func (a *Agent) pendingRequest() (*stagedRequest, error) {
	b, err := os.ReadFile(filepath.Join(a.updatesDir(), "staged", requestName)) // #nosec G304 -- путь из data_dir и константы
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var p stagedRequest
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (a *Agent) downloadAndStage(ctx context.Context, gw *url.URL, version string, ver verify.Verifier) error {
	timeout := a.upd.cfg.Timeout
	if timeout <= 0 {
		timeout = defaultUpdateTO
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	arch := a.upd.cfg.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	debName := release.DebName(version, arch)

	updates := a.updatesDir()
	dlRoot := filepath.Join(updates, "downloads")
	if err := os.MkdirAll(dlRoot, 0o750); err != nil {
		return fmt.Errorf("download dir: %w", err)
	}
	tmp, err := os.MkdirTemp(dlRoot, ".dl-")
	if err != nil {
		return fmt.Errorf("download dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	client := a.gatewayClient(gw)
	defer client.CloseIdleConnections()
	for _, f := range []struct {
		name  string
		limit int64
	}{{release.ChecksumsName, maxUpdateChecksums}, {release.SigName, maxUpdateSig}, {debName, maxUpdateDeb}} {
		if err := fetchPackage(ctx, client, gw, version, f.name, filepath.Join(tmp, f.name), f.limit); err != nil {
			return err
		}
	}
	if err := verifyRelease(tmp, debName, ver); err != nil {
		return &verifyError{err}
	}

	// Проверенный релиз — в кэш загрузок агента (updates/downloads/<v>) и в staged.
	final := release.VersionDir(dlRoot, version)
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("download cache: %w", err)
	}
	return stageRelease(updates, final, debName, version)
}

// verifyRelease: подпись checksums.txt встроенными ключами и sha256 deb из подписанного списка.
func verifyRelease(dir, debName string, ver verify.Verifier) error {
	checksums, err := os.ReadFile(filepath.Join(dir, release.ChecksumsName)) // #nosec G304 -- фиксированные имена в своём temp-каталоге
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(dir, release.SigName)) // #nosec G304 -- см. выше
	if err != nil {
		return err
	}
	if err := ver.Verify(checksums, sig); err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(dir, debName)) // #nosec G304 -- см. выше
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return ver.CheckFile(checksums, debName, f)
}

// stageRelease собирает updates/staged во временном каталоге и подменяет его
// атомарным rename; request — последним файлом перед rename, поэтому path-юнит
// не увидит частичной загрузки.
func stageRelease(updates, src, debName, version string) (err error) {
	tmp, err := os.MkdirTemp(updates, ".staging-")
	if err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmp)
		}
	}()
	for _, n := range []string{debName, release.ChecksumsName, release.SigName} {
		if err = copyPrivate(filepath.Join(src, n), filepath.Join(tmp, n)); err != nil {
			return fmt.Errorf("staging: %w", err)
		}
	}
	req, err := json.Marshal(stagedRequest{Version: version, Component: componentAgent})
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(tmp, requestName), req, 0o600); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	staged := filepath.Join(updates, "staged")
	if err = os.RemoveAll(staged); err != nil { // остаток прошлой неудачи без request
		return fmt.Errorf("staging: %w", err)
	}
	if err = os.Rename(tmp, staged); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	return nil
}

func copyPrivate(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- каталог кэша загрузок агента
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- свежий temp-каталог
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err = out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// gatewayClient — HTTP/1.1-клиент к agent_gateway: клиентский сертификат агента
// (горячая подмена при ротации), сервер проверяется по CA проекта и SAN tgproxy-server.
func (a *Agent) gatewayClient(gw *url.URL) *http.Client {
	cfg := &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              a.caPool,
		NextProtos:           []string{"http/1.1"}, // http-часть gateway не говорит h2
		GetClientCertificate: a.certs.clientCert,
		// Цепочка и идентичность — в VerifyConnection (как у reverse-коннектора).
		InsecureSkipVerify: true, // #nosec G402 -- см. VerifyConnection
		VerifyConnection:   func(cs tls.ConnectionState) error { return pki.VerifyServerPeer(a.caPool)(cs) },
	}
	if net.ParseIP(gw.Hostname()) == nil {
		cfg.ServerName = gw.Hostname()
	}
	tr := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       cfg,
		DisableKeepAlives:     true,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: tcpKeepAlive}).DialContext,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: updateHeaderTO,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func fetchPackage(ctx context.Context, c *http.Client, gw *url.URL, version, name, dst string, limit int64) error {
	u := *gw
	u.Path = path.Join("/_agent_gw/packages", version, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("gateway: %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway: %s: status %d", name, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return fmt.Errorf("gateway: %s: too large", name)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- свежий temp-каталог, имя из release-раскладки
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if err == nil && n > limit {
		err = fmt.Errorf("gateway: %s: too large", name)
	}
	if err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

type updateResult struct {
	Version    string `json:"version"`
	OK         bool   `json:"ok"`
	RolledBack bool   `json:"rolled_back"`
	Error      string `json:"error"`
	At         string `json:"at"`
}

// handleUpdateStatus — GET /_agent/update: idle | downloading | staged | applied | failed (+ result.json apply).
func (a *Agent) handleUpdateStatus(w http.ResponseWriter, _ *http.Request) {
	u := &a.upd
	u.mu.Lock()
	busy, target, failed := u.busy, u.target, u.failed
	u.mu.Unlock()

	rep := updateReply{State: UpdateIdle}
	var res *updateResult
	if b, err := os.ReadFile(filepath.Join(a.updatesDir(), resultName)); err == nil { // #nosec G304 -- путь из data_dir и константы
		var r updateResult
		if json.Unmarshal(b, &r) == nil {
			res = &r
		}
	}
	switch p, _ := a.pendingRequest(); {
	case busy:
		rep.State, rep.Version = UpdateDownloading, target
	case failed != "":
		rep.State, rep.Version, rep.Error = UpdateFailed, target, failed
	case p != nil:
		rep.State, rep.Version = UpdateStaged, p.Version
	case res != nil && res.OK:
		rep.State, rep.Version = UpdateApplied, res.Version
	case res != nil:
		rep.State, rep.Version, rep.Error = UpdateFailed, res.Version, res.Error
	}
	if res != nil {
		rep.Result = res
	}
	writeUpdateJSON(w, http.StatusOK, rep)
}
