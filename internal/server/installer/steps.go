package installer

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Ключи шагов мастера (docs/design/AgentAdd.dc.html).
const (
	stepSSH     = "ssh"
	stepUpload  = "upload"
	stepInstall = "install"
	stepCert    = "cert"
	stepStart   = "start"
	stepCheck   = "check"
	stepBalance = "balance"
)

var archRe = regexp.MustCompile(`^[a-z0-9]{2,16}$`)

type step struct {
	key   string
	label func(*run) string
	do    func(*run, context.Context) error
	// undo откатывает то, что шаг успел сделать; false — откатывать было нечего.
	undo func(*run, context.Context) (bool, error)
	// after вызывается после успеха шага.
	after func(*run)
}

func fixedLabel(s string) func(*run) string { return func(*run) string { return s } }

func (r *run) steps() []step {
	return []step{
		{key: stepSSH, label: fixedLabel("SSH-подключение, ключ хоста закреплён"), do: (*run).doSSH, undo: (*run).undoSSH},
		{key: stepUpload, label: func(r *run) string { return "Загрузка пакета tgproxy " + r.pkgs.version },
			do: (*run).doUpload, undo: (*run).undoUpload},
		{key: stepInstall, label: fixedLabel("Установка пакета и пользователей"), do: (*run).doInstall, undo: (*run).undoInstall},
		{key: stepCert, label: fixedLabel("Выпуск сертификата агента"), do: (*run).doCert, undo: (*run).undoCert,
			after: (*run).releaseAdmin}, // дальше права администратора не нужны
		{key: stepStart, label: fixedLabel("Запуск tgproxy-agent"), do: (*run).doStart, undo: (*run).undoStart},
		{key: stepCheck, label: fixedLabel("Проверка mTLS и доступа к Telegram"), do: (*run).doCheck},
		{key: stepBalance, label: fixedLabel("Включение в балансировку"), do: (*run).doBalance, undo: (*run).undoBalance},
	}
}

// run — состояние выполняющейся задачи. Креды — только здесь, в памяти.
type run struct {
	i      *Installer
	id     string
	req    Request // без секретов
	target Target
	policy HostKeyPolicy
	pkgs   pkgSet
	lj     *liveJob

	auth   Auth // секреты администратора; Zero после шага «Выпуск сертификата»
	admin  *Remote
	deploy *Remote

	curStep string

	// Что реально сделано — для отката.
	debTmp            string
	pkgWasInstalled   bool
	pkgInstallStarted bool
	userCreated       bool
	keyWritten        bool
	sudoersWritten    bool
	tlsTouched        bool
	certSerial        string
	certNotAfter      time.Time
	unitEnabled       bool
	agentCreated      bool
}

func (r *run) cfg() *Config { return &r.i.cfg }

func (r *run) emit(kind, status, level, msg string) {
	r.lj.emit(Event{JobID: r.id, Kind: kind, Step: r.curStep, Status: status, Level: level, Message: msg})
}

func (r *run) logf(level, format string, a ...any) {
	r.emit(EventLog, "", level, fmt.Sprintf(format, a...))
}

func (r *run) stepEvent(st step, status string) {
	r.lj.emit(Event{JobID: r.id, Kind: EventStep, Step: st.key, Status: status, Message: st.label(r)})
}

// exec выполняет команду, пишет её и вывод в журнал (вывод проходит scrub).
func (r *run) exec(ctx context.Context, rem *Remote, c Command) (string, error) {
	return r.execOpt(ctx, rem, c, true)
}

func (r *run) execOpt(ctx context.Context, rem *Remote, c Command, logOut bool) (string, error) {
	r.logf("info", "$ %s", c)
	out, err := rem.Run(ctx, c)
	if logOut {
		r.logOutput(out)
	}
	return out, err
}

func (r *run) logOutput(out string) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	const maxLines = 30
	for k, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if k >= maxLines {
			r.logf("info", "… (ещё %d строк)", len(lines)-k)
			return
		}
		r.logf("info", "%s", l)
	}
}

// releaseAdmin закрывает соединение администратора и затирает его креды.
func (r *run) releaseAdmin() {
	if r.admin != nil {
		r.admin.Close()
		r.admin = nil
	}
	r.auth.Zero()
	r.logf("info", "Креды администратора удалены из памяти задачи")
}

func (r *run) cleanup() {
	r.releaseAdminQuiet()
	if r.deploy != nil {
		r.deploy.Close()
		r.deploy = nil
	}
}

func (r *run) releaseAdminQuiet() {
	if r.admin != nil {
		r.admin.Close()
		r.admin = nil
	}
	r.auth.Zero()
}

func (r *run) execute(base context.Context) {
	defer r.cleanup()
	steps := r.steps()
	failedAt := -1
	var failErr error
	for idx, st := range steps {
		r.curStep = st.key
		r.stepEvent(st, StepRunning)
		ctx, cancel := context.WithTimeout(base, r.cfg().StepTimeout)
		err := st.do(r, ctx)
		cancel()
		if err != nil {
			r.stepEvent(st, StepFailed)
			failedAt, failErr = idx, err
			break
		}
		r.stepEvent(st, StepOK)
		if st.after != nil {
			st.after(r)
		}
	}
	repo := r.i.cfg.Store.InstallJobs()
	bg := context.WithoutCancel(base)
	if failedAt < 0 {
		r.curStep = ""
		_ = repo.SetState(bg, r.id, store.InstallDone, "")
		r.emit(EventDone, "", "info", "Агент "+r.req.Name+" установлен и включён в балансировку")
		r.i.log.Info("install job done", "job", r.id, "agent", r.req.Name)
		return
	}
	msg := r.lj.scrub(failErr.Error())
	r.curStep = steps[failedAt].key
	r.logf("error", "Шаг «%s» не выполнен: %s", steps[failedAt].label(r), msg)
	rbErr := r.rollback(bg, steps, failedAt)
	r.curStep = ""
	state := store.InstallRolledBack
	final := "Установка отменена, выполненные шаги откатены"
	if rbErr != nil {
		state = store.InstallFailed
		final = "Установка отменена, откат выполнен не полностью — проверьте хост вручную"
	}
	_ = repo.SetState(bg, r.id, state, msg)
	r.emit(EventError, "", "error", final+": "+msg)
	r.i.log.Warn("install job failed", "job", r.id, "agent", r.req.Name, "state", state)
}

// rollback откатывает шаги failedAt..0 в обратном порядке.
func (r *run) rollback(parent context.Context, steps []step, failedAt int) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	var errs []error
	r.curStep = ""
	r.logf("warn", "Откат выполненных шагов")
	for k := failedAt; k >= 0; k-- {
		st := steps[k]
		if st.undo == nil {
			continue
		}
		r.curStep = st.key
		did, err := st.undo(r, ctx)
		if err != nil {
			errs = append(errs, err)
			r.logf("warn", "Откат шага «%s»: %s", st.label(r), r.lj.scrub(err.Error()))
		}
		if did {
			r.stepEvent(st, StepRolledBack)
		}
	}
	return errors.Join(errs...)
}

// ---- шаг 1: SSH-подключение ----

func (r *run) doSSH(ctx context.Context) error {
	if err := r.ensurePinned(ctx); err != nil {
		return err
	}
	cl, err := Dial(ctx, r.target, r.auth, r.policy)
	if err != nil {
		return err
	}
	r.admin = newRemote(cl, r.target.User, r.auth, r.cfg().RemoteTmpDir)
	if k, gerr := r.cfg().Store.HostKeys().Get(ctx, r.target.Addr()); gerr == nil {
		r.logf("info", "Подключено к %s, ключ хоста закреплён: %s", r.target.Addr(), k.Fingerprint)
	}
	return nil
}

// ensurePinned закрепляет ключ хоста (TOFU), если он ещё не закреплён: отпечаток
// должен совпасть с подтверждённым администратором.
func (r *run) ensurePinned(ctx context.Context) error {
	repo := r.cfg().Store.HostKeys()
	addr := r.target.Addr()
	if _, err := repo.Get(ctx, addr); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("чтение ключа хоста: %w", err)
	}
	if r.req.ConfirmedFingerprint == "" {
		return &ErrHostKeyUnknown{}
	}
	info, err := Probe(ctx, r.target, r.cfg().DialTimeout)
	if err != nil {
		return err
	}
	if info.Fingerprint != r.req.ConfirmedFingerprint {
		if a := r.cfg().Alerter; a != nil {
			a.HostKeyMismatch(context.WithoutCancel(ctx), r.req.Name, addr)
		}
		return fmt.Errorf("%w: подтверждён %s, хост предъявил %s", ErrHostKeyMismatch, r.req.ConfirmedFingerprint, info.Fingerprint)
	}
	if err := repo.Put(ctx, store.HostKey{Host: addr, Algo: info.Algo, Fingerprint: info.Fingerprint, PublicKey: info.PublicKey}); err != nil {
		return fmt.Errorf("сохранение ключа хоста: %w", err)
	}
	r.logf("info", "Ключ хоста закреплён: %s", info.Label())
	return nil
}

func (r *run) undoSSH(_ context.Context) (bool, error) { return false, nil }

// ---- шаг 2: загрузка пакета ----

func hashFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- файл из кэша пакетов, имя прошло pkgNameRe
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (r *run) doUpload(ctx context.Context) error {
	out, err := r.exec(ctx, r.admin, cmdDpkgArch())
	if err != nil {
		return err
	}
	arch := strings.TrimSpace(out)
	if !archRe.MatchString(arch) {
		return fmt.Errorf("неожиданная архитектура хоста %q", arch)
	}
	local, name, ok := r.pkgs.path(r.cfg().PackagesDir, arch)
	if !ok {
		return fmt.Errorf("в кэше нет пакета tgproxy %s для архитектуры %s", r.pkgs.version, arch)
	}
	want, err := hashFile(local)
	if err != nil {
		return fmt.Errorf("чтение пакета: %w", err)
	}
	if f := r.cfg().ExpectedSHA256; f != nil {
		exp, known := f(name)
		if !known || !strings.EqualFold(exp, want) {
			return fmt.Errorf("sha256 пакета %s не совпадает с подписанным списком", name)
		}
	}
	r.logf("info", "Пакет %s, sha256 %s", name, want)
	src, err := os.Open(local) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	tmp, sum, err := r.admin.Upload(ctx, src)
	if err != nil {
		return err
	}
	r.debTmp = tmp
	if sum != want {
		return errors.New("пакет изменился во время загрузки")
	}
	out, err = r.exec(ctx, r.admin, cmdSHA256(tmp))
	if err != nil {
		return err
	}
	if got, _, _ := strings.Cut(strings.TrimSpace(out), " "); got != want {
		return fmt.Errorf("sha256 на хосте %q не совпадает с локальным %q", got, want)
	}
	r.logf("info", "Пакет загружен на хост, sha256 совпал")
	return nil
}

func (r *run) undoUpload(ctx context.Context) (bool, error) {
	return r.removeDebTmp(ctx)
}

func (r *run) removeDebTmp(ctx context.Context) (bool, error) {
	if r.debTmp == "" || r.admin == nil {
		return false, nil
	}
	tmp := r.debTmp
	r.debTmp = ""
	_, err := r.admin.Run(context.WithoutCancel(ctx), cmdRemoveTmp(tmp))
	return err == nil, err
}

// ---- шаг 3: пакет и пользователи ----

func isExit(err error) bool {
	var ce *CommandError
	return errors.As(err, &ce)
}

func (r *run) doInstall(ctx context.Context) error {
	a := r.admin
	out, err := r.exec(ctx, a, cmdPkgStatus())
	switch {
	case err == nil:
		r.pkgWasInstalled = strings.HasPrefix(strings.TrimSpace(out), "ii")
	case isExit(err):
		r.pkgWasInstalled = false
	default:
		return err
	}
	r.pkgInstallStarted = true
	// Первичная установка: хелпера ещё нет, пакет ставит администратор (он уже доверенный root).
	if _, err := r.exec(ctx, a, cmdDpkgInstall(r.debTmp)); err != nil {
		return err
	}
	_, _ = r.removeDebTmp(ctx)
	switch _, err := r.exec(ctx, a, cmdIDUser()); {
	case err == nil:
		r.logf("info", "Пользователь %s уже существует", deployUser)
	case isExit(err):
		r.userCreated = true
		if _, err := r.exec(ctx, a, cmdUserAdd()); err != nil {
			return err
		}
	default:
		return err
	}
	// Каталоги приёма и кэша пакетов (создаёт и postinst; здесь — для пользователя, появившегося позже).
	if _, err := r.exec(ctx, a, cmdInstallDir("0755", "root", "root", packagesDir)); err != nil {
		return err
	}
	if _, err := r.exec(ctx, a, cmdInstallDir("0730", "root", deployUser, incomingDir)); err != nil {
		return err
	}
	sshDir := deployHome + "/.ssh"
	if _, err := r.exec(ctx, a, cmdInstallDir("0700", deployUser, deployUser, sshDir)); err != nil {
		return err
	}
	r.keyWritten = true
	if err := r.put(ctx, a, authorizedKeyLine(r.cfg().ServerKey.PublicKey()), "0600", deployUser, deployUser, sshDir+"/authorized_keys", nil); err != nil {
		return err
	}
	r.sudoersWritten = true
	if err := r.put(ctx, a, RenderSudoers(), "0440", "root", "root", sudoersPath, cmdVisudoCheck); err != nil {
		return err
	}
	r.logf("info", "Пользователь %s настроен, sudoers проверен visudo", deployUser)
	return nil
}

// put — Remote.PutFile с записью команд в журнал.
func (r *run) put(ctx context.Context, rem *Remote, data []byte, mode, owner, group, dst string, check func(string) Command) error {
	r.logf("info", "Запись %s (%s %s:%s)", dst, mode, owner, group)
	return rem.PutFile(ctx, data, mode, owner, group, dst, check)
}

func (r *run) undoInstall(ctx context.Context) (bool, error) {
	if !r.pkgInstallStarted && !r.keyWritten && !r.sudoersWritten {
		return false, nil
	}
	if r.admin == nil {
		left := []string{"sudoers " + sudoersPath, "ключ в authorized_keys пользователя " + deployUser}
		if r.userCreated {
			left = append(left, "пользователь "+deployUser+" (`userdel -r "+deployUser+"`)")
		}
		if r.pkgInstallStarted && !r.pkgWasInstalled {
			left = append(left, "пакет tgproxy (`dpkg -r tgproxy`)")
		}
		r.logf("warn", "Остались на хосте (креды администратора уже удалены): %s", strings.Join(left, "; "))
		return false, nil
	}
	var errs []error
	did := false
	step := func(c Command) {
		did = true
		if _, err := r.exec(ctx, r.admin, c); err != nil {
			errs = append(errs, err)
		}
	}
	if r.sudoersWritten {
		step(cmdRemoveRoot(sudoersPath))
	}
	if r.userCreated {
		step(cmdUserDel())
	}
	if r.pkgInstallStarted && !r.pkgWasInstalled {
		step(cmdDpkgRemove())
	}
	return did, errors.Join(errs...)
}

// ---- шаг 4: сертификат агента ----

func (r *run) doCert(ctx context.Context) error {
	a := r.admin
	r.tlsTouched = true
	if _, err := r.exec(ctx, a, cmdInstallDir("0750", "root", agentGroup, tlsDir)); err != nil {
		return err
	}
	csr, err := r.execOpt(ctx, a, cmdAgentCSR(r.req.Name), false)
	if err != nil {
		return err
	}
	if blk, _ := pem.Decode([]byte(csr)); blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return errors.New("агент вернул не CSR в PEM")
	}
	certPEM, serial, err := r.cfg().CA.SignAgentCSR(ctx, []byte(csr), r.req.Name, 0)
	if err != nil {
		return fmt.Errorf("выпуск сертификата: %w", err)
	}
	r.certSerial = serial
	if blk, _ := pem.Decode(certPEM); blk != nil {
		if c, perr := x509.ParseCertificate(blk.Bytes); perr == nil {
			r.certNotAfter = c.NotAfter
		}
	}
	r.logf("info", "Сертификат выпущен, серийник %s", serial)
	conf, err := RenderAgentConfig(r.req.AgentPort, r.cfg().AllowedClientSAN)
	if err != nil {
		return err
	}
	if err := r.put(ctx, a, certPEM, "0640", "root", agentGroup, agentCertPath, nil); err != nil {
		return err
	}
	if err := r.put(ctx, a, r.cfg().CA.CertPEM(), "0640", "root", agentGroup, caCertPath, nil); err != nil {
		return err
	}
	if err := r.put(ctx, a, conf, "0640", "root", agentGroup, agentConfPath, nil); err != nil {
		return err
	}
	_, err = r.exec(ctx, a, cmdConfigValidate())
	return err
}

func (r *run) undoCert(ctx context.Context) (bool, error) {
	did := false
	var errs []error
	if r.certSerial != "" {
		did = true
		d := store.DeniedCert{Serial: r.certSerial, AgentID: r.req.Name, Reason: "install rolled back", NotAfter: r.certNotAfter}
		if d.NotAfter.IsZero() {
			d.NotAfter = time.Now().Add(91 * 24 * time.Hour)
		}
		if err := r.cfg().Store.Certs().Deny(ctx, d); err != nil && !errors.Is(err, store.ErrConflict) {
			errs = append(errs, fmt.Errorf("отзыв сертификата: %w", err))
		} else {
			r.logf("info", "Сертификат %s отозван (denylist)", r.certSerial)
		}
	}
	if r.tlsTouched {
		if r.admin == nil {
			r.logf("warn", "Файлы %s остались на хосте (креды администратора уже удалены)", tlsDir)
		} else {
			did = true
			if _, err := r.exec(ctx, r.admin, cmdRemoveRoot(agentKeyPath, agentCertPath, caCertPath)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return did, errors.Join(errs...)
}

// ---- шаг 5: запуск ----

func (r *run) doStart(ctx context.Context) error {
	cl, err := Dial(ctx, Target{Host: r.target.Host, Port: r.target.Port, User: deployUser},
		Auth{Signer: r.cfg().ServerKey}, r.policy)
	if err != nil {
		return fmt.Errorf("вход под %s по серверному ключу: %w", deployUser, err)
	}
	r.deploy = newRemote(cl, deployUser, Auth{Signer: r.cfg().ServerKey}, r.cfg().RemoteTmpDir)
	r.unitEnabled = true
	if _, err := r.exec(ctx, r.deploy, cmdHelperUnit("enable")); err != nil {
		return err
	}
	return r.poll(ctx, "юнит "+agentUnit+" не active", func() error {
		out, err := r.deploy.Run(ctx, cmdHelperUnit("is-active"))
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "active" {
			return fmt.Errorf("статус %q", strings.TrimSpace(out))
		}
		return nil
	})
}

func (r *run) undoStart(ctx context.Context) (bool, error) {
	if !r.unitEnabled || r.deploy == nil {
		return false, nil
	}
	_, err := r.exec(ctx, r.deploy, cmdHelperUnit("disable"))
	return err == nil, err
}

// poll повторяет f до успеха или HealthTimeout.
func (r *run) poll(ctx context.Context, what string, f func() error) error {
	deadline := time.Now().Add(r.cfg().HealthTimeout)
	var last error
	for {
		if last = f(); last == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s за %s: %w", what, r.cfg().HealthTimeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.cfg().HealthInterval):
		}
	}
}

// ---- шаг 6: проверка ----

func (r *run) agentURL() string {
	return "https://" + net.JoinHostPort(r.target.Host, strconv.Itoa(r.req.AgentPort))
}

func (r *run) doCheck(ctx context.Context) error {
	url := r.agentURL()
	return r.poll(ctx, "агент не прошёл проверку mTLS/Telegram", func() error {
		return r.cfg().Health.Check(ctx, url, r.req.Name)
	})
}

// ---- шаг 7: балансировка ----

func (r *run) doBalance(ctx context.Context) error {
	st := r.cfg().Store
	if _, err := st.Agents().Create(ctx, store.Agent{
		ID: r.req.Name, Name: r.req.Name, URL: r.agentURL(), Mode: store.ModeDial, Weight: r.req.Weight,
	}); err != nil {
		return fmt.Errorf("добавление агента: %w", err)
	}
	r.agentCreated = true
	_ = st.InstallJobs().SetAgent(ctx, r.id, r.req.Name)
	if k, err := st.HostKeys().Get(ctx, r.target.Addr()); err == nil {
		k.AgentID = r.req.Name
		_ = st.HostKeys().Put(ctx, k)
	}
	r.logf("info", "Агент %s добавлен в балансировку (вес %d)", r.req.Name, r.req.Weight)
	return nil
}

func (r *run) undoBalance(ctx context.Context) (bool, error) {
	if !r.agentCreated {
		return false, nil
	}
	err := r.cfg().Store.Agents().Delete(ctx, r.req.Name)
	return err == nil, err
}
