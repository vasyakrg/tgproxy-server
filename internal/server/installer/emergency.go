package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/oklog/ulid/v2"

	"github.com/vasyakrg/tgproxy-server/internal/deployhelper"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// JobKindEmergency — тип задачи аварийного обновления агента по SSH (install_jobs.kind).
const JobKindEmergency = "emergency_update"

// Ошибки аварийного обновления.
var (
	// ErrNoSSHTarget — у агента не сохранена SSH-цель (reverse/enrollment-агент или установка без истории).
	ErrNoSSHTarget = errors.New("installer: у агента нет сохранённой SSH-цели")
	// ErrBadVersion — версия пакета не semver (1.2.3[-rc1]).
	ErrBadVersion = errors.New("installer: некорректная версия пакета")
	// ErrNoPackage — релиз нужной версии отсутствует в кэше загрузок сервера.
	ErrNoPackage = errors.New("installer: релиз не найден в кэше загрузок")
	// ErrEmergencyBusy — для агента уже выполняется аварийное обновление.
	ErrEmergencyBusy = errors.New("installer: для агента уже выполняется аварийное обновление")
)

// Ключи шагов аварийного обновления.
const (
	stepEmSSH     = "ssh"
	stepEmUpload  = "upload"
	stepEmStage   = "stage"
	stepEmInstall = "install"
	stepEmRestart = "restart"
	stepEmCheck   = "check"
)

func (c *Config) incoming() string {
	if c.remoteIncoming != "" {
		return c.remoteIncoming
	}
	return incomingDir
}

// EmergencyUpdate обновляет агента по SSH, когда штатный путь (POST /_agent/update по mTLS)
// недоступен. Подключение — только под tgproxy-deploy серверным ключом и с закреплённым ключом
// хоста; админских кредов нет. Релиз проверяется на сервере (minisign + sha256 + min_version),
// затем SFTP в каталог приёма и `deploy-helper stage` → `install` → `unit restart`; хелпер
// ПОВТОРНО проверяет подпись встроенными ключами агента. Возвращает id задачи (kind
// emergency_update, события и лог — как у установки).
func (i *Installer) EmergencyUpdate(ctx context.Context, agentID, version string) (string, error) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if err := validateName(agentID); err != nil {
		return "", err
	}
	if !stageVersionRe.MatchString(version) {
		return "", fmt.Errorf("%w %q", ErrBadVersion, version)
	}
	ag, err := i.cfg.Store.Agents().Get(ctx, agentID)
	if err != nil {
		return "", fmt.Errorf("installer: агент %q: %w", agentID, err)
	}
	if ag.SSHHost == "" || ag.SSHPort == 0 {
		return "", ErrNoSSHTarget
	}
	target := Target{Host: ag.SSHHost, Port: ag.SSHPort, User: deployUser}
	if err := target.validate(); err != nil {
		return "", err
	}
	// Ключ хоста обязан быть закреплён при установке: TOFU здесь не допускается.
	if _, err := i.cfg.Store.HostKeys().Get(ctx, target.Addr()); errors.Is(err, store.ErrNotFound) {
		return "", &ErrHostKeyUnknown{}
	} else if err != nil {
		return "", fmt.Errorf("installer: чтение ключа хоста: %w", err)
	}
	pkgs, err := findPackages(i.cfg.PackagesDir, version)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoPackage, err)
	}

	i.mu.Lock()
	if _, taken := i.busy[agentID]; taken {
		i.mu.Unlock()
		return "", ErrEmergencyBusy
	}
	i.busy[agentID] = struct{}{}
	i.mu.Unlock()
	release := func() {
		i.mu.Lock()
		delete(i.busy, agentID)
		i.mu.Unlock()
	}

	id := ulid.Make().String()
	if err := i.cfg.Store.InstallJobs().Create(ctx, store.InstallJob{
		ID: id, AgentID: agentID, Host: target.Addr(), Kind: JobKindEmergency, State: store.InstallRunning,
	}); err != nil {
		release()
		return "", fmt.Errorf("installer: создание задачи: %w", err)
	}

	r := &run{
		i: i, id: id, emergency: true, req: Request{Name: agentID}, target: target, pkgs: pkgs, healthURL: ag.URL,
		auth: Auth{Signer: i.cfg.ServerKey},
	}
	r.policy = HostKeyPolicy{Repo: i.cfg.Store.HostKeys(), AgentID: agentID, Alerter: i.cfg.Alerter, Timeout: i.cfg.DialTimeout}
	i.launch(r, nil, release)
	return id, nil
}

func (r *run) emergencySteps() []step {
	return []step{
		{key: stepEmSSH, label: fixedLabel("SSH-подключение под " + deployUser + ", ключ хоста сверен"), do: (*run).doEmSSH},
		{key: stepEmUpload, label: func(r *run) string {
			return "Проверка подписи и загрузка пакета tgproxy " + r.pkgs.version
		},
			do: (*run).doEmUpload, undo: (*run).undoEmUpload},
		{key: stepEmStage, label: fixedLabel("Перенос в доверенный кэш хоста (deploy-helper stage)"), do: (*run).doEmStage},
		{key: stepEmInstall, label: func(r *run) string {
			return "Установка пакета " + r.pkgs.version + " (deploy-helper install)"
		},
			do: (*run).doEmInstall},
		{key: stepEmRestart, label: fixedLabel("Перезапуск tgproxy-agent"), do: (*run).doEmRestart},
		{key: stepEmCheck, label: fixedLabel("Проверка mTLS и доступа к Telegram"), do: (*run).doEmCheck},
	}
}

// kind — тип задачи для логов.
func (r *run) kind() string {
	if r.emergency {
		return JobKindEmergency
	}
	return jobKindInstall
}

func (r *run) doneText() string {
	if r.emergency {
		return "Агент " + r.req.Name + " обновлён до " + r.pkgs.version + " (аварийное обновление по SSH)"
	}
	return "Агент " + r.req.Name + " установлен и включён в балансировку"
}

// failState — итоговое состояние и текст неуспеха.
func (r *run) failState(rbErr error) (state, final string) {
	if r.emergency {
		if !r.hostTouched {
			return store.InstallRolledBack, "Аварийное обновление отменено, на хосте ничего не изменено"
		}
		return store.InstallFailed, "Аварийное обновление не выполнено — проверьте хост вручную"
	}
	if rbErr != nil {
		return store.InstallFailed, "Установка отменена, откат выполнен не полностью — проверьте хост вручную"
	}
	return store.InstallRolledBack, "Установка отменена, выполненные шаги откатены"
}

// ---- шаг 1: SSH под tgproxy-deploy ----

func (r *run) doEmSSH(ctx context.Context) error {
	cl, err := Dial(ctx, r.target, r.auth, r.policy)
	if err != nil {
		return fmt.Errorf("вход под %s по серверному ключу: %w", deployUser, err)
	}
	r.deploy = newRemote(cl, deployUser, r.auth, r.cfg().incoming())
	if k, gerr := r.cfg().Store.HostKeys().Get(ctx, r.target.Addr()); gerr == nil {
		r.logf("info", "Подключено к %s, ключ хоста совпал с закреплённым: %s", r.target.Addr(), k.Fingerprint)
	}
	return nil
}

// ---- шаг 2: проверка подписи на сервере и загрузка в incoming ----

func (r *run) doEmUpload(ctx context.Context) error {
	local, _, checksums, sig, want, err := r.verifiedRelease(ctx, r.deploy)
	if err != nil {
		return err
	}
	base, err := r.deploy.newTmpPath()
	if err != nil {
		return err
	}
	r.incomingBase = base      // для undo: до первой записи на хост
	src, err := os.Open(local) // #nosec G304 -- файл из кэша загрузок, имя прошло pkgNameRe
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	sum, err := r.deploy.UploadTo(ctx, base, src)
	if err != nil {
		return err
	}
	if sum != want {
		return errors.New("пакет изменился после проверки подписи")
	}
	if _, err := r.deploy.UploadTo(ctx, base+deployhelper.ChecksumsSuffix, bytes.NewReader(checksums)); err != nil {
		return err
	}
	if _, err := r.deploy.UploadTo(ctx, base+deployhelper.SigSuffix, bytes.NewReader(sig)); err != nil {
		return err
	}
	if err := r.checkRemoteSum(ctx, r.deploy, base, want); err != nil {
		return err
	}
	r.logf("info", "Релиз загружен в %s (deb, .checksums, .minisig), sha256 совпал", r.cfg().incoming())
	return nil
}

// undoEmUpload убирает свои файлы из incoming (хелпер удаляет их сам только при успешном stage).
func (r *run) undoEmUpload(ctx context.Context) (bool, error) {
	if r.incomingBase == "" || r.deploy == nil {
		return false, nil
	}
	base := r.incomingBase
	r.incomingBase = ""
	_, err := r.deploy.Run(context.WithoutCancel(ctx), cmdRemoveTmp(base, base+deployhelper.ChecksumsSuffix, base+deployhelper.SigSuffix))
	return err == nil, err
}

// ---- шаги 3–4: stage и install через deploy-helper ----

func (r *run) doEmStage(ctx context.Context) error {
	r.hostTouched = true
	if _, err := r.exec(ctx, r.deploy, cmdHelperStage(r.incomingBase, r.pkgs.version)); err != nil {
		return err
	}
	r.incomingBase = "" // хелпер удалил свои входные файлы
	return nil
}

func (r *run) doEmInstall(ctx context.Context) error {
	_, err := r.exec(ctx, r.deploy, cmdHelperInstall(r.pkgs.version))
	return err
}

// ---- шаг 5: перезапуск ----

func (r *run) doEmRestart(ctx context.Context) error {
	if _, err := r.exec(ctx, r.deploy, cmdHelperUnit("restart")); err != nil {
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

// ---- шаг 6: health ----

func (r *run) doEmCheck(ctx context.Context) error {
	if r.healthURL == "" {
		r.logf("warn", "У агента нет адреса для mTLS-проверки: шаг пропущен")
		return nil
	}
	return r.poll(ctx, "агент не прошёл проверку mTLS/Telegram", func() error {
		return r.cfg().Health.Check(ctx, r.healthURL, r.req.Name)
	})
}
