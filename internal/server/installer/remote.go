package installer

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
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Фиксированные имена и пути на целевом хосте (architecture §8, §12).
const (
	deployUser     = "tgproxy-deploy"
	deployHome     = "/var/lib/tgproxy-deploy"
	packagesDir    = "/var/lib/tgproxy/packages"
	incomingDir    = "/var/lib/tgproxy-incoming"
	tlsDir         = "/etc/tgproxy/tls"
	agentKeyPath   = tlsDir + "/agent.key"
	agentCertPath  = tlsDir + "/agent.crt"
	caCertPath     = tlsDir + "/ca.crt"
	agentConfPath  = "/etc/tgproxy/agent.yaml"
	sudoersPath    = "/etc/sudoers.d/" + deployUser
	agentUnit      = "tgproxy-agent"
	agentGroup     = "tgproxy"
	maxOutputBytes = 64 << 10
)

// Command — одна фиксированная команда на удалённом хосте. Значения полей
// недоступны снаружи пакета: собирать команду можно только конструкторами cmd*,
// пользовательский ввод в argv не попадает (имя агента, хост и порт — только в
// конфиг/БД; в команды входят лишь константы и сгенерированные пути).
type Command struct {
	argv []string
	sudo bool
}

// String — командная строка с экранированием каждого аргумента.
func (c Command) String() string {
	q := make([]string, len(c.argv))
	for i, a := range c.argv {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

// shellQuote экранирует аргумент для POSIX sh: безопасные строки — как есть,
// остальные в одинарных кавычках.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		alnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !alnum && !strings.ContainsRune("@%_+=:,./-", r) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fixed(sudo bool, argv ...string) Command { return Command{argv: argv, sudo: sudo} }

// Конструкторы команд. Пути-аргументы проверяются absPathRe (защита от инъекции
// при ошибке вызывающего кода).
func cmdDpkgArch() Command { return fixed(false, "/usr/bin/dpkg", "--print-architecture") }
func cmdPkgStatus() Command {
	return fixed(false, "/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}", "tgproxy")
}
func cmdIDUser() Command { return fixed(false, "/usr/bin/id", "-u", deployUser) }
func cmdSHA256(path string) Command {
	mustPath(path)
	return fixed(false, "/usr/bin/sha256sum", path)
}
func cmdRemoveTmp(path string) Command {
	mustPath(path)
	return fixed(false, "/usr/bin/rm", "-f", path)
}
func cmdRemoveRoot(paths ...string) Command {
	for _, p := range paths {
		mustPath(p)
	}
	return fixed(true, append([]string{"/usr/bin/rm", "-f"}, paths...)...)
}
func cmdVisudoCheck(path string) Command {
	mustPath(path)
	return fixed(true, "/usr/sbin/visudo", "-cf", path)
}
func cmdDpkgInstall(path string) Command {
	mustPath(path)
	return fixed(true, "/usr/bin/dpkg", "-i", path)
}
func cmdDpkgRemove() Command { return fixed(true, "/usr/bin/dpkg", "-r", "tgproxy") }
func cmdUserAdd() Command {
	return fixed(true, "/usr/sbin/useradd", "--system", "--create-home", "--home-dir", deployHome,
		"--shell", "/bin/sh", "--user-group", "--password", "*", deployUser)
}
func cmdUserDel() Command { return fixed(true, "/usr/sbin/userdel", "--remove", deployUser) }
func cmdInstallDir(mode, owner, group, path string) Command {
	mustPath(path)
	return fixed(true, "/usr/bin/install", "-d", "-m", mode, "-o", owner, "-g", group, path)
}

// cmdInstallFile копирует src (временный файл администратора) в dst с владельцем и режимом.
func cmdInstallFile(mode, owner, group, src, dst string) Command {
	mustPath(src)
	mustPath(dst)
	return fixed(true, "/usr/bin/install", "-D", "-m", mode, "-o", owner, "-g", group, src, dst)
}

// cmdAgentCSR: ключ P-256 создаётся на агенте (0600, владелец tgproxy), в stdout уходит CSR.
// id — уже проверенный validateName slug; --force нужен при переустановке поверх старого ключа.
func cmdAgentCSR(id string) Command {
	return fixed(true, "/usr/bin/tgproxy", "agent", "csr", "--key", agentKeyPath, "--id", id, "--out", "-", "--force")
}
func cmdConfigValidate() Command {
	return fixed(true, "/usr/bin/tgproxy", "config", "validate", "--mode", "agent", "-c", agentConfPath)
}

// cmdHelperUnit — управление tgproxy-agent через deploy-helper (единственное, что разрешает sudoers).
func cmdHelperUnit(verb string) Command {
	return fixed(true, "/usr/bin/tgproxy", "deploy-helper", "unit", verb)
}

func mustPath(p string) {
	if !absPathRe.MatchString(p) || strings.Contains(p, "..") {
		panic("installer: unsafe remote path " + p) // программная ошибка, не пользовательский ввод
	}
}

// CommandError — команда завершилась с ненулевым кодом.
type CommandError struct {
	Cmd    string
	Code   int
	Stderr string
}

func (e *CommandError) Error() string {
	msg := fmt.Sprintf("команда %q завершилась с кодом %d", e.Cmd, e.Code)
	if e.Stderr != "" {
		msg += ": " + strings.TrimSpace(e.Stderr)
	}
	return msg
}

// capBuffer хранит не более max байт (остальное отбрасывается).
type capBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// Remote — подключение к хосту. Команды идут от имени User; если он не root,
// привилегированные — через sudo (-n для ключей, -S с паролем из stdin для пароля).
type Remote struct {
	client *ssh.Client
	root   bool
	sudoPW []byte // ссылка на буфер задачи: обнуляется вместе с кредами
	tmpDir string
	sftpCl *sftp.Client
}

func newRemote(client *ssh.Client, user string, auth Auth, tmpDir string) *Remote {
	r := &Remote{client: client, root: user == "root", tmpDir: tmpDir}
	if len(auth.PrivateKeyPEM) == 0 && auth.Signer == nil {
		r.sudoPW = auth.Password
	}
	return r
}

// Close закрывает SFTP и SSH.
func (r *Remote) Close() {
	if r == nil {
		return
	}
	if r.sftpCl != nil {
		_ = r.sftpCl.Close()
		r.sftpCl = nil
	}
	if r.client != nil {
		_ = r.client.Close()
		r.client = nil
	}
}

func (r *Remote) wire(c Command) (line string, stdin []byte) {
	line = c.String()
	if !c.sudo || r.root {
		return line, nil
	}
	if len(r.sudoPW) > 0 {
		return "sudo -S -p '' " + line, append(append([]byte(nil), r.sudoPW...), '\n')
	}
	return "sudo -n " + line, nil
}

// Run выполняет команду и возвращает stdout. Ненулевой код → *CommandError.
func (r *Remote) Run(ctx context.Context, c Command) (string, error) {
	if r == nil || r.client == nil {
		return "", errors.New("installer: ssh-соединение закрыто")
	}
	line, stdin := r.wire(c)
	sess, err := r.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("installer: ssh session: %w", err)
	}
	defer func() { _ = sess.Close() }()
	var stdout, stderr = &capBuffer{max: maxOutputBytes}, &capBuffer{max: maxOutputBytes}
	sess.Stdout, sess.Stderr = stdout, stderr
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
		defer clear(stdin)
	}
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	err = sess.Run(line)
	stop()
	out := stdout.buf.String()
	if err == nil {
		return out, nil
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return out, &CommandError{Cmd: c.String(), Code: ee.ExitStatus(), Stderr: stderr.buf.String()}
	}
	return out, fmt.Errorf("installer: %s: %w", c.String(), err)
}

func (r *Remote) sftp() (*sftp.Client, error) {
	if r.sftpCl != nil {
		return r.sftpCl, nil
	}
	if r.client == nil {
		return nil, errors.New("installer: ssh-соединение закрыто")
	}
	c, err := sftp.NewClient(r.client)
	if err != nil {
		return nil, fmt.Errorf("installer: sftp: %w", err)
	}
	r.sftpCl = c
	return c, nil
}

// newTmpPath — уникальный путь для временного файла администратора.
func (r *Remote) newTmpPath() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return strings.TrimSuffix(r.tmpDir, "/") + "/tgproxy-" + hex.EncodeToString(b[:]), nil
}

// Upload кладёт данные во временный файл (SFTP, O_EXCL, 0600) и возвращает путь и sha256.
// Секретов (приватных ключей) через Upload не передаётся.
func (r *Remote) Upload(ctx context.Context, src io.Reader) (path, sum string, err error) {
	cl, err := r.sftp()
	if err != nil {
		return "", "", err
	}
	path, err = r.newTmpPath()
	if err != nil {
		return "", "", err
	}
	stop := context.AfterFunc(ctx, func() { _ = cl.Close() })
	defer stop()
	f, err := cl.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return "", "", fmt.Errorf("installer: sftp create: %w", err)
	}
	h := sha256.New()
	_, cpErr := io.Copy(io.MultiWriter(f, h), src)
	clErr := f.Close()
	if cpErr == nil {
		cpErr = clErr
	}
	if cpErr == nil {
		cpErr = cl.Chmod(path, 0o600)
	}
	if cpErr != nil {
		_ = cl.Remove(path)
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		return "", "", fmt.Errorf("installer: sftp upload: %w", cpErr)
	}
	return path, hex.EncodeToString(h.Sum(nil)), nil
}

// PutFile — SFTP во временный файл → install с владельцем/режимом → удаление временного.
func (r *Remote) PutFile(ctx context.Context, data []byte, mode, owner, group, dst string, check func(tmp string) Command) error {
	tmp, _, err := r.Upload(ctx, bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _, _ = r.Run(context.WithoutCancel(ctx), cmdRemoveTmp(tmp)) }()
	if check != nil {
		if _, err := r.Run(ctx, check(tmp)); err != nil {
			return err
		}
	}
	_, err = r.Run(ctx, cmdInstallFile(mode, owner, group, tmp, dst))
	return err
}
