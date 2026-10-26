package pki

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrExists — CA в каталоге уже существует; перезапись запрещена.
var ErrExists = errors.New("pki: CA already exists")

// Имена файлов, создаваемых DevInit.
const (
	FileCACert     = "ca.crt"
	FileCAKey      = "ca.key"
	FileServerCert = "server-client.crt"
	FileServerKey  = "server-client.key"
	FileAgentCert  = "agent.crt"
	FileAgentKey   = "agent.key"
)

const devCATTL = 10 * 365 * 24 * time.Hour

// DevInit создаёт в outDir (0700) dev-PKI: CA, сертификат сервера и сертификаты
// агентов agentIDs (по умолчанию ["local"]) в файлах agent-<id>.crt/.key;
// первый агент дополнительно сохраняется как agent.crt/.key (совместимость).
// Ключи — 0600. Если ca.crt или ca.key уже есть — ErrExists, ничего не меняется.
func DevInit(outDir string, agentIDs []string) error {
	if len(agentIDs) == 0 {
		agentIDs = []string{"local"}
	}
	seen := make(map[string]struct{}, len(agentIDs))
	for _, id := range agentIDs {
		if !ValidAgentID(id) {
			return fmt.Errorf("pki: invalid agent id %q", id)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("pki: duplicate agent id %q", id)
		}
		seen[id] = struct{}{}
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("pki: mkdir: %w", err)
	}
	if err := os.Chmod(outDir, 0o700); err != nil { // #nosec G302 -- 0700 — каталог ключей
		return fmt.Errorf("pki: chmod dir: %w", err)
	}
	for _, n := range []string{FileCACert, FileCAKey} {
		if _, err := os.Lstat(filepath.Join(outDir, n)); err == nil {
			return fmt.Errorf("%w: %s", ErrExists, filepath.Join(outDir, n))
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("pki: stat: %w", err)
		}
	}

	ca, err := NewCA("tgproxy dev CA", devCATTL)
	if err != nil {
		return err
	}
	srv, err := IssueServerClient(ca, 0)
	if err != nil {
		return err
	}
	caKey, err := ca.KeyPEM()
	if err != nil {
		return err
	}
	files := []devFile{
		{FileCACert, ca.CertPEM(), 0o644},
		{FileCAKey, caKey, 0o600},
		{FileServerCert, srv.CertPEM, 0o644},
		{FileServerKey, srv.KeyPEM, 0o600},
	}
	for i, id := range agentIDs {
		csr, agentKey, err := NewAgentCSR(id)
		if err != nil {
			return err
		}
		agentCert, err := IssueAgent(ca, csr, id, 0)
		if err != nil {
			return err
		}
		files = append(files,
			devFile{AgentCertFile(id), agentCert, 0o644},
			devFile{AgentKeyFile(id), agentKey, 0o600})
		if i == 0 {
			files = append(files,
				devFile{FileAgentCert, agentCert, 0o644},
				devFile{FileAgentKey, agentKey, 0o600})
		}
	}
	for _, f := range files {
		if err := writeFile(filepath.Join(outDir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

type devFile struct {
	name string
	data []byte
	mode os.FileMode
}

// AgentCertFile — имя файла сертификата агента id, созданного DevInit.
func AgentCertFile(id string) string { return "agent-" + id + ".crt" }

// AgentKeyFile — имя файла ключа агента id, созданного DevInit.
func AgentKeyFile(id string) string { return "agent-" + id + ".key" }

// writeFile пишет файл с точными правами; CA-файлы — только O_EXCL.
func writeFile(path string, data []byte, mode os.FileMode) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	switch filepath.Base(path) {
	case FileCACert, FileCAKey:
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, mode) // #nosec G304 -- путь из конфигурации оператора
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, path)
		}
		return fmt.Errorf("pki: write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("pki: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("pki: close %s: %w", path, err)
	}
	return os.Chmod(path, mode)
}
