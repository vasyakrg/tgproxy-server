package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
)

// BuildCSR строит CSR (ECDSA P-256) с URI SAN spiffe://tgproxy/agent/<id>.
// Содержимое информационное: сервер выставляет SAN сам.
func BuildCSR(key *ecdsa.PrivateKey, agentID string) ([]byte, error) {
	if !pki.ValidAgentID(agentID) {
		return nil, fmt.Errorf("agent: invalid agent id %q", agentID)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agent/" + agentID},
		URIs:    []*url.URL{pki.AgentURI(agentID)},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("agent: create csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func marshalKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("agent: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("agent: no PKCS#8 private key in PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agent: parse key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("agent: key is not ECDSA P-256")
	}
	return ec, nil
}

// atomicWrite пишет файл во временный рядом и переименовывает.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// NewKeyFile создаёт ключ P-256 в path (0600, O_EXCL). Существующий файл —
// ошибка, если не force. Запущенный от root процесс отдаёт файл пользователю
// owner (если такой существует; иначе пропуск без ошибки).
func NewKeyFile(path string, force bool, owner string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("agent: generate key: %w", err)
	}
	pemKey, err := marshalKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if force {
		if err := atomicWrite(path, pemKey, 0o600); err != nil {
			return nil, fmt.Errorf("agent: write key: %w", err)
		}
	} else {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- путь из флага CLI
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return nil, fmt.Errorf("agent: key %s already exists (use --force to overwrite)", path)
			}
			return nil, fmt.Errorf("agent: create key: %w", err)
		}
		_, werr := f.Write(pemKey)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(path)
			return nil, fmt.Errorf("agent: write key: %w", werr)
		}
	}
	chownIfRoot(path, owner)
	return key, nil
}

// chownIfRoot: от root передаёт файл owner, если пользователь существует.
func chownIfRoot(path, owner string) {
	if owner == "" || os.Geteuid() != 0 {
		return
	}
	u, err := user.Lookup(owner)
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}
