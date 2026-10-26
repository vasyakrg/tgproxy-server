package installer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

const serverKeyName = "id_ed25519"

// LoadOrCreateServerKey загружает серверный ed25519-ключ для tgproxy-deploy из
// dir/id_ed25519 (0600) или создаёт его (каталог 0700). Рядом пишется .pub.
// dir — обычно data_dir/ssh.
func LoadOrCreateServerKey(dir string) (ssh.Signer, error) {
	path := filepath.Join(dir, serverKeyName)
	data, err := os.ReadFile(path) // #nosec G304 -- путь из конфига сервера
	switch {
	case err == nil:
		if st, serr := os.Stat(path); serr == nil && st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("installer: права %s слишком широкие (%v), нужно 0600", path, st.Mode().Perm())
		}
		sg, perr := ssh.ParsePrivateKey(data)
		if perr != nil {
			return nil, fmt.Errorf("installer: серверный ssh-ключ: %w", perr)
		}
		return sg, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("installer: чтение серверного ssh-ключа: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("installer: каталог ssh-ключа: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "tgproxy-server")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(blk)
	defer clear(pemBytes)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- путь ключа из data_dir сервера, O_EXCL
	if err != nil {
		return nil, fmt.Errorf("installer: запись серверного ssh-ключа: %w", err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil { // #nosec G306 -- публичный ключ
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
