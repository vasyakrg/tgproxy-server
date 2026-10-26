package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.yaml.in/yaml/v3"
)

// maxUsersFileSize ограничивает размер читаемого users-файла.
const maxUsersFileSize = 4 << 20

// User — запись users_database.yml (формат Authelia + telegram_id, totp_secret_enc).
type User struct {
	DisplayName   string   `yaml:"displayname"`
	Password      string   `yaml:"password"` // PHC-строка argon2id
	Email         string   `yaml:"email"`
	Groups        []string `yaml:"groups"`
	Disabled      bool     `yaml:"disabled"`
	TelegramID    int64    `yaml:"telegram_id"`
	TOTPSecretEnc string   `yaml:"totp_secret_enc"` // base64(KEK-sealed секрет), AAD = "totp:"+username
}

// UsersFile — корень users_database.yml.
type UsersFile struct {
	Users map[string]User `yaml:"users"`
}

// Users — атомарно подменяемый снимок users-файла.
type Users struct {
	path string
	log  *slog.Logger
	cur  atomic.Pointer[UsersFile]

	mu       sync.Mutex // сериализует Reload и доступ к subs
	subs     []func([]string)
	debounce time.Duration
}

// LoadUsers читает файл; ошибка первичной загрузки возвращается вызывающему.
func LoadUsers(path string, log *slog.Logger) (*Users, error) {
	if log == nil {
		log = slog.Default()
	}
	u := &Users{path: path, log: log, debounce: 150 * time.Millisecond}
	f, err := readUsersFile(path)
	if err != nil {
		return nil, err
	}
	u.cur.Store(f)
	return u, nil
}

func readUsersFile(path string) (*UsersFile, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("auth: users file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("auth: users file %s: not a regular file", path)
	}
	if fi.Mode().Perm()&^0o640 != 0 {
		return nil, fmt.Errorf("auth: users file %s: mode %04o is wider than 0640", path, fi.Mode().Perm())
	}
	if fi.Size() > maxUsersFileSize {
		return nil, fmt.Errorf("auth: users file %s: too large", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- путь из конфига
	if err != nil {
		return nil, fmt.Errorf("auth: users file: %w", err)
	}
	var f UsersFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("auth: users file %s: %w", path, err)
	}
	for name, usr := range f.Users {
		if name == "" {
			return nil, fmt.Errorf("auth: users file %s: empty username", path)
		}
		if _, err := ParsePHC(usr.Password); err != nil {
			return nil, fmt.Errorf("auth: users file %s: user %q: %w", path, name, err)
		}
	}
	return &f, nil
}

// Get возвращает копию записи пользователя.
func (u *Users) Get(name string) (User, bool) {
	f := u.cur.Load()
	if f == nil {
		return User{}, false
	}
	usr, ok := f.Users[name]
	return usr, ok
}

// Names — имена пользователей (отсортированы).
func (u *Users) Names() []string {
	f := u.cur.Load()
	var out []string
	if f != nil {
		for n := range f.Users {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// OnChange регистрирует callback: список пользователей, которые удалены, отключены
// или у которых изменился пароль/TOTP (для инвалидации сессий).
func (u *Users) OnChange(fn func(changed []string)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.subs = append(u.subs, fn)
}

// Reload перечитывает файл. При ошибке остаётся прежняя версия, ошибка логируется (ERROR) и возвращается.
func (u *Users) Reload() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	nf, err := readUsersFile(u.path)
	if err != nil {
		u.log.Error("users file reload failed, keeping previous version", "err", err)
		return err
	}
	old := u.cur.Swap(nf)
	changed := diffUsers(old, nf)
	if len(changed) > 0 {
		for _, fn := range u.subs {
			fn(changed)
		}
	}
	u.log.Info("users file reloaded", "users", len(nf.Users), "changed", len(changed))
	return nil
}

func diffUsers(old, nf *UsersFile) []string {
	if old == nil {
		return nil
	}
	var out []string
	for name, o := range old.Users {
		n, ok := nf.Users[name]
		if !ok || (n.Disabled && !o.Disabled) || n.Password != o.Password || n.TOTPSecretEnc != o.TOTPSecretEnc {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// Watch следит за файлом (fsnotify на каталог — переживает атомарную замену) до отмены ctx.
func (u *Users) Watch(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("auth: watcher: %w", err)
	}
	defer func() { _ = w.Close() }()
	dir := filepath.Dir(u.path)
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("auth: watch %s: %w", dir, err)
	}
	base := filepath.Base(u.path)
	var timer *time.Timer
	var fire <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			// "..data" — атомарная подмена каталога ConfigMap/secret в Kubernetes.
			if name := filepath.Base(ev.Name); name != base && name != "..data" {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(u.debounce)
			} else {
				timer.Reset(u.debounce)
			}
			fire = timer.C
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			u.log.Error("users file watcher error", "err", err)
		case <-fire:
			fire = nil
			_ = u.Reload() // ошибка уже залогирована
		}
	}
}
