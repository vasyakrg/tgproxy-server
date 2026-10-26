package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// RequestName — файл-триггер tgproxy-update.path (updates/staged/request).
const RequestName = "request"

// Request — содержимое staged/request; формат читает `tgproxy update apply`
// (строгий JSON без лишних полей).
type Request struct {
	Version   string `json:"version"`
	Component string `json:"component"`
}

// ComponentServer — компонент, обновляемый этим процессом.
const ComponentServer = "server"

// Stager кладёт пакет для root-oneshot. Каталог staged появляется целиком и
// атомарно (rename), `request` внутри него — последним файлом перед rename,
// поэтому path-юнит никогда не увидит частичную загрузку.
type Stager struct {
	Dir string // <data_dir>/updates
}

// StagedDir — updates/staged.
func (s Stager) StagedDir() string { return filepath.Join(s.Dir, "staged") }

// Pending возвращает поставленный в очередь запрос (nil — очередь пуста).
func (s Stager) Pending() (*Request, error) {
	b, err := os.ReadFile(filepath.Join(s.StagedDir(), RequestName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var r Request
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("updater: staged/request: %w", err)
	}
	return &r, nil
}

// StageFiles — что именно стейджится.
type StageFiles struct {
	Req       Request
	Deb       string // путь к проверенному deb в кэше загрузок
	DebName   string // имя файла в staged (tgproxy_<v>_<arch>.deb)
	Checksums []byte
	Sig       []byte
}

// Stage собирает каталог во временном месте и переименовывает его в staged.
// Уже поставленный в очередь запрос → ErrPending (второй request не создаётся).
func (s Stager) Stage(f StageFiles) (err error) {
	p, perr := s.Pending()
	if perr != nil {
		return perr
	}
	if p != nil {
		return ErrPending
	}
	if err = os.MkdirAll(s.Dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(s.Dir, ".staging-")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err = copyFile(f.Deb, filepath.Join(tmp, f.DebName)); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(tmp, ChecksumsName), f.Checksums, 0o600); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(tmp, SigName), f.Sig, 0o600); err != nil {
		return err
	}
	req, err := json.Marshal(f.Req)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(tmp, RequestName), req, 0o600); err != nil {
		return err
	}
	// Оставшийся без request каталог — мусор прошлой неудачи.
	if err = os.RemoveAll(s.StagedDir()); err != nil {
		return err
	}
	if err = os.Rename(tmp, s.StagedDir()); err != nil {
		return err
	}
	return nil
}

// CleanStaging удаляет недособранные .staging-* (после падения процесса).
func (s Stager) CleanStaging() {
	m, _ := filepath.Glob(filepath.Join(s.Dir, ".staging-*"))
	for _, p := range m {
		_ = os.RemoveAll(p)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- путь из кэша
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- внутри свежего temp-каталога
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
