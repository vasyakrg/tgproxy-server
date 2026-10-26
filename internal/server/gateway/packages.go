package gateway

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/release"
)

var (
	pkgVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
	pkgArchRe    = regexp.MustCompile(`^[a-z0-9]{2,16}$`)
)

// PackagesHandler раздаёт агентам релиз из кэша загрузок сервера
// (<dir>/<v>/{tgproxy_<v>_<arch>.deb, checksums.txt, checksums.txt.minisig}) по
// GET /_agent_gw/packages/<v>/<file> (architecture §12). Доступ — только по mTLS-
// сертификату зарегистрированного агента (его проверяет Gateway). Отдаются
// исключительно три имени из release-раскладки; любой другой путь — 404, версия
// или имя вне формата — 400. Подпись сервер не проверяет: агент всё равно
// проверяет её встроенными ключами, а в кэш загрузок попадает только проверенный релиз.
func PackagesHandler(dir string, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return &packagesHandler{dir: dir, log: log}
}

type packagesHandler struct {
	dir string
	log *slog.Logger
}

func (h *packagesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := AgentIDFromContext(r.Context())
	if !ok {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, PackagesPath)
	version, file, found := strings.Cut(rest, "/")
	if !found || !pkgVersionRe.MatchString(version) || strings.ContainsAny(file, "/\\") || !h.allowedFile(version, file) {
		// Всё, что не похоже на допустимый (версия, файл), — в том числе "..", "%2e%2e", вложенные пути.
		code := http.StatusNotFound
		if !pkgVersionRe.MatchString(version) || strings.Contains(rest, "..") {
			code = http.StatusBadRequest
		}
		http.Error(w, http.StatusText(code), code)
		return
	}
	p := filepath.Join(release.VersionDir(h.dir, version), file)
	fi, err := os.Lstat(p) // #nosec G304 G703 -- version и file прошли строгую проверку формата
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(p) // #nosec G304 G703 -- см. выше
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()
	if ofi, err := f.Stat(); err != nil || !os.SameFile(fi, ofi) {
		http.NotFound(w, r)
		return
	}
	h.log.Info("gateway: package served", "agent", id, "version", version, "file", file)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, file, fi.ModTime(), f)
}

// allowedFile — имя входит в раскладку релиза версии v.
func (h *packagesHandler) allowedFile(v, name string) bool {
	switch name {
	case release.ChecksumsName, release.SigName:
		return true
	}
	rest, ok := strings.CutPrefix(name, "tgproxy_"+v+"_")
	if !ok {
		return false
	}
	arch, ok := strings.CutSuffix(rest, ".deb")
	return ok && pkgArchRe.MatchString(arch)
}
