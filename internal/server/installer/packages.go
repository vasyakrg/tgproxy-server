package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	pkgNameRe = regexp.MustCompile(`^tgproxy_([0-9][0-9A-Za-z.+~-]*)_([a-z0-9]+)\.deb$`)
	// stageVersionRe — формат версии, который принимает `deploy-helper stage`.
	stageVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
)

// pkgSet — релиз одной версии из кэша загрузок сервера (<dir>/<версия>/):
// deb по архитектурам + checksums.txt + checksums.txt.minisig.
type pkgSet struct {
	version string
	dir     string            // <PackagesDir>/<версия>
	files   map[string]string // arch → имя deb
}

// findPackages выбирает версию в кэше загрузок: заданную или новейшую.
// Раскладка <dir>/<v>/tgproxy_<v>_<arch>.deb пишет updater (updates/downloads).
func findPackages(dir, want string) (pkgSet, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return pkgSet{}, fmt.Errorf("installer: кэш пакетов %s: %w", dir, err)
	}
	byVer := map[string]pkgSet{}
	for _, e := range ents {
		if !e.IsDir() || !stageVersionRe.MatchString(e.Name()) {
			continue
		}
		vdir := filepath.Join(dir, e.Name())
		files, err := os.ReadDir(vdir)
		if err != nil {
			continue
		}
		set := pkgSet{version: e.Name(), dir: vdir, files: map[string]string{}}
		for _, f := range files {
			m := pkgNameRe.FindStringSubmatch(f.Name())
			if m == nil || m[1] != e.Name() || !f.Type().IsRegular() {
				continue
			}
			set.files[m[2]] = f.Name()
		}
		if len(set.files) > 0 {
			byVer[e.Name()] = set
		}
	}
	if len(byVer) == 0 {
		return pkgSet{}, fmt.Errorf("installer: в кэше %s нет пакетов <версия>/tgproxy_<версия>_<arch>.deb", dir)
	}
	if want != "" {
		set, ok := byVer[want]
		if !ok {
			return pkgSet{}, fmt.Errorf("installer: в кэше нет пакета версии %s", want)
		}
		return set, nil
	}
	best := ""
	for v := range byVer {
		if best == "" || compareVersions(v, best) > 0 {
			best = v
		}
	}
	return byVer[best], nil
}

// compareVersions сравнивает "1.4.1" > "1.4.1-rc1" > ... упрощённо: числовые
// компоненты до первого '-'/'~', затем релиз новее пререлиза.
func compareVersions(a, b string) int {
	core := func(v string) ([]int, string) {
		pre := ""
		if k := strings.IndexAny(v, "-~"); k >= 0 {
			v, pre = v[:k], v[k+1:]
		}
		var nums []int
		for _, p := range strings.Split(v, ".") {
			n, _ := strconv.Atoi(strings.TrimFunc(p, func(r rune) bool { return r < '0' || r > '9' }))
			nums = append(nums, n)
		}
		return nums, pre
	}
	an, ap := core(a)
	bn, bp := core(b)
	for k := 0; k < max(len(an), len(bn)); k++ {
		var x, y int
		if k < len(an) {
			x = an[k]
		}
		if k < len(bn) {
			y = bn[k]
		}
		if x != y {
			return x - y
		}
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	return strings.Compare(ap, bp)
}

func (p pkgSet) path(arch string) (string, string, bool) {
	name, ok := p.files[arch]
	if !ok {
		return "", "", false
	}
	return filepath.Join(p.dir, name), name, true
}
