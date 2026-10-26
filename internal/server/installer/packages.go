package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var pkgNameRe = regexp.MustCompile(`^tgproxy_([0-9][0-9A-Za-z.+~-]*)_([a-z0-9]+)\.deb$`)

// pkgSet — deb-файлы одной версии по архитектурам.
type pkgSet struct {
	version string
	files   map[string]string // arch → имя файла в PackagesDir
}

// findPackages выбирает версию в локальном кэше: заданную или новейшую.
func findPackages(dir, want string) (pkgSet, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return pkgSet{}, fmt.Errorf("installer: кэш пакетов %s: %w", dir, err)
	}
	byVer := map[string]map[string]string{}
	for _, e := range ents {
		m := pkgNameRe.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		if byVer[m[1]] == nil {
			byVer[m[1]] = map[string]string{}
		}
		byVer[m[1]][m[2]] = e.Name()
	}
	if len(byVer) == 0 {
		return pkgSet{}, fmt.Errorf("installer: в кэше %s нет пакетов tgproxy_<версия>_<arch>.deb", dir)
	}
	if want != "" {
		files, ok := byVer[want]
		if !ok {
			return pkgSet{}, fmt.Errorf("installer: в кэше нет пакета версии %s", want)
		}
		return pkgSet{version: want, files: files}, nil
	}
	best := ""
	for v := range byVer {
		if best == "" || compareVersions(v, best) > 0 {
			best = v
		}
	}
	return pkgSet{version: best, files: byVer[best]}, nil
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

func (p pkgSet) path(dir, arch string) (string, string, bool) {
	name, ok := p.files[arch]
	if !ok {
		return "", "", false
	}
	return filepath.Join(dir, name), name, true
}
