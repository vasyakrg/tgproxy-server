package verify

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var semverRe = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$`)

// Version — разобранный semver.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string
}

// ParseVersion разбирает "1.2.3", "v1.2.3-rc.1+build".
func ParseVersion(s string) (Version, error) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, fmt.Errorf("%w: %q", ErrBadVersion, s)
	}
	var v Version
	for i, dst := range []*uint64{&v.Major, &v.Minor, &v.Patch} {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("%w: %q", ErrBadVersion, s)
		}
		*dst = n
	}
	if m[4] != "" {
		v.Pre = strings.Split(m[4], ".")
	}
	return v, nil
}

// Compare возвращает -1, 0, 1 по правилам semver 2.0 (build игнорируется).
func (v Version) Compare(o Version) int {
	for _, p := range [][2]uint64{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if c := cmpU(p[0], p[1]); c != 0 {
			return c
		}
	}
	switch {
	case len(v.Pre) == 0 && len(o.Pre) == 0:
		return 0
	case len(v.Pre) == 0:
		return 1
	case len(o.Pre) == 0:
		return -1
	}
	for i := 0; i < len(v.Pre) && i < len(o.Pre); i++ {
		if c := cmpPre(v.Pre[i], o.Pre[i]); c != 0 {
			return c
		}
	}
	return cmpU(uint64(len(v.Pre)), uint64(len(o.Pre)))
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpPre(a, b string) int {
	an, aErr := strconv.ParseUint(a, 10, 64)
	bn, bErr := strconv.ParseUint(b, 10, 64)
	switch {
	case aErr == nil && bErr == nil:
		return cmpU(an, bn)
	case aErr == nil:
		return -1
	case bErr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// CompareVersions сравнивает две строки-версии.
func CompareVersions(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// CheckVersion отказывает, если v ниже min. Пустой minVer — без ограничения.
// Некорректная v — всегда ошибка.
func CheckVersion(v, minVer string) error {
	pv, err := ParseVersion(v)
	if err != nil {
		return err
	}
	if minVer == "" {
		return nil
	}
	pm, err := ParseVersion(minVer)
	if err != nil {
		return fmt.Errorf("min_version: %w", err)
	}
	if pv.Compare(pm) < 0 {
		return fmt.Errorf("%w: %s < %s", ErrDowngrade, v, minVer)
	}
	return nil
}
