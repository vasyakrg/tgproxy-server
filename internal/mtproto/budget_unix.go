//go:build unix

package mtproto

import "syscall"

func nofileLimit() (uint64, bool) {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return 0, false
	}
	return uint64(r.Cur), true //nolint:unconvert // тип Cur зависит от платформы
}
