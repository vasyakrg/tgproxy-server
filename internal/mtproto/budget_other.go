//go:build !unix

package mtproto

func nofileLimit() (uint64, bool) { return 0, false }
