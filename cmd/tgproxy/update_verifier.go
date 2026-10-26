package main

import (
	"fmt"
	"io"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/release"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/selfupdate"
)

// releaseVerifier — проверка релиза встроенными ключами (internal/release/verify).
// min_version = установленная версия: понижение версии отвергается.
type releaseVerifier struct {
	keys []verify.PublicKey
	min  string
}

func newReleaseVerifier() (selfupdate.Verifier, error) {
	keys, err := release.EmbeddedPubKeys()
	if err != nil {
		return nil, fmt.Errorf("встроенные ключи: %w", err)
	}
	floor := buildinfo.Version
	if _, err := verify.ParseVersion(floor); err != nil {
		floor = "" // dev-сборка: нижней границы нет
	}
	return releaseVerifier{keys: keys, min: floor}, nil
}

func (v releaseVerifier) Verify(checksums, sig []byte) error {
	return verify.Verify(checksums, sig, v.keys)
}

func (v releaseVerifier) CheckFile(checksums []byte, name string, r io.Reader) error {
	return verify.CheckFile(checksums, name, r)
}

func (v releaseVerifier) CheckVersion(version string) error {
	return verify.CheckVersion(version, v.min)
}
