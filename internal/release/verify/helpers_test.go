package verify

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"aead.dev/minisign"
)

type keyPair struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func newKey(t *testing.T) keyPair {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{pub, priv}
}

// signED имитирует `minisign -S` (prehashed ED, trusted comment с timestamp/file).
func signED(k keyPair, msg []byte) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	_, _ = io.Copy(io.Discard, r)
	return r.SignWithComments(k.priv, "timestamp:1700000000\tfile:checksums.txt", "untrusted")
}

func sumLine(name string, data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:]) + "  " + name + "\n"
}
