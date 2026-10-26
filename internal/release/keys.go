// Package release хранит доверенные ключи подписи релизов.
package release

import (
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
)

// pubKeysCSV — доверенные minisign-ключи, вшитые в бинарь: основной и
// (опционально) ротационный, через запятую. В релизной сборке переопределяется:
//
//	-X github.com/vasyakrg/tgproxy-server/internal/release.pubKeysCSV=RWQ...,RWQ...
//
// TODO(ОВ-4): заменить тестовый ключ реальным ключом релизов. Приватная часть
// тестового ключа не существует (сгенерирован и выброшен), поэтому до замены
// ни одна подпись не будет принята — fail closed.
var pubKeysCSV = testPubKey

const testPubKey = "RWQdT+xGRpE/2tOTNhpUvmBvwOQKU4mR1jH6+jhnHgBjjksgGu1ypgzX"

// EmbeddedPubKeys разбирает вшитые ключи.
func EmbeddedPubKeys() ([]verify.PublicKey, error) {
	var ss []string
	for _, p := range strings.Split(pubKeysCSV, ",") {
		if p = strings.TrimSpace(p); p != "" {
			ss = append(ss, p)
		}
	}
	return verify.ParsePublicKeys(ss)
}
