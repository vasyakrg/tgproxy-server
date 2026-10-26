// Package views содержит templ-компоненты веб-UI tgproxy.
package views

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"sync"

	webfs "github.com/vasyakrg/tgproxy-server/web"
)

const staticPrefix = "/static/"

var assetHashes sync.Map // путь внутри static/ -> короткий sha256 ("" если файла нет)

// AssetHash возвращает короткий (12 hex) sha256 содержимого вшитого файла static/<path>.
// Хеш считается один раз на путь; для неизвестного файла — пустая строка.
func AssetHash(path string) string {
	if v, ok := assetHashes.Load(path); ok {
		return v.(string) //nolint:forcetypeassert // в карте только string
	}
	h := ""
	if data, err := fs.ReadFile(webfs.Static, "static/"+path); err == nil {
		sum := sha256.Sum256(data)
		h = hex.EncodeToString(sum[:])[:12]
	}
	assetHashes.Store(path, h)
	return h
}

// Asset возвращает URL статики с версией: /static/<path>?v=<hash>.
// Ответы с ?v отдаются с Cache-Control: immutable.
func Asset(path string) string {
	h := AssetHash(path)
	if h == "" {
		return staticPrefix + path
	}
	return staticPrefix + path + "?v=" + h
}
