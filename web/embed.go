// Package web содержит вшитые статические ассеты веб-UI (шрифты, JS, CSS, изображения).
package web

import "embed"

// Static — вшитая файловая система каталога static.
//
//go:embed static
var Static embed.FS
