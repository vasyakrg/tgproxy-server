package auth

import (
	"image"
	"strings"
)

// renderQR превращает чёрно-белое изображение QR (1 пиксель = 1 модуль) в псевдографику
// из полублоков с тихой зоной в 2 модуля. Светлый фон — для тёмных терминалов инвертирован.
func renderQR(img image.Image) string {
	b := img.Bounds()
	const quiet = 2
	dark := func(x, y int) bool {
		if x < b.Min.X || y < b.Min.Y || x >= b.Max.X || y >= b.Max.Y {
			return false
		}
		r, g, bl, _ := img.At(x, y).RGBA()
		return (r+g+bl)/3 < 0x8000
	}
	var sb strings.Builder
	for y := b.Min.Y - quiet; y < b.Max.Y+quiet; y += 2 {
		for x := b.Min.X - quiet; x < b.Max.X+quiet; x++ {
			top, bot := !dark(x, y), !dark(x, y+1) // светлый модуль = закрашенный блок
			switch {
			case top && bot:
				sb.WriteString("█")
			case top:
				sb.WriteString("▀")
			case bot:
				sb.WriteString("▄")
			default:
				sb.WriteString(" ")
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
