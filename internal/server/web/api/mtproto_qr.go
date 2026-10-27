package api

// QRSVG рисует QR-код текста в виде SVG (для модалки UI). Пусто при ошибке кодирования.
func QRSVG(text string) string { return qrSVG(text) }
