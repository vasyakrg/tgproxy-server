// Команда check проверяет, что файл — читаемая mmdb с country-записями (используется fetch.sh).
package main

import (
	"fmt"
	"os"

	"github.com/vasyakrg/tgproxy-server/internal/geoip"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: check <file.mmdb>")
		os.Exit(2)
	}
	db, err := geoip.Open(os.Args[1])
	if err != nil || db == nil {
		fmt.Fprintln(os.Stderr, "geoip check: файл не открывается как mmdb:", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	// 8.8.8.8 и 1.1.1.1 есть в любой актуальной базе
	if db.LookupString("8.8.8.8") == "" && db.LookupString("1.1.1.1") == "" {
		fmt.Fprintln(os.Stderr, "geoip check: тестовые адреса не нашлись, база не похожа на country")
		os.Exit(1)
	}
}
