// Package buildinfo хранит метаданные сборки, подставляемые через -ldflags -X.
package buildinfo

// Значения по умолчанию действуют для сборки без ldflags (go run, go test).
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
