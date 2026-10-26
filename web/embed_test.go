package web

import (
	"io/fs"
	"testing"
)

func TestStaticEmbed(t *testing.T) {
	for _, name := range []string{
		"static/vendor/htmx/htmx.min.js",
		"static/img/favicon.ico",
		"static/fonts/OFL.txt",
	} {
		if _, err := fs.Stat(Static, name); err != nil {
			t.Errorf("нет %s в embed: %v", name, err)
		}
	}
}

func TestStaticSize(t *testing.T) {
	var total int64
	err := fs.WalkDir(Static, "static", func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total >= 1536*1024 {
		t.Errorf("static/ слишком большой: %d байт", total)
	}
}
