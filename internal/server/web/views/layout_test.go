package views_test

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	webfs "github.com/vasyakrg/tgproxy-server/web"
)

func layoutHTML(t *testing.T) string {
	t.Helper()
	meta := views.PageMeta{Title: "Обзор", Active: views.NavAgents, Version: "v1", User: "vasya", CSRF: "c"}
	return render(t, views.Layout(meta, views.OverviewStub()))
}

func TestLayoutStaticLinksResolve(t *testing.T) {
	html := layoutHTML(t)
	re := regexp.MustCompile(`(?:href|src)="(/static/[^"?]+)(?:\?v=[A-Z0-9]+)?"`)
	links := re.FindAllStringSubmatch(html, -1)
	if len(links) < 8 {
		t.Fatalf("ожидалось >=8 ссылок на статику, найдено %d", len(links))
	}
	for _, m := range links {
		name := "static/" + strings.TrimPrefix(m[1], "/static/")
		if _, err := fs.Stat(webfs.Static, name); err != nil {
			t.Errorf("ссылка %s не резолвится в embed: %v", m[1], err)
		}
	}
	if !strings.Contains(html, "?v=HASH") {
		t.Error("ссылки должны быть версионированы (?v=)")
	}
}

func TestLayoutNoExternalURLsNoInline(t *testing.T) {
	html := layoutHTML(t)
	for _, m := range regexp.MustCompile(`https?://[^\s"'<>]+`).FindAllString(html, -1) {
		if !strings.Contains(m, "api.telegram.org") && !strings.HasPrefix(m, "http://www.w3.org/") {
			t.Errorf("внешний URL в HTML: %s", m)
		}
	}
	if regexp.MustCompile(`<script[^>]*>\s*[^<\s]`).MatchString(html) {
		t.Error("inline <script> с телом запрещён CSP")
	}
	if regexp.MustCompile(`<style[\s>]`).MatchString(html) {
		t.Error("<style> запрещён CSP")
	}
	if regexp.MustCompile(`\sstyle\s*=`).MatchString(html) {
		t.Error("атрибут style= запрещён CSP")
	}
	if regexp.MustCompile(`\son[a-z]+\s*=`).MatchString(html) {
		t.Error("inline-обработчики событий запрещены CSP")
	}
}

func TestLayoutSidebarA11y(t *testing.T) {
	html := layoutHTML(t)
	for _, want := range []string{
		`aria-expanded="true"`,
		`href="/agents" aria-label="Агенты" title="Агенты" aria-current="page"`,
		`href="/" aria-label="Обзор" title="Обзор" aria-current="false"`,
		`action="/logout"`, `name="csrf" value="c"`, `aria-label="Выйти (vasya)"`,
		`<main id="main"`, `id="toasts"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("нет фрагмента %q", want)
		}
	}
	if strings.Index(html, "early.js") > strings.Index(html, "app.css") {
		t.Error("early.js должен подключаться до CSS")
	}
}

func TestStaticAssetsExistForCSSFonts(t *testing.T) {
	css, err := fs.ReadFile(webfs.Static, "static/css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(css), "http://") || strings.Contains(string(css), "https://") {
		t.Error("app.css содержит внешние URL")
	}
}

func TestAssetHashStable(t *testing.T) {
	a, b := views.Asset("css/app.css"), views.Asset("css/app.css")
	if a != b || !regexp.MustCompile(`^/static/css/app\.css\?v=[0-9a-f]{12}$`).MatchString(a) {
		t.Errorf("Asset: %q / %q", a, b)
	}
	if got := views.Asset("nope.css"); got != "/static/nope.css" {
		t.Errorf("неизвестный файл: %q", got)
	}
}
