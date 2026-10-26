package views_test

import (
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
)

var update = flag.Bool("update", false, "обновить golden-файлы")

var hashRe = regexp.MustCompile(`\?v=[0-9a-f]{12}`)

// render рендерит компонент; хеши ассетов нормализуются, чтобы golden не зависел от содержимого файлов.
func render(t *testing.T, c templ.Component) string {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return hashRe.ReplaceAllString(buf.String(), "?v=HASH")
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden.html")
	if *update {
		if err := os.WriteFile(path, []byte(got+"\n"), 0o644); err != nil { //nolint:gosec // тестовые данные
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // путь из тестовых констант
	if err != nil {
		t.Fatalf("нет golden %s (запустите с -update): %v", path, err)
	}
	if strings.TrimSuffix(string(want), "\n") != got {
		t.Errorf("%s: вывод не совпал с golden (запустите с -update, если изменение намеренное)\n--- got ---\n%s", name, got)
	}
}

func rows(t *testing.T) templ.Component {
	t.Helper()
	return templ.ComponentFunc(func(_ context.Context, w io.Writer) error {
		_, err := w.Write([]byte(`<tr><td>agent-1</td><td>ok</td></tr>`))
		return err
	})
}

func withChildren(c templ.Component, children templ.Component) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		return c.Render(templ.WithChildren(ctx, children), w)
	})
}

func TestGoldenComponents(t *testing.T) {
	cases := map[string]templ.Component{
		"status_pills": templ.Join(
			views.StatusPill(views.StatusUp, ""),
			views.StatusPill(views.StatusDegraded, ""),
			views.StatusPill(views.StatusDown, ""),
			views.StatusPill(views.StatusUpdating, ""),
			views.StatusPill(views.StatusDraining, "Дрейн"),
		),
		"kpi": templ.Join(
			views.KPI("Запросов в секунду", "128.4", "за 5 минут", views.ToneAccent),
			views.KPI("Ошибки прокси", "0", "", views.ToneNeutral),
		),
		"table":   withChildren(views.Table("Агенты", []string{"Агент", "Статус"}), rows(t)),
		"modal":   withChildren(views.Modal("m-new", "Новое правило"), views.Chip("тело", views.ToneNeutral)),
		"toast":   views.Toast(views.ToastErr, "Не удалось сохранить"),
		"empty":   withChildren(views.EmptyState("Нет агентов", "Добавьте первого агента."), views.Button("Добавить", views.ButtonPrimary, templ.Attributes{"data-modal-open": "m-new"})),
		"buttons": templ.Join(views.Button("Сохранить", views.ButtonPrimary, nil), views.Button("Удалить", views.ButtonDanger, templ.Attributes{"hx-delete": "/api/v1/x", "hx-confirm": "Точно?"}), views.IconButton("Изменить правило r1", "edit", false, nil), views.IconButton("Удалить правило r1", "trash", true, nil)),
		"field": templ.Join(
			views.Field(views.FieldProps{Name: "host", Label: "Хост", Hint: "IP или DNS", Required: true}),
			views.Field(views.FieldProps{Name: "port", Label: "Порт", Value: "99999", Error: "Допустимо 1–65535", Type: "number"}),
		),
		"chip": templ.Join(views.Chip("сеть", views.ToneAccent), views.Chip("v1.4.1", views.ToneNeutral)),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { golden(t, name, render(t, c)) })
	}
}

func TestGoldenLayout(t *testing.T) {
	meta := views.PageMeta{Title: "Обзор", Active: views.NavOverview, Version: "v1.4.1", User: "vasya", CSRF: "tok123"}
	golden(t, "layout_overview", render(t, views.Layout(meta, views.OverviewStub())))
	golden(t, "layout_notfound", render(t, views.Layout(views.PageMeta{Title: "Не найдено"}, views.NotFound())))
}
