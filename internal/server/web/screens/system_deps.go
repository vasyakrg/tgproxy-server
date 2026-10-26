package screens

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
)

// SystemPollInterval — как часто карточка обновления перечитывается, пока пакет ждёт установки.
const SystemPollInterval = 5 * time.Second

// SystemDeps — зависимости экрана «Система». Любой из сервисов может быть nil:
// соответствующая карточка покажет «не настроено».
type SystemDeps struct {
	Auth     *auth.Auth // обязательно
	Update   *api.SystemService
	Notify   *api.NotificationsService
	ClientIP func(*http.Request) string // nil — хост из RemoteAddr
	Logger   *slog.Logger               // nil — slog.Default()
	Now      func() time.Time           // nil — time.Now
}

// SourceRow — вариант «Откуда скачать» (задаётся в конфиге, в UI только показывается).
type SourceRow struct {
	Label, Hint string
	On          bool
}

// CheckRow — строка чеклиста проверки пакета. Status: pending|ok|failed.
type CheckRow struct{ Status, Text string }

// ResultVM — итог последней установки.
type ResultVM struct {
	Text string
	Tone views.Tone
	Err  string
}

// UpdateVM — карточка «Обновление сервера».
type UpdateVM struct {
	Enabled    bool
	Current    string
	Available  string
	Uploaded   string // загруженный вручную пакет
	Target     string // версия на кнопке «Установить»
	Checked    string
	Sources    []SourceRow
	Checks     []CheckRow
	Staged     string // версия, ожидающая установки
	CanInstall bool
	Notes      string
	LastError  string
	Result     *ResultVM
	UploadMax  string
	Poll       bool
	PollSec    int
}

// AdminRow — строка таблицы администраторов.
type AdminRow struct {
	Name, Telegram, LastLogin string
	TOTP, Disabled            bool
	NoTelegram                bool
}

// NotifyEventRow — переключатель типа события.
type NotifyEventRow struct {
	Type, Title, Hint string
	On                bool
	Tone              views.Tone
}

// NotifyVM — карточка «Уведомления в Telegram».
type NotifyVM struct {
	Configured bool
	BotID      string
	Pending    int
	Admins     []AdminRow
	Events     []NotifyEventRow
	Error      string
}

// SystemVM — страница «Система».
type SystemVM struct {
	Update UpdateVM
	Notify NotifyVM
}

// ConfirmInstallVM — диалог подтверждения установки.
type ConfirmInstallVM struct{ Version, Current string }

func vprefix(v string) string {
	if v == "" {
		return ""
	}
	if v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

// fmtWhen: «сегодня, 09:00», иначе «02.01.2006 15:04»; нулевое время — «не проверялось».
func fmtWhen(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	t, now = t.In(time.Local), now.In(time.Local)
	if t.YearDay() == now.YearDay() && t.Year() == now.Year() {
		return "сегодня, " + t.Format("15:04")
	}
	return t.Format("02.01.2006 15:04")
}

func parseRFC3339(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return comma(strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64)) + " МБ"
	case n >= 1<<10:
		return strconv.FormatInt(n>>10, 10) + " КБ"
	}
	return strconv.FormatInt(n, 10) + " Б"
}

func sourceRows(kind, detail string) []SourceRow {
	rows := []SourceRow{
		{Label: "GitHub Releases", Hint: "напрямую"},
		{Label: "Через HTTP-прокси", Hint: "update.http_proxy"},
		{Label: "Через агента", Hint: "egress агента"},
		{Label: "Загрузить файл", Hint: "deb, checksums.txt и .minisig"},
	}
	kinds := []string{"github", "proxy", "agent", "upload"}
	for i, k := range kinds {
		if k != kind {
			continue
		}
		rows[i].On = true
		if detail != "" {
			rows[i].Hint = detail
		}
	}
	return rows
}

func makeResult(r *api.InstallResult, now time.Time) *ResultVM {
	if r == nil {
		return nil
	}
	when := fmtWhen(parseRFC3339(r.At), now)
	suffix := ""
	if when != "" {
		suffix = " · " + when
	}
	switch {
	case r.OK:
		return &ResultVM{Text: "Последняя установка: " + vprefix(r.Version) + " установлена" + suffix, Tone: views.ToneOK}
	case r.RolledBack:
		return &ResultVM{Text: "Последняя установка: " + vprefix(r.Version) + " не удалась, выполнен откат" + suffix, Tone: views.ToneWarn, Err: r.Error}
	}
	return &ResultVM{Text: "Последняя установка: " + vprefix(r.Version) + " не удалась" + suffix, Tone: views.ToneErr, Err: r.Error}
}

func checkRows(v api.VersionInfo) []CheckRow {
	if v.Target == "" {
		return nil
	}
	deb := v.DebName
	if v.DebSize > 0 {
		deb += " · " + humanSize(v.DebSize)
	}
	status, tail := "pending", " — проверяется при установке"
	switch {
	case v.Staged == v.Target:
		status, tail = "ok", ""
	case v.LastError != "":
		status, tail = "failed", ""
	}
	rows := []CheckRow{
		{status, deb + tail},
		{status, "подпись minisign checksums.txt доверенным ключом" + tail},
		{status, "sha256 пакета совпадает с checksums.txt" + tail},
	}
	if status == "failed" {
		rows[0].Text = deb
		rows[1].Text, rows[2].Text = "подпись minisign checksums.txt", "sha256 пакета совпадает с checksums.txt"
		rows = append(rows, CheckRow{"failed", v.LastError})
	}
	return rows
}

func buildUpdateVM(svc *api.SystemService, now time.Time) UpdateVM {
	if svc == nil {
		return UpdateVM{}
	}
	v := svc.Version()
	vm := UpdateVM{
		Enabled: v.Enabled, Current: vprefix(v.Current), Available: vprefix(v.Available), Uploaded: vprefix(v.Uploaded), Target: vprefix(v.Target),
		Checked: fmtWhen(parseRFC3339(v.CheckedAt), now), Sources: sourceRows(v.Source, v.SourceDetail),
		Staged: vprefix(v.Staged), Notes: v.Notes, LastError: v.LastError, Result: makeResult(v.Result, now),
		UploadMax: strconv.FormatInt(svc.MaxUpload()>>20, 10) + " МБ", PollSec: int(SystemPollInterval / time.Second),
	}
	vm.CanInstall = v.Enabled && v.Target != "" && v.Staged == ""
	vm.Poll = v.Staged != ""
	vm.Checks = checkRows(v)
	return vm
}

func buildNotifyVM(ctx context.Context, svc *api.NotificationsService, now time.Time) NotifyVM {
	if svc == nil {
		return NotifyVM{}
	}
	info, err := svc.Info(ctx)
	vm := NotifyVM{Configured: info.Enabled, BotID: info.BotID, Pending: info.Pending}
	if err != nil {
		vm.Error = "Не удалось прочитать настройки уведомлений."
	}
	for _, a := range info.Admins {
		row := AdminRow{Name: a.Name, TOTP: a.TOTP, Disabled: a.Disabled, NoTelegram: a.TelegramID == 0, LastLogin: "—"}
		if a.TelegramID != 0 {
			row.Telegram = strconv.FormatInt(a.TelegramID, 10)
		}
		if t := parseRFC3339(a.LastLogin); !t.IsZero() {
			row.LastLogin = fmtWhen(t, now)
		}
		vm.Admins = append(vm.Admins, row)
	}
	for _, e := range info.Events {
		tone := views.ToneWarn
		switch e.Severity {
		case "critical":
			tone = views.ToneErr
		case "info":
			tone = views.ToneNeutral
		}
		vm.Events = append(vm.Events, NotifyEventRow{Type: e.Type, Title: e.Title, Hint: e.Hint, On: e.Enabled, Tone: tone})
	}
	return vm
}

// noteLines режет release notes на строки для показа без разметки.
func noteLines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		out = append(out, strings.TrimRight(l, " \t"))
	}
	return out
}
