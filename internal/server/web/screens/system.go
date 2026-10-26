package screens

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
)

// SystemRouter — то, что нужно экрану от *web.Router.
type SystemRouter interface {
	Shell
	Mount(pattern string, h http.Handler)
}

type systemScreen struct {
	rt  SystemRouter
	d   SystemDeps
	log *slog.Logger
	now func() time.Time
}

// MountSystem регистрирует экран «Система». Все маршруты за Protect + RequireAuth:
//
//	GET  /system                  страница
//	GET  /system/update           карточка обновления (опрос, пока пакет ждёт установки)
//	POST /system/check            проверить обновления
//	GET|POST /system/install      подтверждение и постановка в очередь (confirm=yes обязателен)
//	GET|POST /system/upload       загрузка deb + checksums + .minisig (multipart)
//	POST /system/notify/test      тестовое сообщение администраторам
//	POST /system/notify/events    переключатели типов событий
func MountSystem(rt SystemRouter, d SystemDeps) {
	s := &systemScreen{rt: rt, d: d, log: d.Logger, now: d.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	m := func(pattern string, h http.HandlerFunc) {
		rt.Mount(pattern, auth.Protect(d.Auth.RequireAuth(h)))
	}
	m("GET /system", s.page)
	m("GET /system/update", s.updateCard)
	m("POST /system/check", s.check)
	m("GET /system/install", s.installConfirm)
	m("POST /system/install", s.install)
	m("GET /system/upload", s.uploadForm)
	m("POST /system/upload", s.upload)
	m("POST /system/notify/test", s.notifyTest)
	m("POST /system/notify/events", s.notifyEvents)
}

func (s *systemScreen) actor(r *http.Request) api.Actor {
	ip := remoteHost(r)
	if s.d.ClientIP != nil {
		ip = s.d.ClientIP(r)
	}
	sess, _ := auth.SessionFromContext(r.Context())
	if sess == nil {
		return api.Actor{IP: ip}
	}
	return api.Actor{User: sess.User, IP: ip}
}

func (s *systemScreen) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "system screen", "path", r.URL.Path, "err", redact.Error(err))
	http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
}

func (s *systemScreen) updateVM() UpdateVM { return buildUpdateVM(s.d.Update, s.now()) }

func (s *systemScreen) page(w http.ResponseWriter, r *http.Request) {
	vm := SystemVM{Update: s.updateVM(), Notify: buildNotifyVM(r.Context(), s.d.Notify, s.now())}
	renderPage(s.rt, w, r, http.StatusOK, "Система", views.NavSystem, SystemPage(vm)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *systemScreen) updateCard(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/system") {
		return
	}
	renderFragment(w, r, http.StatusOK, UpdateCard(s.updateVM(), false)) //nolint:contextcheck // templ
}

// htmxOnlyTo — как htmxOnly, но редирект на произвольную страницу.
func htmxOnlyTo(w http.ResponseWriter, r *http.Request, page string) bool {
	if r.Header.Get("HX-Request") == "true" {
		return true
	}
	if r.Method == http.MethodGet {
		http.Redirect(w, r, page, http.StatusSeeOther)
	} else {
		http.Error(w, "требуется htmx-запрос", http.StatusBadRequest)
	}
	return false
}

func (s *systemScreen) updateOff(w http.ResponseWriter, r *http.Request) bool {
	if s.d.Update != nil && s.d.Update.Enabled() {
		return false
	}
	toast(w, "warn", "Обновления выключены в конфиге (update.enabled: false)")
	renderFragment(w, r, http.StatusOK, UpdateCard(s.updateVM(), false)) //nolint:contextcheck // templ
	return true
}

func (s *systemScreen) check(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/system") || s.updateOff(w, r) { //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	v, err := s.d.Update.Check(r.Context(), s.actor(r))
	switch {
	case err != nil:
		_, _, msg := api.SystemFail(err)
		toast(w, "err", msg)
	case v.Available != "":
		toast(w, "ok", "Доступна версия "+vprefix(v.Available))
	default:
		toast(w, "info", "Установлена последняя версия")
	}
	renderFragment(w, r, http.StatusOK, UpdateCard(s.updateVM(), false)) //nolint:contextcheck // templ
}

func (s *systemScreen) installConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/system") || s.updateOff(w, r) { //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	v := s.d.Update.Version()
	if v.Target == "" || v.Staged != "" {
		renderFragment(w, r, http.StatusOK, templ.Raw(`<div class="alert alert-warn" role="status">Нет версии для установки: обновите список через «Проверить сейчас».</div>`))
		return
	}
	renderFragment(w, r, http.StatusOK, InstallConfirm(ConfirmInstallVM{Version: vprefix(v.Target), Current: vprefix(v.Current)})) //nolint:contextcheck // templ
}

// closeAndRefresh закрывает диалог и подменяет карточку обновления (OOB).
func (s *systemScreen) closeAndRefresh(w http.ResponseWriter, r *http.Request, kind, msg string) {
	toast(w, kind, msg)
	renderFragment(w, r, http.StatusOK, templ.Join(SysModal(true), UpdateCard(s.updateVM(), true))) //nolint:contextcheck // templ
}

func (s *systemScreen) install(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/system") || !parseForm(w, r) || s.updateOff(w, r) { //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	ver := r.PostFormValue("version")
	if ver != "" && ver[0] == 'v' {
		ver = ver[1:]
	}
	if _, err := verify.ParseVersion(ver); err != nil {
		http.Error(w, "некорректная версия", http.StatusBadRequest)
		return
	}
	_, err := s.d.Update.Install(r.Context(), s.actor(r), ver, r.PostFormValue("confirm") == api.ConfirmYes)
	switch {
	case errors.Is(err, api.ErrConfirmRequired):
		http.Error(w, "требуется подтверждение", http.StatusBadRequest)
	case errors.Is(err, api.ErrUpdatesDisabled):
		s.updateOff(w, r) //nolint:contextcheck // templ-компонент получает ctx в Render
	case err == nil:
		s.closeAndRefresh(w, r, "ok", "Версия "+vprefix(ver)+" проверена и поставлена в очередь на установку") //nolint:contextcheck // templ
	default:
		code, kind, msg := api.SystemFail(err)
		if code >= http.StatusInternalServerError && kind == "internal" {
			s.log.ErrorContext(r.Context(), "system install", "err", redact.Error(err))
		}
		tone := "err"
		if kind == "already_pending" || kind == "busy" {
			tone = "warn"
		}
		s.closeAndRefresh(w, r, tone, msg) //nolint:contextcheck // templ
	}
}

func (s *systemScreen) uploadForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/system") || s.updateOff(w, r) { //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	renderFragment(w, r, http.StatusOK, UploadForm(s.updateVM().UploadMax, "")) //nolint:contextcheck // templ
}

func (s *systemScreen) upload(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/system") || s.updateOff(w, r) { //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	s.d.Update.LimitUpload(w, r)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "ожидается multipart/form-data", http.StatusBadRequest)
		return
	}
	v, err := s.d.Update.Upload(r.Context(), s.actor(r), mr)
	if err != nil {
		code, kind, msg := api.SystemFail(err)
		if code >= http.StatusInternalServerError && kind == "internal" {
			s.log.ErrorContext(r.Context(), "system upload", "err", redact.Error(err))
		}
		// 422: htmx подменяет тело диалога формой с причиной отказа.
		renderFragment(w, r, http.StatusUnprocessableEntity, UploadForm(s.updateVM().UploadMax, msg)) //nolint:contextcheck // templ
		return
	}
	if v.Uploaded == "" && v.CachedForAgents != "" {
		// Версия равна установленной: сервер не обновляется, пакет доступен установщику агентов.
		s.closeAndRefresh(w, r, "ok", "Пакет "+vprefix(v.CachedForAgents)+" проверен и сохранён для установки агентов") //nolint:contextcheck // templ
		return
	}
	s.closeAndRefresh(w, r, "ok", "Файлы приняты, подпись проверена: "+vprefix(v.Uploaded)) //nolint:contextcheck // templ
}

func (s *systemScreen) notifyTest(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/system") {
		return
	}
	if s.d.Notify == nil {
		toast(w, "warn", "Уведомления не настроены")
		return
	}
	switch err := s.d.Notify.SendTest(r.Context(), s.actor(r)); {
	case err == nil:
		toast(w, "ok", "Тестовое сообщение поставлено в очередь отправки")
	case errors.Is(err, api.ErrNotConfigured):
		toast(w, "warn", "Уведомления не настроены: не задан notify.bot_token_file")
	case errors.Is(err, api.ErrTestTooOften):
		toast(w, "warn", "Тест отправлялся совсем недавно: подождите несколько секунд")
	default:
		s.log.ErrorContext(r.Context(), "system notify test", "err", redact.Error(err))
		toast(w, "err", "Не удалось поставить тест в очередь")
	}
}

func (s *systemScreen) notifyEvents(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/system") || !parseForm(w, r) {
		return
	}
	if s.d.Notify == nil || r.PostFormValue("present") != "1" {
		http.Error(w, "некорректная форма", http.StatusBadRequest)
		return
	}
	on := map[string]bool{}
	for _, t := range r.PostForm["event"] {
		on[t] = true
	}
	info, err := s.d.Notify.Info(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	states := make(map[string]bool, len(info.Events))
	for _, e := range info.Events {
		states[e.Type] = on[e.Type]
	}
	for t := range on { // неизвестные типы отклоняет сервис
		if _, ok := states[t]; !ok {
			states[t] = true
		}
	}
	if _, err := s.d.Notify.SetEvents(r.Context(), s.actor(r), states); err != nil {
		var ve *api.ValidationError
		if errors.As(err, &ve) {
			http.Error(w, "неизвестный тип события", http.StatusBadRequest)
			return
		}
		s.log.ErrorContext(r.Context(), "system notify events", "err", redact.Error(err))
		toast(w, "err", "Не удалось сохранить настройки")
		w.Header().Set("HX-Retarget", "#sys-events")
		w.Header().Set("HX-Reswap", "outerHTML")
		vm := buildNotifyVM(r.Context(), s.d.Notify, s.now())
		renderFragment(w, r, http.StatusOK, EventsForm(vm.Events, vm.Configured)) //nolint:contextcheck // templ
		return
	}
	toast(w, "ok", "Настройки событий сохранены")
	w.WriteHeader(http.StatusNoContent)
}
