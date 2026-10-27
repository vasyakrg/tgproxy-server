package screens

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const accessMaxForm = 64 << 10

// AccessRouter — то, что нужно экрану от *web.Router.
type AccessRouter interface {
	Shell
	Mount(pattern string, h http.Handler)
}

type accessScreen struct {
	rt  AccessRouter
	d   AccessDeps
	log *slog.Logger
	now func() time.Time
}

// MountAccess регистрирует экран «Доступ»: GET /access и htmx-ручки
// (GET /access/new, POST /access, GET /access/{id}/edit, POST /access/{id},
// GET|POST /access/{id}/delete). Все маршруты за Protect + RequireAuth.
func MountAccess(rt AccessRouter, d AccessDeps) {
	s := &accessScreen{rt: rt, d: d, log: d.Logger, now: d.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	m := func(pattern string, h http.HandlerFunc) {
		rt.Mount(pattern, auth.Protect(d.Auth.RequireAuth(h)))
	}
	m("GET /access", s.page)
	m("GET /access/new", s.newForm)
	m("POST /access", s.create)
	m("GET /access/{id}/edit", s.editForm)
	m("POST /access/{id}", s.update)
	m("GET /access/{id}/delete", s.deleteConfirm)
	m("POST /access/{id}/delete", s.remove)
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *accessScreen) actor(r *http.Request) api.Actor {
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

// baseURL: public_base_url из конфига; если не задан — по Host запроса.
func (s *accessScreen) baseURL(r *http.Request) string {
	if s.d.Env != nil {
		if b := strings.TrimRight(s.d.Env.PublicBaseURL(), "/"); b != "" {
			return b
		}
	}
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func (s *accessScreen) rows(r *http.Request) ([]RuleRow, error) {
	rules, err := s.d.Service.List(r.Context())
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]RuleRow, 0, len(rules))
	for _, x := range rules {
		out = append(out, makeRuleRow(x, s.d.Env, now))
	}
	return out, nil
}

func (s *accessScreen) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "access screen", "path", r.URL.Path, "err", err)
	http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
}

func (s *accessScreen) page(w http.ResponseWriter, r *http.Request) {
	rows, err := s.rows(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	vm := AccessVM{BaseURL: s.baseURL(r), Rows: rows, Bots: botRows(s.d.Bots)}
	renderPage(s.rt, w, r, http.StatusOK, "Доступ", views.NavAccess, AccessPage(vm)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

// htmxOnly: фрагменты и изменения работают только через htmx (модалка требует JS).
func htmxOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("HX-Request") == "true" {
		return true
	}
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/access", http.StatusSeeOther)
	} else {
		http.Error(w, "требуется htmx-запрос", http.StatusBadRequest)
	}
	return false
}

func (s *accessScreen) ruleID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return 0, false
	}
	return id, true
}

func (s *accessScreen) lookupFail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		renderFragment(w, r, http.StatusNotFound, notFoundPanel())
		return
	}
	s.serverError(w, r, err)
}

func notFoundPanel() templ.Component {
	return templ.Raw(`<div class="alert alert-err" role="alert">Правило не найдено: возможно, его уже удалили.</div>`)
}

func (s *accessScreen) newForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	renderFragment(w, r, http.StatusOK, RuleForm(RuleFormVM{})) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *accessScreen) editForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.ruleID(w, r)
	if !ok {
		return
	}
	rule, err := s.d.Service.Get(r.Context(), id)
	if err != nil {
		s.lookupFail(w, r, err)
		return
	}
	cidrs := make([]string, 0, len(rule.CIDRs))
	for _, p := range rule.CIDRs {
		cidrs = append(cidrs, p.String())
	}
	rps := ""
	if rule.RPS > 0 {
		rps = strconv.FormatFloat(rule.RPS, 'f', -1, 64)
	}
	f := RuleFormVM{
		ID: rule.ID, Name: rule.Name, CIDRs: strings.Join(cidrs, "\n"), RPS: rps,
		Enabled: rule.Enabled && rule.RevokedAt == nil,
	}
	if len(rule.KeyHash) > 0 {
		f.KeyPrefix = "задан"
		if rule.KeyPrefix != "" {
			f.KeyPrefix = rule.KeyPrefix + "…"
		}
	}
	renderFragment(w, r, http.StatusOK, RuleForm(f)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *accessScreen) deleteConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.ruleID(w, r)
	if !ok {
		return
	}
	rule, err := s.d.Service.Get(r.Context(), id)
	if err != nil {
		s.lookupFail(w, r, err)
		return
	}
	renderFragment(w, r, http.StatusOK, DeleteConfirm(rule.ID, rule.Name)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, accessMaxForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "некорректная форма", http.StatusBadRequest)
		return false
	}
	return true
}

// asciiJSON кодирует значение в JSON, пригодный для HTTP-заголовка (не-ASCII -> \uXXXX).
func asciiJSON(v any) string {
	b, _ := json.Marshal(v)
	var sb strings.Builder
	for _, r := range string(b) {
		if r < 0x80 {
			sb.WriteRune(r)
			continue
		}
		if r > 0xFFFF {
			r -= 0x10000
			sb.WriteString(`\u` + hex4(0xD800+(r>>10)) + `\u` + hex4(0xDC00+(r&0x3FF)))
			continue
		}
		sb.WriteString(`\u` + hex4(r))
	}
	return sb.String()
}

func hex4(r rune) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(r>>12)&0xF], digits[(r>>8)&0xF], digits[(r>>4)&0xF], digits[r&0xF]})
}

// toast выставляет HX-Trigger: {"toast": {"kind", "message"}} (ловит app.js).
func toast(w http.ResponseWriter, kind, message string) {
	w.Header().Set("HX-Trigger", asciiJSON(map[string]any{"toast": map[string]string{"kind": kind, "message": message}}))
}

func (s *accessScreen) create(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !parseForm(w, r) {
		return
	}
	form := RuleFormVM{
		Name: strings.TrimSpace(r.PostFormValue("name")), CIDRs: r.PostFormValue("cidrs"),
		RPS: strings.TrimSpace(r.PostFormValue("rps")), WithKey: r.PostFormValue("with_key") != "",
	}
	rps, rpsErr := api.ParseRPS(form.RPS)
	in := api.CreateInput{Name: form.Name, CIDRs: api.SplitCIDRs(form.CIDRs), WithKey: form.WithKey, RPS: rps}
	fe := api.ValidateCreate(in)
	if rpsErr != "" {
		if fe == nil {
			fe = api.FieldErrors{}
		}
		fe[api.FieldRPS] = rpsErr
	}
	if len(fe) > 0 {
		form.Errors = fe
		invalidForm(w, r, form) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	res, err := s.d.Service.Create(r.Context(), s.actor(r), in)
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		form.Errors = ve.Fields
		invalidForm(w, r, form) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	rows, err := s.rows(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	toast(w, "ok", "Правило «"+res.Rule.Name+"» создано")
	renderFragment(w, r, http.StatusOK, templ.Join(
		CreatedPanel(CreatedVM{Name: res.Rule.Name, Key: res.PlainKey, BaseURL: api.BaseURLFor(s.baseURL(r), res.PlainKey)}), //nolint:contextcheck // templ-компонент получает ctx в Render
		RulesSection(rows, true), //nolint:contextcheck // templ-компонент получает ctx в Render
	))
}

// closeAndRefresh отвечает на успешное изменение/удаление: закрытый диалог и свежая таблица (OOB).
func (s *accessScreen) closeAndRefresh(w http.ResponseWriter, r *http.Request, message string) {
	rows, err := s.rows(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	toast(w, "ok", message)
	renderFragment(w, r, http.StatusOK, templ.Join(RuleModal(true), RulesSection(rows, true)))
}

func (s *accessScreen) update(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !parseForm(w, r) {
		return
	}
	id, ok := s.ruleID(w, r)
	if !ok {
		return
	}
	cur, err := s.d.Service.Get(r.Context(), id)
	if err != nil {
		s.lookupFail(w, r, err)
		return
	}
	form := RuleFormVM{
		ID: id, Name: strings.TrimSpace(r.PostFormValue("name")), CIDRs: r.PostFormValue("cidrs"),
		RPS: strings.TrimSpace(r.PostFormValue("rps")), Enabled: r.PostFormValue("enabled") != "",
	}
	if len(cur.KeyHash) > 0 {
		form.KeyPrefix = "задан"
		if cur.KeyPrefix != "" {
			form.KeyPrefix = cur.KeyPrefix + "…"
		}
	}
	rps, rpsErr := api.ParseRPS(form.RPS)
	if rpsErr != "" {
		form.Errors = api.FieldErrors{api.FieldRPS: rpsErr}
		invalidForm(w, r, form) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	cidrs := api.SplitCIDRs(form.CIDRs)
	_, err = s.d.Service.Update(r.Context(), s.actor(r), id, api.UpdateInput{
		Name: &form.Name, CIDRs: &cidrs, RPS: &rps, Enabled: &form.Enabled,
	})
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		form.Errors = ve.Fields
		invalidForm(w, r, form) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	case err != nil:
		s.lookupFail(w, r, err)
		return
	}
	s.closeAndRefresh(w, r, "Правило «"+form.Name+"» сохранено") //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *accessScreen) remove(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.ruleID(w, r)
	if !ok {
		return
	}
	rule, err := s.d.Service.Delete(r.Context(), s.actor(r), id)
	if err != nil {
		s.lookupFail(w, r, err)
		return
	}
	s.closeAndRefresh(w, r, "Правило «"+rule.Name+"» удалено") //nolint:contextcheck // templ-компонент получает ctx в Render
}

// invalidForm отдаёт форму с ошибками (422); htmx принимает такой ответ (см. responseHandling в layout).
func invalidForm(w http.ResponseWriter, r *http.Request, form RuleFormVM) {
	renderFragment(w, r, http.StatusUnprocessableEntity, RuleForm(form)) //nolint:contextcheck // templ-компонент получает ctx в Render
}
