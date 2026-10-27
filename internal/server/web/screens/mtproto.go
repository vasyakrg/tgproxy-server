package screens

import (
	"errors"
	"log/slog"
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

type mtScreen struct {
	rt  AccessRouter
	d   MTProtoDeps
	log *slog.Logger
	now func() time.Time
}

// MountMTProto регистрирует экран «MTProto»: GET /mtproto, GET /mtproto/list, GET /mtproto/new,
// POST /mtproto, GET|POST /mtproto/{id}/link (показ ссылки; при несвежем TOTP — запрос кода),
// GET|POST /mtproto/{id}/rotate, GET|POST /mtproto/{id}/revoke,
// GET|POST /mtproto/{id}/purge (удаление отозванного секрета), GET|POST /mtproto/purge-revoked (массово). Все маршруты за Protect + RequireAuth;
// изменяющие — только htmx (CSRF: http.CrossOriginProtection в Protect).
func MountMTProto(rt AccessRouter, d MTProtoDeps) {
	s := &mtScreen{rt: rt, d: d, log: d.Logger, now: d.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	m := func(pattern string, h http.HandlerFunc) {
		rt.Mount(pattern, auth.Protect(d.Auth.RequireAuth(h)))
	}
	m("GET /mtproto", s.page)
	m("GET /mtproto/list", s.list)
	m("GET /mtproto/new", s.newForm)
	m("POST /mtproto", s.create)
	m("GET /mtproto/{id}/link", s.link)
	m("POST /mtproto/{id}/link", s.confirmLink)
	m("GET /mtproto/{id}/rotate", s.rotateForm)
	m("POST /mtproto/{id}/rotate", s.rotate)
	m("GET /mtproto/{id}/revoke", s.revokeConfirm)
	m("POST /mtproto/{id}/revoke", s.revoke)
	m("GET /mtproto/{id}/purge", s.purgeConfirm)
	m("POST /mtproto/{id}/purge", s.purge)
	m("GET /mtproto/purge-revoked", s.purgeAllConfirm)
	m("POST /mtproto/purge-revoked", s.purgeAll)
}

func (s *mtScreen) actor(r *http.Request) api.Actor {
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

func (s *mtScreen) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "mtproto screen", "path", r.URL.Path, "err", err)
	http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
}

func (s *mtScreen) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		renderFragment(w, r, http.StatusNotFound, mtNotFound())
		return
	}
	s.serverError(w, r, err)
}

func mtNotFound() templ.Component {
	return templ.Raw(`<div class="alert alert-err" role="alert">Секрет не найден: возможно, он уже отозван.</div>`)
}

func (s *mtScreen) secretID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return 0, false
	}
	return id, true
}

func (s *mtScreen) vm(r *http.Request) (MTProtoVM, error) {
	secrets, err := s.d.Service.List(r.Context())
	if err != nil {
		return MTProtoVM{}, err
	}
	ep := s.d.Service.Endpoint()
	vm := MTProtoVM{
		Disabled:   !ep.Enabled,
		NoEndpoint: ep.Host == "" || ep.Domain == "" || ep.Port <= 0,
	}
	now := s.now()
	for _, m := range secrets {
		vm.Rows = append(vm.Rows, mtSecretRow(m, s.d.ActiveConns, now))
	}
	if s.d.Stats != nil && ep.Enabled {
		vm.Matrix = mtMatrix(s.d.Stats.Snapshot())
	}
	return vm, nil
}

func (s *mtScreen) page(w http.ResponseWriter, r *http.Request) {
	vm, err := s.vm(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	renderPage(s.rt, w, r, http.StatusOK, "MTProto", views.NavMTProto, MTProtoPage(vm)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

// list отдаёт свежую таблицу и матрицу (OOB) для кнопки «Обновить»; без поллинга.
func (s *mtScreen) list(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	vm, err := s.vm(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	renderFragment(w, r, http.StatusOK, templ.Join(MTSecretsSection(vm.Rows, true), MTMatrixSection(vm.Matrix, vm.Disabled, true))) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) refresh(w http.ResponseWriter, r *http.Request, first templ.Component) {
	vm, err := s.vm(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	renderFragment(w, r, http.StatusOK, templ.Join(first, MTSecretsSection(vm.Rows, true))) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) newForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	renderFragment(w, r, http.StatusOK, MTCreateForm(MTFormVM{})) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) create(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !parseForm(w, r) {
		return
	}
	form := MTFormVM{
		Name: strings.TrimSpace(r.PostFormValue("name")), CIDRs: r.PostFormValue("cidrs"),
		MaxConns: strings.TrimSpace(r.PostFormValue("max_conns")),
	}
	n, mcErr := form.maxConnsInt()
	if mcErr != "" {
		form.Errors = api.FieldErrors{"max_conns": mcErr}
		renderFragment(w, r, http.StatusUnprocessableEntity, MTCreateForm(form)) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	res, err := s.d.Service.Create(r.Context(), s.actor(r), api.MTProtoCreateInput{
		Name: form.Name, CIDRs: api.SplitCIDRs(form.CIDRs), MaxConns: n,
	})
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		form.Errors = ve.Fields
		renderFragment(w, r, http.StatusUnprocessableEntity, MTCreateForm(form)) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	toast(w, "ok", "Секрет «"+res.Secret.Name+"» создан")
	s.refresh(w, r, MTLinkPanel(mtLinkVM("Секрет «"+res.Secret.Name+"» создан", res, ""))) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func mtLinkVM(title string, res api.MTProtoCreated, note string) MTLinkVM {
	vm := MTLinkVM{Title: title, Name: res.Secret.Name, Note: note, Fresh: true}
	if res.LinkErr != nil {
		vm.Err = mtEndpointErr
		return vm
	}
	vm.TG, vm.HTTPS, vm.QR = res.Links.TG, res.Links.HTTPS, api.QRSVG(res.Links.HTTPS)
	return vm
}

func (s *mtScreen) fresh(r *http.Request) bool {
	sess, ok := auth.SessionFromContext(r.Context())
	return ok && sess != nil && s.d.Auth.TOTPFresh(r.Context(), sess, auth.FreshTOTPWindow)
}

// link — «Ссылка + QR» существующего секрета: при несвежем TOTP отдаётся только запрос кода.
func (s *mtScreen) link(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.secretID(w, r)
	if !ok {
		return
	}
	if !s.fresh(r) {
		m, err := s.get(r, id)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		renderFragment(w, r, http.StatusUnauthorized, MTTOTPPrompt(MTTOTPVM{ID: id, Name: m.Name})) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	s.reveal(w, r, id)
}

func (s *mtScreen) reveal(w http.ResponseWriter, r *http.Request, id int64) {
	m, err := s.get(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	links, err := s.d.Service.Reveal(r.Context(), s.actor(r), id)
	vm := MTLinkVM{Title: "Ссылка для «" + m.Name + "»", Name: m.Name}
	switch {
	case errors.Is(err, api.ErrMTProtoEndpoint):
		vm.Err = mtEndpointErr
	case err != nil:
		s.fail(w, r, err)
		return
	default:
		vm.TG, vm.HTTPS, vm.QR = links.TG, links.HTTPS, api.QRSVG(links.HTTPS)
	}
	renderFragment(w, r, http.StatusOK, MTLinkPanel(vm)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

// confirmLink проверяет код TOTP (отмечая сессию свежей) и показывает ссылку.
func (s *mtScreen) confirmLink(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !parseForm(w, r) {
		return
	}
	id, ok := s.secretID(w, r)
	if !ok {
		return
	}
	sess, ok := auth.SessionFromContext(r.Context())
	if !ok || sess == nil {
		http.Error(w, "требуется вход", http.StatusUnauthorized)
		return
	}
	m, err := s.get(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ip := remoteHost(r)
	if s.d.ClientIP != nil {
		ip = s.d.ClientIP(r)
	}
	err = s.d.Auth.ConfirmTOTP(r.Context(), sess, strings.TrimSpace(r.PostFormValue("code")), ip)
	if err != nil {
		vm := MTTOTPVM{ID: id, Name: m.Name}
		var fe *auth.FailError
		switch {
		case errors.As(err, &fe) && errors.Is(fe.Err, auth.ErrInvalidCode):
			vm.Error = "Неверный код."
		case errors.Is(err, auth.ErrRateLimited):
			vm.Error = "Слишком много попыток. Повторите через минуту."
		case errors.Is(err, auth.ErrLockedOut):
			vm.Error = "Вход временно заблокирован на 15 минут."
		case errors.Is(err, auth.ErrTOTPNotConfigured):
			vm.Error = "TOTP не настроен: tgproxy totp enroll."
		default:
			s.serverError(w, r, err)
			return
		}
		renderFragment(w, r, http.StatusUnauthorized, MTTOTPPrompt(vm)) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	s.reveal(w, r, id)
}

func (s *mtScreen) rotateForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.secretID(w, r)
	if !ok {
		return
	}
	m, err := s.get(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	renderFragment(w, r, http.StatusOK, MTRotateForm(MTRotateVM{ID: id, Name: m.Name, Grace: "24h"})) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) rotate(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !parseForm(w, r) {
		return
	}
	id, ok := s.secretID(w, r)
	if !ok {
		return
	}
	m, err := s.get(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	form := MTRotateVM{ID: id, Name: m.Name, Grace: strings.TrimSpace(r.PostFormValue("grace"))}
	var grace time.Duration
	if form.Grace != "" && form.Grace != "0" {
		d, perr := time.ParseDuration(form.Grace)
		if perr != nil {
			form.Errors = api.FieldErrors{"grace": "Длительность вида 1h, 24h"}
			renderFragment(w, r, http.StatusUnprocessableEntity, MTRotateForm(form)) //nolint:contextcheck // templ-компонент получает ctx в Render
			return
		}
		grace = d
	}
	res, err := s.d.Service.Rotate(r.Context(), s.actor(r), id, grace)
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		form.Errors = ve.Fields
		renderFragment(w, r, http.StatusUnprocessableEntity, MTRotateForm(form)) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	note := "Старый ключ отозван."
	if grace > 0 {
		note = "Старый ключ действует ещё " + grace.String() + ": за это время обновите ссылку у клиентов."
	}
	toast(w, "ok", "Секрет «"+m.Name+"» повёрнут")
	s.refresh(w, r, MTLinkPanel(mtLinkVM("Секрет «"+res.Secret.Name+"» повёрнут", res, note))) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) revokeConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.secretID(w, r)
	if !ok {
		return
	}
	m, err := s.get(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	renderFragment(w, r, http.StatusOK, MTRevokeConfirm(MTRevokeVM{ID: id, Name: m.Name})) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) revoke(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.secretID(w, r)
	if !ok {
		return
	}
	m, err := s.d.Service.Revoke(r.Context(), s.actor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	toast(w, "ok", "Секрет «"+m.Name+"» отозван")
	s.refresh(w, r, MTModal(true)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) purgeConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.secretID(w, r)
	if !ok {
		return
	}
	m, err := s.get(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	vm := MTPurgeVM{ID: id, Name: m.Name}
	if !api.MTProtoPurgeable(m, s.now()) {
		vm.Err = mtPurgeActiveMsg
	}
	renderFragment(w, r, http.StatusOK, MTPurgeConfirm(vm)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

const mtPurgeActiveMsg = "Секрет ещё действует: сначала отзовите его (и дождитесь конца grace)."

func (s *mtScreen) purge(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	id, ok := s.secretID(w, r)
	if !ok {
		return
	}
	m, err := s.d.Service.Purge(r.Context(), s.actor(r), id)
	if errors.Is(err, api.ErrMTProtoActive) {
		renderFragment(w, r, http.StatusConflict, MTPurgeConfirm(MTPurgeVM{ID: id, Err: mtPurgeActiveMsg})) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	toast(w, "ok", "Секрет «"+m.Name+"» удалён")
	s.refresh(w, r, MTModal(true)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) purgeableCount(r *http.Request) (int, error) {
	all, err := s.d.Service.List(r.Context())
	if err != nil {
		return 0, err
	}
	now, n := s.now(), 0
	for _, m := range all {
		if api.MTProtoPurgeable(m, now) {
			n++
		}
	}
	return n, nil
}

func (s *mtScreen) purgeAllConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	n, err := s.purgeableCount(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	renderFragment(w, r, http.StatusOK, MTPurgeAllConfirm(MTPurgeAllVM{Count: n})) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *mtScreen) purgeAll(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) {
		return
	}
	n, err := s.d.Service.PurgeRevoked(r.Context(), s.actor(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	toast(w, "ok", "Удалено отозванных секретов: "+strconv.Itoa(n))
	s.refresh(w, r, MTModal(true)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

// get ищет секрет по id (сервис отдаёт только список).
func (s *mtScreen) get(r *http.Request, id int64) (store.MTProtoSecret, error) {
	all, err := s.d.Service.List(r.Context())
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	for _, m := range all {
		if m.ID == id {
			return m, nil
		}
	}
	return store.MTProtoSecret{}, store.ErrNotFound
}
