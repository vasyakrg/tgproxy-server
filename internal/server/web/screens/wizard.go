package screens

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

func (s *agentsScreen) mountWizard(m func(string, http.HandlerFunc)) {
	m("GET /agents/new", s.wizard)
	m("POST /agents/new/ssh", s.sshSubmit)
	m("POST /agents/new/ssh/confirm", s.sshConfirm)
	m("POST /agents/new/nat", s.natIssue)
	m("GET /agents/new/nat/pending", s.natPending)
	m("GET /agents/enroll/{id}/status", s.enrollStatus)
	m("GET /agents/enroll/{id}/revoke", s.revokeConfirm)
	m("POST /agents/enroll/{id}/revoke", s.revoke)
	m("GET /agents/new/jobs/{job}", s.installPage)
}

// ---------- страница ----------

func (s *agentsScreen) wizardVM(r *http.Request, mode string) WizardVM {
	vm := WizardVM{Mode: mode, SSH: DefaultSSHForm(), NAT: DefaultNATForm(), NATConfigured: s.d.Enroll.Configured()}
	vm.SSH.Disabled = !s.d.Install.Configured()
	if mode == WizardNAT && vm.NATConfigured {
		vm.Pending = s.pendingList(r)
	}
	return vm
}

func (s *agentsScreen) wizard(w http.ResponseWriter, r *http.Request) {
	mode := WizardSSH
	if r.URL.Query().Get("mode") == WizardNAT {
		mode = WizardNAT
	}
	renderPage(s.rt, w, r, http.StatusOK, "Новый агент", views.NavAgents, WizardPage(s.wizardVM(r, mode))) //nolint:contextcheck // templ
}

// ---------- ветка SSH ----------

// formInput собирает ввод шага 1. Берётся только выбранный способ входа: второй игнорируется.
func formInput(r *http.Request) api.InstallInput {
	in := api.InstallInput{
		Name: strings.TrimSpace(r.PostFormValue("name")), Host: strings.TrimSpace(r.PostFormValue("host")),
		User: strings.TrimSpace(r.PostFormValue("user")),
	}
	in.SSHPort = atoiOr(r.PostFormValue("ssh_port"), api.DefaultSSHPort)
	in.AgentPort = atoiOr(r.PostFormValue("agent_port"), api.DefaultAgentPort)
	in.Weight = atoiOr(r.PostFormValue("weight"), api.DefaultWeight)
	if in.User == "" {
		in.User = "root"
	}
	if r.PostFormValue("auth") == "password" {
		in.Password = []byte(r.PostFormValue("password"))
	} else {
		in.PrivateKey = []byte(r.PostFormValue("private_key"))
		in.Passphrase = []byte(r.PostFormValue("passphrase"))
	}
	return in
}

// atoiOr: пусто — умолчание; мусор — -1 (валидация поймает).
func atoiOr(v string, def int) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return n
}

func (s *agentsScreen) sshForm(w http.ResponseWriter, r *http.Request, status int, f SSHFormVM) {
	renderFragment(w, r, status, templ.Join(WizSteps(1), SSHForm(f))) //nolint:contextcheck // templ
}

func (s *agentsScreen) redirectToJob(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("HX-Redirect", "/agents/new/jobs/"+url.PathEscape(id))
	renderFragment(w, r, http.StatusOK, templ.NopComponent)
}

// startFail показывает ошибку запуска установки в форме шага 1 (без секретов).
func (s *agentsScreen) startFail(w http.ResponseWriter, r *http.Request, in api.InstallInput, err error) {
	f := sshFormFrom(in)
	f.Retype = true
	var ve *api.ValidationError
	var unknown *installer.ErrHostKeyUnknown
	switch {
	case errors.As(err, &ve):
		f.Errors = ve.Fields
	case errors.Is(err, api.ErrHostKeyChanged), errors.Is(err, installer.ErrHostKeyMismatch):
		f.Errors = api.FieldErrors{api.FieldGeneral: "Ключ хоста отличается от закреплённого: возможна подмена. Установка остановлена. Если хост переустановлен — выполните на сервере: tgproxy hostkeys forget <host:port>"}
	case errors.Is(err, api.ErrPendingGone):
		f.Errors = api.FieldErrors{api.FieldGeneral: "Время ожидания подтверждения истекло. Введите данные заново."}
	case errors.As(err, &unknown):
		f.Errors = api.FieldErrors{api.FieldGeneral: "Ключ хоста ещё не подтверждён."}
	case errors.Is(err, api.ErrProbeFailed):
		f.Errors = api.FieldErrors{api.FieldGeneral: redact.String(err.Error())}
	case errors.Is(err, api.ErrNotConfigured):
		f.Disabled = true
	default:
		s.log.ErrorContext(r.Context(), "wizard: install start", "err", redact.Error(err))
		f.Errors = api.FieldErrors{api.FieldGeneral: "Не удалось запустить установку. Подробности в журнале сервера."}
	}
	s.sshForm(w, r, http.StatusUnprocessableEntity, f) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *agentsScreen) sshSubmit(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !parseForm(w, r) {
		return
	}
	in := formInput(r)
	defer in.Zero()
	if !s.d.Install.Configured() {
		s.startFail(w, r, in, api.ErrNotConfigured)
		return
	}
	if fe := in.Validate(); fe != nil {
		s.startFail(w, r, in, &api.ValidationError{Fields: fe})
		return
	}
	probe, err := s.d.Install.Probe(r.Context(), in.Host, in.SSHPort)
	if err != nil {
		s.startFail(w, r, in, err)
		return
	}
	act := s.actor(r)
	switch {
	case probe.Pinned && !probe.Match:
		s.startFail(w, r, in, api.ErrHostKeyChanged)
	case probe.Pinned:
		// Ключ уже закреплён и совпал: подтверждение не нужно, установщик проверит его сам.
		id, serr := s.d.Install.Start(r.Context(), act, in)
		if serr != nil {
			s.startFail(w, r, in, serr)
			return
		}
		s.redirectToJob(w, r, id)
	default:
		pid, serr := s.d.Install.Stage(act, in, probe)
		if serr != nil {
			s.startFail(w, r, in, serr)
			return
		}
		renderFragment(w, r, http.StatusOK, HostKeyStep(HostKeyVM{ //nolint:contextcheck // templ
			PendingID: pid, Addr: probe.Addr, Algo: probe.Algo, Fingerprint: probe.Fingerprint, Name: in.Name,
		}))
	}
}

func (s *agentsScreen) sshConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !parseForm(w, r) {
		return
	}
	pid := r.PostFormValue("pending")
	act := s.actor(r)
	if r.PostFormValue("action") == "reject" {
		form, ok := s.d.Install.Reject(act, pid)
		f := DefaultSSHForm()
		if ok {
			f = sshFormFrom(form)
			f.Retype = true
		}
		s.sshForm(w, r, http.StatusOK, f) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	id, form, err := s.d.Install.Confirm(r.Context(), act, pid)
	if err != nil {
		s.startFail(w, r, form, err)
		return
	}
	s.redirectToJob(w, r, id)
}

// ---------- шаг «Установка» ----------

func (s *agentsScreen) installPage(w http.ResponseWriter, r *http.Request) {
	if !s.d.Install.Configured() {
		http.Error(w, "установка по SSH не настроена", http.StatusNotImplemented)
		return
	}
	id := r.PathValue("job")
	st, err := s.d.Install.Status(r.Context(), id)
	switch {
	case errors.Is(err, api.ErrBadJob), errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	title := st.AgentID
	if title == "" {
		title = st.Host
	}
	j := JobVM{
		Emergency: st.Kind == installer.JobKindEmergency,
		ID:        st.ID, Title: title, State: st.State, Error: redact.String(st.Error), StartedMS: st.CreatedAt.UnixMilli(),
		EventsURL: "/api/v1/install-jobs/" + url.PathEscape(st.ID) + "/events", StatusURL: "/api/v1/install-jobs/" + url.PathEscape(st.ID),
	}
	if st.FinishedAt != nil {
		j.FinishedMS = st.FinishedAt.UnixMilli()
	}
	for _, step := range st.Steps {
		j.Steps = append(j.Steps, JobStepVM{Key: step.Key, Label: step.Label, Status: step.Status})
	}
	pageTitle := "Установка агента"
	if j.Emergency {
		pageTitle = "Аварийное обновление агента"
	}
	renderPage(s.rt, w, r, http.StatusOK, pageTitle, views.NavAgents, InstallPage(j)) //nolint:contextcheck // templ
}

// ---------- ветка NAT ----------

func (s *agentsScreen) pendingList(r *http.Request) []PendingRowVM {
	items, err := s.d.Enroll.List(r.Context())
	if err != nil {
		s.log.WarnContext(r.Context(), "wizard: pending enrollments", "err", redact.Error(err))
		return nil
	}
	return pendingRows(items, s.now())
}

func (s *agentsScreen) natIssue(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !parseForm(w, r) {
		return
	}
	if !s.d.Enroll.Configured() {
		renderFragment(w, r, http.StatusOK, NATBody(NATFormVM{}, nil, nil, false)) //nolint:contextcheck // templ
		return
	}
	f := NATFormVM{
		Name: strings.TrimSpace(r.PostFormValue("name")), Weight: strings.TrimSpace(r.PostFormValue("weight")),
		TTL: atoiOr(r.PostFormValue("ttl"), 60),
	}
	in := api.EnrollInput{Name: f.Name, Weight: atoiOr(f.Weight, api.DefaultWeight), TTL: time.Duration(f.TTL) * time.Minute}
	is, err := s.d.Enroll.Issue(r.Context(), s.actor(r), in)
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		f.Errors = ve.Fields
		renderFragment(w, r, http.StatusUnprocessableEntity, NATBody(f, nil, s.pendingList(r), true)) //nolint:contextcheck // templ
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "wizard: issue enrollment", "err", redact.Error(err))
		f.Errors = api.FieldErrors{api.FieldGeneral: "Не удалось выпустить токен. Подробности в журнале сервера."}
		renderFragment(w, r, http.StatusUnprocessableEntity, NATBody(f, nil, s.pendingList(r), true)) //nolint:contextcheck // templ
		return
	}
	issued := NATIssuedVM{ID: is.ID, Name: f.Name, Cmdline: is.Cmdline, CmdlineInstalled: is.CmdlineInstalled, Expires: is.ExpiresAt.Local().Format("15:04"),
		Status: EnrollStatusVM{ID: is.ID, State: api.EnrollWaiting, Name: f.Name, Left: leftRu(is.ExpiresAt.Sub(s.now()))}}
	toast(w, "ok", "Токен для «"+f.Name+"» выпущен")
	renderFragment(w, r, http.StatusOK, NATBody(f, &issued, s.pendingList(r), true)) //nolint:contextcheck // templ
}

func (s *agentsScreen) natPending(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.d.Enroll.Configured() {
		return
	}
	renderFragment(w, r, http.StatusOK, NATPending(s.pendingList(r), false)) //nolint:contextcheck // templ
}

// enrollStatus — фрагмент опроса «Ожидаем подключения агента». ?go=1 (отложенный запрос после
// успеха) отвечает HX-Redirect на /agents с подсветкой нового агента.
func (s *agentsScreen) enrollStatus(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/agents/new?mode=nat") || !s.d.Enroll.Configured() {
		return
	}
	id, ok := s.enrollID(w, r)
	if !ok {
		return
	}
	st, err := s.d.Enroll.Status(r.Context(), id)
	if err != nil {
		s.log.WarnContext(r.Context(), "wizard: enrollment status", "err", redact.Error(err))
		http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	vm := EnrollStatusVM{ID: id, State: st.State, Name: st.Name, AgentID: st.AgentID, Left: leftRu(st.Left)}
	if st.State == api.EnrollConnected {
		if r.URL.Query().Get("go") == "1" {
			w.Header().Set("HX-Redirect", vm.agentsURL())
			renderFragment(w, r, http.StatusOK, templ.NopComponent) //nolint:contextcheck // templ
			return
		}
		toast(w, "ok", "Агент «"+st.Name+"» подключился")
	}
	renderFragment(w, r, http.StatusOK, NATStatus(vm)) //nolint:contextcheck // templ
}

func (s *agentsScreen) enrollID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !api.ValidEnrollID(id) {
		http.NotFound(w, r)
		return "", false
	}
	return id, true
}

func (s *agentsScreen) revokeConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.d.Enroll.Configured() {
		return
	}
	id, ok := s.enrollID(w, r)
	if !ok {
		return
	}
	renderFragment(w, r, http.StatusOK, ConfirmDialog(ConfirmVM{ //nolint:contextcheck // templ
		Title: "Отозвать токен?", Text: "Агент, который ещё не успел подключиться по этому токену, получит отказ.",
		Note: "Уже подключённых агентов это не затрагивает.", Action: "/agents/enroll/" + id + "/revoke", Label: "Отозвать", Danger: true,
		Target: "#wiz-modal-body",
	}))
}

func (s *agentsScreen) revoke(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.d.Enroll.Configured() || !parseForm(w, r) {
		return
	}
	id, ok := s.enrollID(w, r)
	if !ok {
		return
	}
	err := s.d.Enroll.Revoke(r.Context(), s.actor(r), id, r.PostFormValue("confirm") == api.ConfirmYes)
	switch {
	case errors.Is(err, api.ErrConfirmRequired):
		http.Error(w, "требуется подтверждение", http.StatusBadRequest)
		return
	case errors.Is(err, store.ErrNotFound):
		renderFragment(w, r, http.StatusUnprocessableEntity, ModalError("Токен не найден: он уже использован, истёк или отозван.")) //nolint:contextcheck // templ
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "wizard: revoke enrollment", "err", redact.Error(err))
		renderFragment(w, r, http.StatusUnprocessableEntity, ModalError("Не удалось отозвать токен.")) //nolint:contextcheck // templ
		return
	}
	toast(w, "ok", "Токен отозван")
	renderFragment(w, r, http.StatusOK, templ.Join(WizModal(true), NATPending(s.pendingList(r), true))) //nolint:contextcheck // templ
}
