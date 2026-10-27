package screens

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// AgentsRouter — то, что нужно экрану от *web.Router.
type AgentsRouter interface {
	Shell
	Mount(pattern string, h http.Handler)
}

type agentsScreen struct {
	rt  AgentsRouter
	d   AgentsDeps
	log *slog.Logger
	now func() time.Time
}

// MountAgents регистрирует экран «Агенты» и мастер «Новый агент». Все маршруты за Protect + RequireAuth:
//
//	GET  /agents                         страница / фрагмент таблицы (опрос htmx)
//	POST /agents/{id}/drain|undrain      вывод из балансировки / возврат
//	GET|POST /agents/{id}/rotate         подтверждение и перевыпуск сертификата
//	GET|POST /agents/{id}/mode           смена режима связи
//	GET|POST /agents/{id}/weight         вес в балансировке (1..100)
//	GET  /agents/{id}/more               сведения об агенте
//	GET|POST /agents/{id}/emergency      аварийное обновление по SSH (подтверждение, затем задача)
//	GET|POST /agents/{id}/delete         подтверждение и удаление
//	GET  /agents/new                     мастер (?mode=ssh|nat)
//	POST /agents/new/ssh[/confirm]       ветка SSH
//	POST /agents/new/nat                 ветка NAT: выпуск токена
//	GET  /agents/enroll/{id}/status      состояние токена (опрос «Ожидаем подключения агента»)
//	GET  /agents/new/nat/pending         список ожидающих токенов (опрос)
//	GET|POST /agents/enroll/{id}/revoke  отзыв токена
//	GET  /agents/new/jobs/{job}           шаг «Установка» (SSE)
func MountAgents(rt AgentsRouter, d AgentsDeps) {
	s := &agentsScreen{rt: rt, d: d, log: d.Logger, now: d.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	m := func(pattern string, h http.HandlerFunc) {
		rt.Mount(pattern, auth.Protect(d.Auth.RequireAuth(h)))
	}
	m("GET /agents", s.page)
	m("POST /agents/{id}/drain", s.drain(true))
	m("POST /agents/{id}/undrain", s.drain(false))
	m("GET /agents/{id}/rotate", s.rotateConfirm)
	m("POST /agents/{id}/rotate", s.rotate)
	m("GET /agents/{id}/mode", s.modeForm)
	m("POST /agents/{id}/mode", s.modeApply)
	m("GET /agents/{id}/weight", s.weightForm)
	m("POST /agents/{id}/weight", s.weightApply)
	m("GET /agents/{id}/more", s.more)
	m("GET /agents/{id}/emergency", s.emergencyConfirm)
	m("POST /agents/{id}/emergency", s.emergencyApply)
	m("GET /agents/{id}/delete", s.deleteConfirm)
	m("POST /agents/{id}/delete", s.remove)
	s.mountRollout(m)
	s.mountWizard(m)
}

func (s *agentsScreen) actor(r *http.Request) api.Actor {
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

func (s *agentsScreen) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "agents screen", "path", r.URL.Path, "err", redact.Error(err))
	http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
}

// ---------- модель ----------

func (s *agentsScreen) rows(ctx context.Context, filterQ, filterStatus string) AgentsVM {
	vm := AgentsVM{
		ServerVersion: s.d.ServerVersion, Query: filterQ, Status: filterStatus, StatusOpts: statusOpts,
		Can: s.d.Service.Capabilities(), PollSec: int(AgentsPollInterval / time.Second),
	}
	now := s.now()
	ro := s.rolloutInfo(ctx, &vm)
	q := strings.ToLower(strings.TrimSpace(filterQ))
	for _, v := range s.d.Service.List() {
		vm.Total++
		if v.State.Up {
			vm.Up++
		}
		row := makeAgentRow(v, s.d.ServerVersion, now)
		if lagging(v.State, s.d.ServerVersion) {
			vm.Lagging++
			row.Lagging = true
			row.CanUpdate = ro.canUpdate && v.State.Up
			switch {
			case ro.block != "":
				row.UpdateBlock = ro.block
			case !v.State.Up:
				row.UpdateBlock = "Агент недоступен"
			}
		}
		if filterStatus != "" && api.StatusOf(v.State) != filterStatus {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(row.Name+" "+row.ID+" "+row.Addr), q) {
			continue
		}
		vm.Rows = append(vm.Rows, row)
	}
	vm.CanUpdateAll = ro.canUpdate && vm.Lagging > 0
	vm.UpdateBlock = ro.block
	return vm
}

func validStatusFilter(v string) string {
	for _, o := range statusOpts {
		if o.Value == v {
			return v
		}
	}
	return ""
}

func makeAgentRow(v api.AgentView, serverVersion string, now time.Time) AgentRowVM {
	st := v.State
	name := st.Agent.Name
	if name == "" {
		name = st.Agent.ID
	}
	row := AgentRowVM{
		ID: st.Agent.ID, Name: name, Addr: agentAddr(st.Agent), Status: agentStatus(st),
		Weight: strconv.Itoa(st.Agent.Weight), RPS: "—", RTT: "—", Inflight: "—", Version: "—", Cert: "—", Seen: "—", SeenMuted: true,
		Draining: st.Draining,
	}
	switch api.LinkOf(v) {
	case "reverse":
		row.LinkLabel, row.LinkTone = "агент →", views.ToneTG
	case "both":
		row.LinkLabel, row.LinkTone = "оба", views.ToneAccent
	default:
		row.LinkLabel, row.LinkTone = "→ агент", views.ToneNeutral
	}
	if v.HasConns && (st.Agent.Mode == store.ModeReverse || v.ReverseConns > 0) {
		row.LinkConns = "· " + strconv.Itoa(v.ReverseConns) + " соед."
	}
	if !st.LastSeen.IsZero() {
		row.Seen, row.SeenMuted = agoRu(now, st.LastSeen), false
	}
	if ls := st.LastStatus; ls != nil {
		if ls.Version != "" {
			row.Version = ls.Version
			row.VersionStale = serverVersion != "" && ls.Version != serverVersion
		}
		if st.Up {
			row.RPS = fmtRPS(ls.RPS1m)
			row.Inflight, row.InflightLP = inflightSplit(ls.Inflight, ls.InflightLongPoll)
			if ls.UpstreamRTTMs > 0 {
				row.RTT = fmtMs(ls.UpstreamRTTMs)
			}
		}
		if !ls.CertNotAfter.IsZero() {
			row.Cert, row.CertTone = certLeft(now, ls.CertNotAfter)
		}
		row.MTProto = ls.HasCapability(transport.CapMTProto)
		if row.MTProto && st.Up {
			row.DC = dcViews(ls.MTProto)
		}
	}
	return row
}

// dcViews — состояние DC из статуса агента по возрастанию номера; нечисловые ключи пропускаются.
func dcViews(m *transport.MTProtoStatus) []DCVM {
	if m == nil {
		return nil
	}
	nums := make([]int, 0, len(m.DC))
	byNum := make(map[int]transport.DCStatus, len(m.DC))
	for k, v := range m.DC {
		n, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		nums = append(nums, n)
		byNum[n] = v
	}
	sort.Ints(nums)
	out := make([]DCVM, 0, len(nums))
	for _, n := range nums {
		d := DCVM{Name: "DC" + strconv.Itoa(n), Up: byNum[n].Up}
		if d.Up {
			d.RTT = fmtMs(byNum[n].RTTMs)
		}
		out = append(out, d)
	}
	return out
}

// certLeft: «71 д», подсветка за 14 дней до конца, «истёк» после.
func certLeft(now, notAfter time.Time) (label, tone string) {
	left := notAfter.Sub(now)
	if left <= 0 {
		return "истёк", "err"
	}
	days := int(left / (24 * time.Hour))
	if days < 1 {
		return "< 1 д", "warn"
	}
	if days < certWarnDays {
		return strconv.Itoa(days) + " д", "warn"
	}
	return strconv.Itoa(days) + " д", ""
}

// ---------- страница и таблица ----------

func (s *agentsScreen) filters(r *http.Request) (q, status string) {
	q = strings.TrimSpace(r.FormValue("q"))
	if len(q) > 64 {
		q = q[:64]
	}
	return q, validStatusFilter(r.FormValue("status"))
}

func (s *agentsScreen) page(w http.ResponseWriter, r *http.Request) {
	if !s.d.Service.Configured() {
		renderPage(s.rt, w, r, http.StatusOK, "Агенты", views.NavAgents, AgentsNotConfigured()) //nolint:contextcheck // templ
		return
	}
	q, status := s.filters(r)
	vm := s.rows(r.Context(), q, status)
	if hl := r.URL.Query().Get("highlight"); api.ValidAgentID(hl) && !isFragment(r) {
		for i := range vm.Rows {
			vm.Rows[i].New = vm.Rows[i].ID == hl
		}
	}
	if isFragment(r) {
		renderFragment(w, r, http.StatusOK, AgentsBody(vm, false)) //nolint:contextcheck // templ
		return
	}
	renderPage(s.rt, w, r, http.StatusOK, "Агенты", views.NavAgents, AgentsPage(vm)) //nolint:contextcheck // templ
}

// refresh отдаёт свежую таблицу (outerHTML для hx-target=#agents-body) с тостом.
func (s *agentsScreen) refresh(w http.ResponseWriter, r *http.Request, kind, message string) {
	q, status := s.filters(r)
	if message != "" {
		toast(w, kind, message)
	}
	renderFragment(w, r, http.StatusOK, AgentsBody(s.rows(r.Context(), q, status), false)) //nolint:contextcheck // templ
}

// closeAndRefresh закрывает диалог и подменяет таблицу (OOB).
func (s *agentsScreen) closeAndRefresh(w http.ResponseWriter, r *http.Request, message string) {
	q, status := s.filters(r)
	toast(w, "ok", message)
	renderFragment(w, r, http.StatusOK, templ.Join(AgentModal(true), AgentsBody(s.rows(r.Context(), q, status), true))) //nolint:contextcheck // templ
}

// failToast превращает ошибку действия в тост и свежую таблицу.
func (s *agentsScreen) failToast(w http.ResponseWriter, r *http.Request, err error) {
	code, kind := api.FailStatus(err)
	if code == http.StatusInternalServerError || kind == "agent_error" {
		s.log.ErrorContext(r.Context(), "agents screen", "path", r.URL.Path, "err", redact.Error(err))
	}
	msg := map[string]string{
		"not_found":        "Агент не найден: возможно, его уже удалили.",
		"not_configured":   "Функция не настроена на сервере.",
		"in_progress":      "Операция уже выполняется.",
		"agent_error":      "Агент не ответил или отклонил запрос.",
		"confirm_required": "Требуется подтверждение.",
	}[kind]
	if msg == "" {
		msg = "Не удалось выполнить действие."
	}
	s.refresh(w, r, "err", msg) //nolint:contextcheck // templ-компонент получает ctx в Render
}

// failModal показывает ошибку действия внутри диалога (422: htmx подменяет тело диалога).
func (s *agentsScreen) failModal(w http.ResponseWriter, r *http.Request, err error) {
	code, kind := api.FailStatus(err)
	if code == http.StatusInternalServerError || kind == "agent_error" {
		s.log.ErrorContext(r.Context(), "agents screen", "path", r.URL.Path, "err", redact.Error(err))
	}
	msg := map[string]string{
		"not_found":      "Агент не найден: возможно, его уже удалили.",
		"not_configured": "Функция не настроена на сервере.",
		"in_progress":    "Операция уже выполняется, повторите позже.",
		"agent_error":    "Агент не ответил или отклонил запрос.",
	}[kind]
	if msg == "" {
		msg = "Не удалось выполнить действие."
	}
	renderFragment(w, r, http.StatusUnprocessableEntity, ModalError(msg)) //nolint:contextcheck // templ
}

// agentID проверяет {id}; для htmx-ручек. Возвращает ok=false и уже написанный ответ.
func (s *agentsScreen) agentID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !api.ValidAgentID(id) {
		http.NotFound(w, r)
		return "", false
	}
	return id, true
}

func (s *agentsScreen) configured(w http.ResponseWriter, _ *http.Request) bool {
	if s.d.Service.Configured() {
		return true
	}
	http.Error(w, "управление агентами не настроено", http.StatusNotImplemented)
	return false
}

func (s *agentsScreen) agentRow(w http.ResponseWriter, r *http.Request, id string) (AgentRowVM, api.AgentView, bool) {
	v, err := s.d.Service.Get(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			renderFragment(w, r, http.StatusNotFound, templ.Raw(`<div class="alert alert-err" role="alert">Агент не найден: возможно, его уже удалили.</div>`))
			return AgentRowVM{}, v, false
		}
		s.serverError(w, r, err)
		return AgentRowVM{}, v, false
	}
	return makeAgentRow(v, s.d.ServerVersion, s.now()), v, true
}

// ---------- действия ----------

func (s *agentsScreen) drain(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
			return
		}
		id, ok := s.agentID(w, r)
		if !ok {
			return
		}
		if err := s.d.Service.SetDraining(r.Context(), s.actor(r), id, on); err != nil {
			s.failToast(w, r, err)
			return
		}
		msg := "Агент выведен из балансировки (drain)"
		if !on {
			msg = "Агент возвращён в балансировку"
		}
		s.refresh(w, r, "ok", msg) //nolint:contextcheck // templ-компонент получает ctx в Render
	}
}

func (s *agentsScreen) rotateConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	row, _, ok := s.agentRow(w, r, id)
	if !ok {
		return
	}
	renderFragment(w, r, http.StatusOK, ConfirmDialog(ConfirmVM{ //nolint:contextcheck // templ
		Title: "Перевыпустить сертификат?", Text: "Для агента " + row.Name + " будет выпущен новый сертификат; ключ создаётся на агенте.",
		Note: "Соединения не обрываются. Старый сертификат отзывается после льготного периода.", Action: "/agents/" + id + "/rotate", Label: "Перевыпустить",
	}))
}

func (s *agentsScreen) rotate(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	err := s.d.Service.Rotate(r.Context(), s.actor(r), id, r.PostFormValue("confirm") == api.ConfirmYes)
	switch {
	case errors.Is(err, api.ErrConfirmRequired):
		http.Error(w, "требуется подтверждение", http.StatusBadRequest)
	case err != nil:
		s.failModal(w, r, err)
	default:
		s.closeAndRefresh(w, r, "Сертификат агента перевыпущен") //nolint:contextcheck // templ-компонент получает ctx в Render
	}
}

func (s *agentsScreen) modeForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	row, v, ok := s.agentRow(w, r, id)
	if !ok {
		return
	}
	f := ModeFormVM{ID: id, Name: row.Name, Mode: api.LinkOf(v), AgentURL: v.State.Agent.URL}
	renderFragment(w, r, http.StatusOK, ModeForm(f)) //nolint:contextcheck // templ
}

func (s *agentsScreen) modeApply(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	row, _, ok := s.agentRow(w, r, id)
	if !ok {
		return
	}
	f := ModeFormVM{ID: id, Name: row.Name, Mode: r.PostFormValue("mode"), AgentURL: strings.TrimSpace(r.PostFormValue("agent_url"))}
	err := s.d.Service.SetMode(r.Context(), s.actor(r), id, api.ModeInput{Mode: config.AgentMode(f.Mode), AgentURL: f.AgentURL})
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		f.Errors = ve.Fields
		renderFragment(w, r, http.StatusUnprocessableEntity, ModeForm(f)) //nolint:contextcheck // templ
	case errors.Is(err, api.ErrAgentUnreachable), errors.Is(err, api.ErrAgentRejected):
		s.log.ErrorContext(r.Context(), "agents screen: set mode", "agent", id, "err", redact.Error(err))
		f.Errors = api.FieldErrors{api.FieldGeneral: "Агент не принял смену режима: проверьте, что он доступен. Режим не изменён."}
		renderFragment(w, r, http.StatusUnprocessableEntity, ModeForm(f)) //nolint:contextcheck // templ
	case err != nil:
		s.failModal(w, r, err)
	default:
		s.closeAndRefresh(w, r, "Режим связи изменён") //nolint:contextcheck // templ-компонент получает ctx в Render
	}
}

func (s *agentsScreen) weightForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	row, _, ok := s.agentRow(w, r, id)
	if !ok {
		return
	}
	renderFragment(w, r, http.StatusOK, WeightForm(WeightFormVM{ID: id, Name: row.Name, Weight: row.Weight})) //nolint:contextcheck // templ
}

func (s *agentsScreen) weightApply(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	row, _, ok := s.agentRow(w, r, id)
	if !ok {
		return
	}
	f := WeightFormVM{ID: id, Name: row.Name, Weight: strings.TrimSpace(r.PostFormValue("weight"))}
	n, convErr := strconv.Atoi(f.Weight)
	var err error
	if convErr != nil {
		err = &api.ValidationError{Fields: api.FieldErrors{api.FieldWeight: "Вес — целое число"}}
	} else {
		err = s.d.Service.SetWeight(r.Context(), s.actor(r), id, n)
	}
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		f.Errors = ve.Fields
		renderFragment(w, r, http.StatusUnprocessableEntity, WeightForm(f)) //nolint:contextcheck // templ
	case err != nil:
		s.failModal(w, r, err)
	default:
		s.closeAndRefresh(w, r, "Вес агента изменён") //nolint:contextcheck // templ-компонент получает ctx в Render
	}
}

func (s *agentsScreen) more(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	row, v, ok := s.agentRow(w, r, id)
	if !ok {
		return
	}
	renderFragment(w, r, http.StatusOK, MoreCard(MoreVM{ //nolint:contextcheck // templ
		Row: row, CanRemove: s.d.Service.Capabilities().Remove, CanEmergency: s.canEmergency(v),
	}))
}

func (s *agentsScreen) deleteConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	row, _, ok := s.agentRow(w, r, id)
	if !ok {
		return
	}
	renderFragment(w, r, http.StatusOK, ConfirmDialog(ConfirmVM{ //nolint:contextcheck // templ
		Title: "Удалить агента?", Text: "Агент " + row.Name + " будет выведен из балансировки, его сертификаты попадут в denylist, запись удалится.",
		Note:   "Сервер дождётся завершения запросов (до 30 с). Действие нельзя отменить: для возврата агент ставится заново.",
		Action: "/agents/" + id + "/delete", Label: "Удалить", Danger: true,
	}))
}

func (s *agentsScreen) remove(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	row, _, ok := s.agentRow(w, r, id)
	if !ok {
		return
	}
	res, err := s.d.Service.Remove(r.Context(), s.actor(r), id, r.PostFormValue("confirm") == api.ConfirmYes)
	switch {
	case errors.Is(err, api.ErrConfirmRequired):
		http.Error(w, "требуется подтверждение", http.StatusBadRequest)
		return
	case err != nil:
		s.failModal(w, r, err)
		return
	}
	q, status := s.filters(r)
	toast(w, "ok", "Агент «"+row.Name+"» удалён")
	renderFragment(w, r, http.StatusOK, templ.Join( //nolint:contextcheck // templ
		RemovedPanel(RemovedVM{Name: row.Name, Revoked: res.Revoked, DrainTimedOut: res.DrainTimedOut, DrainUnchecked: res.DrainUnchecked}),
		AgentsBody(s.rows(r.Context(), q, status), true), //nolint:contextcheck // templ-компонент получает ctx в Render
	))
}
