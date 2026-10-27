package screens

import (
	"errors"
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// reissueOff отвечает 501, если выпуск токенов не подключён.
func (s *agentsScreen) reissueOff(w http.ResponseWriter) bool {
	if s.d.Enroll.Configured() {
		return false
	}
	http.Error(w, "подключение агентов по токену не настроено", http.StatusNotImplemented)
	return true
}

// reissueForm — диалог «Новый токен подключения» для существующего агента.
func (s *agentsScreen) reissueForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/agents") || !s.configured(w, r) || s.reissueOff(w) {
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
	renderFragment(w, r, http.StatusOK, ReissueForm(ReissueFormVM{ //nolint:contextcheck // templ
		ID: id, Name: row.Name, TTL: 60, ToReverse: v.State.Agent.Mode != store.ModeReverse,
	}))
}

// reissueIssue выпускает токен и показывает тот же блок, что мастер NAT: команды, отслеживание статуса, отзыв.
func (s *agentsScreen) reissueIssue(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || s.reissueOff(w) || !parseForm(w, r) {
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
	f := ReissueFormVM{ID: id, Name: row.Name, TTL: atoiOr(r.PostFormValue("ttl"), 60), ToReverse: v.State.Agent.Mode != store.ModeReverse}
	is, err := s.d.Enroll.IssueForAgent(r.Context(), s.actor(r), id, time.Duration(f.TTL)*time.Minute)
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		f.Errors = ve.Fields
		renderFragment(w, r, http.StatusUnprocessableEntity, ReissueForm(f)) //nolint:contextcheck // templ
		return
	case errors.Is(err, store.ErrNotFound):
		s.failModal(w, r, err)
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "agents screen: reissue enrollment", "agent", id, "err", redact.Error(err))
		f.Errors = api.FieldErrors{api.FieldGeneral: "Не удалось выпустить токен. Подробности в журнале сервера."}
		renderFragment(w, r, http.StatusUnprocessableEntity, ReissueForm(f)) //nolint:contextcheck // templ
		return
	}
	issued := NATIssuedVM{
		ID: is.ID, Name: row.Name, Cmdline: is.Cmdline, CmdlineInstalled: is.CmdlineInstalled,
		Expires: is.ExpiresAt.Local().Format("15:04"), Reissue: true,
		Status: EnrollStatusVM{ID: is.ID, State: api.EnrollWaiting, Name: row.Name, AgentID: id, Left: leftRu(is.ExpiresAt.Sub(s.now())), Reissue: true},
	}
	toast(w, "ok", "Токен для «"+row.Name+"» выпущен")
	renderFragment(w, r, http.StatusOK, natIssued(issued)) //nolint:contextcheck // templ
}
