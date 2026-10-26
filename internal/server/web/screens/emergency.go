package screens

import (
	"errors"
	"net/http"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
)

// canEmergency: аварийное обновление подключено, версия сервера известна и у агента есть SSH-цель.
func (s *agentsScreen) canEmergency(v api.AgentView) bool {
	return s.d.Emergency.Configured() && s.d.ServerVersion != "" && v.State.Agent.SSHHost != ""
}

func (s *agentsScreen) emergencyConfirm(w http.ResponseWriter, r *http.Request) {
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
	if !s.canEmergency(v) {
		renderFragment(w, r, http.StatusUnprocessableEntity, ModalError(emergencyMsg(nil))) //nolint:contextcheck // templ
		return
	}
	version := trimV(s.d.ServerVersion)
	renderFragment(w, r, http.StatusOK, ConfirmDialog(ConfirmVM{ //nolint:contextcheck // templ
		Title:  "Аварийное обновление по SSH?",
		Text:   "Агент " + row.Name + " будет обновлён до v" + version + " в обход штатного канала: сервер зайдёт на " + v.State.Agent.SSHHost + " под tgproxy-deploy, загрузит проверенный релиз, установит его и перезапустит агента.",
		Note:   "Агент не выводится из балансировки: во время перезапуска запросы к нему могут оборваться. Используйте, только когда обычное обновление недоступно. Подпись релиза проверяется на сервере и повторно на хосте.",
		Action: "/agents/" + id + "/emergency", Label: "Обновить по SSH", Danger: true,
	}))
}

func (s *agentsScreen) emergencyApply(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	if !s.d.Emergency.Configured() || s.d.ServerVersion == "" {
		http.Error(w, "аварийное обновление не настроено", http.StatusNotImplemented)
		return
	}
	confirm := r.PostFormValue("confirm") == api.ConfirmYes
	job, err := s.d.Emergency.Start(r.Context(), s.actor(r), id, trimV(s.d.ServerVersion), confirm)
	switch {
	case errors.Is(err, api.ErrConfirmRequired):
		http.Error(w, "требуется подтверждение", http.StatusBadRequest)
		return
	case err != nil:
		if code, _, _ := api.EmergencyFail(err); code == http.StatusInternalServerError {
			s.log.ErrorContext(r.Context(), "agents screen: emergency update", "path", r.URL.Path, "err", redact.Error(err))
		}
		renderFragment(w, r, http.StatusUnprocessableEntity, ModalError(emergencyMsg(err))) //nolint:contextcheck // templ
		return
	}
	// Ход задачи — на странице лога установки (тот же SSE и чеклист шагов).
	s.redirectToJob(w, r, job)
}

func emergencyMsg(err error) string {
	if err == nil {
		return "Аварийное обновление недоступно: у агента нет сохранённой SSH-цели."
	}
	_, _, msg := api.EmergencyFail(err)
	return msg
}
