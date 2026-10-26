package screens

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/server/rollout"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const maxBatchSize = 50

// PackageCache сообщает, что релиз версии есть в кэше загрузок сервера (updater.Cache).
type PackageCache interface{ Has(version string) bool }

// RolloutHandle — раскатка агентов для экрана: API (старт/стоп/статус с аудитом) и кэш релизов.
type RolloutHandle struct {
	API      *api.RolloutAPI
	Packages PackageCache // nil — обновлять нельзя
}

// RolloutStepVM — шаг раскатки (один агент).
type RolloutStepVM struct {
	Agent, Phase, State, StateLabel, Error string
}

// RolloutVM — баннер активной раскатки.
type RolloutVM struct {
	Version, Plan string
	Stopping      bool
	Done, Total   int
	Steps         []RolloutStepVM
}

// RolloutFormVM — форма «Обновить отстающие».
type RolloutFormVM struct {
	Version, Batch string
	AllowDowntime  bool
	Lagging        int
	Errors         api.FieldErrors
}

func trimV(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

// lagging: версия агента известна и отличается от серверной.
func lagging(st agents.State, server string) bool {
	return server != "" && st.LastStatus != nil && st.LastStatus.Version != "" && trimV(st.LastStatus.Version) != trimV(server)
}

type rolloutInfo struct{ canUpdate bool }

func (s *agentsScreen) handle() *RolloutHandle {
	if s.d.Rollout == nil {
		return nil
	}
	h := s.d.Rollout()
	if h == nil || h.API == nil || h.API.Manager == nil {
		return nil
	}
	return h
}

// rolloutInfo заполняет баннер и версию в vm; canUpdate — можно ли запускать обновления прямо сейчас.
func (s *agentsScreen) rolloutInfo(ctx context.Context, vm *AgentsVM) rolloutInfo {
	h := s.handle()
	if h == nil || s.d.ServerVersion == "" {
		return rolloutInfo{}
	}
	vm.UpdateTo = "v" + trimV(s.d.ServerVersion)
	active := false
	switch st, err := h.API.Manager.Current(ctx); {
	case err == nil && st.Rollout.Active():
		active = true
		vm.Rollout = rolloutVM(st)
	case err != nil && !errors.Is(err, store.ErrNotFound):
		s.log.WarnContext(ctx, "agents: rollout current", "err", redact.Error(err))
	}
	return rolloutInfo{canUpdate: !active && h.Packages != nil && h.Packages.Has(trimV(s.d.ServerVersion))}
}

var stepLabels = map[string]string{
	store.StepPending: "ожидает", store.StepRunning: "выполняется", store.StepDone: "готово",
	store.StepSkipped: "пропущен", store.StepFailed: "ошибка",
}

func rolloutVM(st rollout.Status) *RolloutVM {
	r := st.Rollout
	vm := &RolloutVM{
		Version: "v" + trimV(r.Version), Stopping: r.State == store.RolloutStopping,
		Plan: "канарейка → батчи по " + strconv.Itoa(max(r.BatchSize, 1)),
	}
	for _, step := range st.Steps {
		vm.Total++
		if step.State == store.StepDone || step.State == store.StepSkipped {
			vm.Done++
		}
		phase := "батч"
		if step.Phase == store.PhaseCanary {
			phase = "канарейка"
		}
		vm.Steps = append(vm.Steps, RolloutStepVM{
			Agent: step.AgentID, Phase: phase, State: step.State, StateLabel: stepLabels[step.State], Error: redact.String(step.Error),
		})
	}
	return vm
}

func (s *agentsScreen) mountRollout(m func(string, http.HandlerFunc)) {
	m("GET /agents/rollout/start", s.rolloutForm)
	m("POST /agents/rollout/start", s.rolloutStart)
	m("GET /agents/rollout/stop", s.rolloutStopConfirm)
	m("POST /agents/rollout/stop", s.rolloutStop)
	m("GET /agents/{id}/update", s.updateConfirm)
	m("POST /agents/{id}/update", s.updateApply)
}

// rolloutReady: раскатка подключена и серверная версия известна; иначе ответ уже написан.
func (s *agentsScreen) rolloutReady(w http.ResponseWriter) (*RolloutHandle, bool) {
	h := s.handle()
	if h == nil || s.d.ServerVersion == "" {
		http.Error(w, "раскатка не настроена", http.StatusNotImplemented)
		return nil, false
	}
	return h, true
}

func rolloutMsg(err error) string {
	switch {
	case errors.Is(err, rollout.ErrBusy):
		return "Уже выполняется другая раскатка."
	case errors.Is(err, rollout.ErrNoActive):
		return "Нет выполняющейся раскатки."
	case errors.Is(err, rollout.ErrAgentDown):
		return "Агент недоступен: обновить можно только работающий агент."
	case errors.Is(err, rollout.ErrNoPackage):
		return "Релиз этой версии не найден в кэше загрузок сервера."
	case errors.Is(err, rollout.ErrUnknownAgent), errors.Is(err, store.ErrNotFound):
		return "Агент не найден."
	case errors.Is(err, rollout.ErrBadParams), errors.Is(err, rollout.ErrBadVersion):
		return "Недопустимые параметры раскатки."
	}
	return "Не удалось выполнить действие. Подробности в журнале сервера."
}

func (s *agentsScreen) rolloutFail(w http.ResponseWriter, r *http.Request, err error) {
	if rolloutMsg(err) == "Не удалось выполнить действие. Подробности в журнале сервера." {
		s.log.ErrorContext(r.Context(), "agents screen: rollout", "path", r.URL.Path, "err", redact.Error(err))
	}
	renderFragment(w, r, http.StatusUnprocessableEntity, ModalError(rolloutMsg(err))) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *agentsScreen) laggingCount() int {
	n := 0
	for _, v := range s.d.Service.List() {
		if lagging(v.State, s.d.ServerVersion) {
			n++
		}
	}
	return n
}

func (s *agentsScreen) rolloutForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) {
		return
	}
	if _, ok := s.rolloutReady(w); !ok {
		return
	}
	f := RolloutFormVM{Version: "v" + trimV(s.d.ServerVersion), Batch: "1", Lagging: s.laggingCount()}
	renderFragment(w, r, http.StatusOK, RolloutForm(f)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *agentsScreen) rolloutStart(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
		return
	}
	h, ok := s.rolloutReady(w)
	if !ok {
		return
	}
	f := RolloutFormVM{
		Version: "v" + trimV(s.d.ServerVersion), Batch: strings.TrimSpace(r.PostFormValue("batch_size")),
		AllowDowntime: r.PostFormValue("allow_downtime") != "", Lagging: s.laggingCount(),
	}
	batch, err := strconv.Atoi(f.Batch)
	if err != nil || batch < 1 || batch > maxBatchSize {
		f.Errors = api.FieldErrors{"batch_size": "Целое от 1 до " + strconv.Itoa(maxBatchSize)}
		renderFragment(w, r, http.StatusUnprocessableEntity, RolloutForm(f)) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	if r.PostFormValue("confirm") != api.ConfirmYes {
		hidden := [][2]string{{"batch_size", strconv.Itoa(batch)}}
		if f.AllowDowntime {
			hidden = append(hidden, [2]string{"allow_downtime", "1"})
		}
		note := "Сначала обновится один агент-канарейка, затем батчи по " + strconv.Itoa(batch) + ". Каждый агент выводится из балансировки на время обновления."
		if f.AllowDowntime {
			note += " Разрешён простой: последний активный агент тоже будет выведен."
		}
		renderFragment(w, r, http.StatusOK, ConfirmDialog(ConfirmVM{ //nolint:contextcheck // templ-компонент получает ctx в Render
			Title: "Запустить раскатку " + f.Version + "?", Text: "Будет обновлено агентов: " + strconv.Itoa(f.Lagging) + ".",
			Note: note, Action: "/agents/rollout/start", Label: "Запустить", Hidden: hidden,
		}))
		return
	}
	if _, err := h.API.StartRollout(r.Context(), s.actor(r), f.Version, batch, f.AllowDowntime); err != nil {
		s.rolloutFail(w, r, err)
		return
	}
	s.closeAndRefresh(w, r, "Раскатка "+f.Version+" запущена")
}

func (s *agentsScreen) rolloutStopConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) {
		return
	}
	if _, ok := s.rolloutReady(w); !ok {
		return
	}
	renderFragment(w, r, http.StatusOK, ConfirmDialog(ConfirmVM{ //nolint:contextcheck // templ-компонент получает ctx в Render
		Title: "Остановить раскатку?", Text: "Агенты, которые обновляются сейчас, завершат шаг; новые шаги начаты не будут.",
		Action: "/agents/rollout/stop", Label: "Остановить", Danger: true,
	}))
}

func (s *agentsScreen) rolloutStop(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
		return
	}
	h, ok := s.rolloutReady(w)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != api.ConfirmYes {
		http.Error(w, "требуется подтверждение", http.StatusBadRequest)
		return
	}
	if _, err := h.API.StopRollout(r.Context(), s.actor(r)); err != nil {
		s.rolloutFail(w, r, err)
		return
	}
	s.closeAndRefresh(w, r, "Раскатка останавливается")
}

func (s *agentsScreen) updateConfirm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) {
		return
	}
	if _, ok := s.rolloutReady(w); !ok {
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
	renderFragment(w, r, http.StatusOK, ConfirmDialog(ConfirmVM{ //nolint:contextcheck // templ-компонент получает ctx в Render
		Title: "Обновить агент?", Text: "Агент " + row.Name + " будет выведен из балансировки, обновлён до v" + trimV(s.d.ServerVersion) + " и возвращён.",
		Note: "Неудачное обновление агент откатывает сам.", Action: "/agents/" + id + "/update", Label: "Обновить",
	}))
}

func (s *agentsScreen) updateApply(w http.ResponseWriter, r *http.Request) {
	if !htmxOnly(w, r) || !s.configured(w, r) || !parseForm(w, r) {
		return
	}
	h, ok := s.rolloutReady(w)
	if !ok {
		return
	}
	id, ok := s.agentID(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != api.ConfirmYes {
		http.Error(w, "требуется подтверждение", http.StatusBadRequest)
		return
	}
	if _, err := h.API.UpdateAgent(r.Context(), s.actor(r), id, "v"+trimV(s.d.ServerVersion)); err != nil {
		s.rolloutFail(w, r, err)
		return
	}
	s.closeAndRefresh(w, r, "Обновление агента запущено")
}
