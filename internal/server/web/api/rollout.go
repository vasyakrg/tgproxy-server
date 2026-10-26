package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/rollout"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Действия аудита раскатки.
const (
	AuditRolloutStart = "rollout.start"
	AuditRolloutStop  = "rollout.stop"
	AuditAgentUpdate  = "agent.update"
)

const maxRolloutBody = 4 << 10

// RolloutManager — раскатка агентов (*rollout.Manager).
type RolloutManager interface {
	Start(ctx context.Context, p rollout.Params) (rollout.Status, error)
	Stop(ctx context.Context) (rollout.Status, error)
	Current(ctx context.Context) (rollout.Status, error)
}

// RolloutAPI — JSON-ручки раскатки агентов (M6-T4):
//
//	POST /api/v1/rollouts                 {version, batch_size, allow_downtime}
//	GET  /api/v1/rollouts/current
//	POST /api/v1/rollouts/current/stop
//	POST /api/v1/agents/{id}/update       {version}
type RolloutAPI struct {
	Manager  RolloutManager
	Audit    store.AuditRepo
	ClientIP func(*http.Request) string
	Log      *slog.Logger
	Now      func() time.Time
}

// Routes регистрирует маршруты; wrap — Protect + RequireAuth.
func (a *RolloutAPI) Routes(m Registrar, wrap Wrap) {
	m.Handle("POST /api/v1/rollouts", wrap.apply(http.HandlerFunc(a.start)))
	m.Handle("GET /api/v1/rollouts/current", wrap.apply(http.HandlerFunc(a.current)))
	m.Handle("POST /api/v1/rollouts/current/stop", wrap.apply(http.HandlerFunc(a.stop)))
	m.Handle("POST /api/v1/agents/{id}/update", wrap.apply(http.HandlerFunc(a.updateAgent)))
}

func (a *RolloutAPI) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func (a *RolloutAPI) record(ctx context.Context, act Actor, action, target, detail string) {
	if a.Audit == nil {
		return
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	user := act.User
	if user == "" {
		user = "-"
	}
	if _, err := a.Audit.Append(ctx, store.AuditEntry{At: now(), Actor: user, Action: action, Target: target, IP: act.IP, Detail: detail}); err != nil {
		a.log().ErrorContext(ctx, "rollout audit failed", "action", action, "err", err)
	}
}

// RolloutStepJSON — шаг раскатки в JSON.
type RolloutStepJSON struct {
	AgentID     string    `json:"agent_id"`
	Seq         int       `json:"seq"`
	Phase       string    `json:"phase"`
	State       string    `json:"state"`
	FromVersion string    `json:"from_version,omitempty"`
	Error       string    `json:"error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RolloutProgress — счётчики шагов по состояниям.
type RolloutProgress struct {
	Total   int `json:"total"`
	Pending int `json:"pending"`
	Running int `json:"running"`
	Done    int `json:"done"`
	Skipped int `json:"skipped"`
	Failed  int `json:"failed"`
}

// RolloutJSON — раскатка в JSON.
type RolloutJSON struct {
	ID            string            `json:"id"`
	Version       string            `json:"version"`
	State         string            `json:"state"`
	Active        bool              `json:"active"`
	Error         string            `json:"error,omitempty"`
	BatchSize     int               `json:"batch_size"`
	Canary        int               `json:"canary"`
	AllowDowntime bool              `json:"allow_downtime"`
	Actor         string            `json:"actor,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	FinishedAt    *time.Time        `json:"finished_at,omitempty"`
	Progress      RolloutProgress   `json:"progress"`
	Steps         []RolloutStepJSON `json:"steps"`
}

// RolloutToJSON переводит снимок раскатки в JSON-вид (ошибки шагов повторно проходят redact на стороне manager).
func RolloutToJSON(st rollout.Status) RolloutJSON {
	r := st.Rollout
	out := RolloutJSON{
		ID: r.ID, Version: r.Version, State: r.State, Active: r.Active(), Error: r.Error, BatchSize: r.BatchSize,
		Canary: r.Canary, AllowDowntime: r.AllowDowntime, Actor: r.Actor, CreatedAt: r.CreatedAt, FinishedAt: r.FinishedAt,
		Steps: make([]RolloutStepJSON, 0, len(st.Steps)),
	}
	for _, s := range st.Steps {
		out.Steps = append(out.Steps, RolloutStepJSON{
			AgentID: s.AgentID, Seq: s.Seq, Phase: s.Phase, State: s.State, FromVersion: s.FromVersion, Error: s.Error, UpdatedAt: s.UpdatedAt,
		})
		out.Progress.Total++
		switch s.State {
		case store.StepPending:
			out.Progress.Pending++
		case store.StepRunning:
			out.Progress.Running++
		case store.StepDone:
			out.Progress.Done++
		case store.StepSkipped:
			out.Progress.Skipped++
		case store.StepFailed:
			out.Progress.Failed++
		}
	}
	return out
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRolloutBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "Ожидается JSON с полями запроса.")
		return false
	}
	return true
}

// rolloutFail переводит ошибку менеджера в код и тело ответа.
func (a *RolloutAPI) rolloutFail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, rollout.ErrBusy):
		writeErr(w, http.StatusConflict, "rollout_busy", "Уже выполняется другая раскатка.")
	case errors.Is(err, rollout.ErrNoActive):
		writeErr(w, http.StatusConflict, "no_active_rollout", "Нет выполняющейся раскатки.")
	case errors.Is(err, rollout.ErrUnknownAgent), errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "Не найдено.")
	case errors.Is(err, rollout.ErrAgentDown):
		writeErr(w, http.StatusConflict, "agent_down", "Агент недоступен: обновить можно только работающий агент.")
	case errors.Is(err, rollout.ErrNoPackage):
		writeErr(w, http.StatusUnprocessableEntity, "no_package", "Релиз этой версии не найден в кэше загрузок сервера: сначала скачайте его на экране «Система».")
	case errors.Is(err, rollout.ErrBadVersion):
		writeErr(w, http.StatusUnprocessableEntity, "bad_version", "Некорректная версия (ожидается 1.2.3).")
	case errors.Is(err, rollout.ErrBadParams):
		writeErr(w, http.StatusUnprocessableEntity, "validation", "Недопустимые параметры раскатки.")
	default:
		a.log().ErrorContext(r.Context(), "api: rollout", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "Внутренняя ошибка.")
	}
}

type startBody struct {
	Version       string `json:"version"`
	BatchSize     int    `json:"batch_size"`
	AllowDowntime bool   `json:"allow_downtime"`
}

// StartRollout запускает раскатку на всех отстающих агентов и пишет аудит (общий для API и HTML-экрана).
func (a *RolloutAPI) StartRollout(ctx context.Context, act Actor, version string, batch int, allowDowntime bool) (rollout.Status, error) {
	st, err := a.Manager.Start(context.WithoutCancel(ctx), rollout.Params{
		Version: version, BatchSize: batch, AllowDowntime: allowDowntime, Actor: act.User,
	})
	if err != nil {
		return st, err
	}
	a.record(ctx, act, AuditRolloutStart, st.Rollout.Version,
		fmt.Sprintf("rollout=%s batch=%d allow_downtime=%t", st.Rollout.ID, st.Rollout.BatchSize, st.Rollout.AllowDowntime))
	return st, nil
}

// StopRollout останавливает текущую раскатку и пишет аудит.
func (a *RolloutAPI) StopRollout(ctx context.Context, act Actor) (rollout.Status, error) {
	st, err := a.Manager.Stop(ctx)
	if err != nil {
		return st, err
	}
	a.record(ctx, act, AuditRolloutStop, st.Rollout.Version, "rollout="+st.Rollout.ID)
	return st, nil
}

// UpdateAgent обновляет одного агента (раскатка из одного шага, без канарейки) и пишет аудит.
func (a *RolloutAPI) UpdateAgent(ctx context.Context, act Actor, id, version string) (rollout.Status, error) {
	st, err := a.Manager.Start(context.WithoutCancel(ctx), rollout.Params{
		Version: version, Agents: []string{id}, NoCanary: true, Actor: act.User,
	})
	if err != nil {
		return st, err
	}
	a.record(ctx, act, AuditAgentUpdate, id, fmt.Sprintf("version=%s rollout=%s", st.Rollout.Version, st.Rollout.ID))
	return st, nil
}

func (a *RolloutAPI) start(w http.ResponseWriter, r *http.Request) {
	var b startBody
	if !decodeBody(w, r, &b) {
		return
	}
	st, err := a.StartRollout(r.Context(), actorOf(r, a.ClientIP), b.Version, b.BatchSize, b.AllowDowntime)
	if err != nil {
		a.rolloutFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, RolloutToJSON(st))
}

func (a *RolloutAPI) current(w http.ResponseWriter, r *http.Request) {
	st, err := a.Manager.Current(r.Context())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no_rollout", "Раскаток ещё не было.")
			return
		}
		a.rolloutFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, RolloutToJSON(st))
}

func (a *RolloutAPI) stop(w http.ResponseWriter, r *http.Request) {
	st, err := a.StopRollout(r.Context(), actorOf(r, a.ClientIP))
	if err != nil {
		a.rolloutFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, RolloutToJSON(st))
}

type updateBody struct {
	Version string `json:"version"`
}

func (a *RolloutAPI) updateAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !ValidAgentID(id) {
		writeErr(w, http.StatusNotFound, "not_found", "Агент не найден.")
		return
	}
	var b updateBody
	if !decodeBody(w, r, &b) {
		return
	}
	st, err := a.UpdateAgent(r.Context(), actorOf(r, a.ClientIP), id, b.Version)
	if err != nil {
		a.rolloutFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, RolloutToJSON(st))
}
