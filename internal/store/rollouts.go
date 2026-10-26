package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Состояния раскатки.
const (
	RolloutRunning  = "running"
	RolloutStopping = "stopping" // «Остановить» нажато: текущие шаги дорабатывают, новые не начинаются
	RolloutDone     = "done"
	RolloutFailed   = "failed"
	RolloutStopped  = "stopped"
)

// Состояния шага раскатки (один агент).
const (
	StepPending = "pending"
	StepRunning = "running"
	StepDone    = "done"
	StepSkipped = "skipped" // агент уже на версии или недоступен на момент планирования
	StepFailed  = "failed"
)

// Фазы раскатки.
const (
	PhaseCanary = "canary"
	PhaseBatch  = "batch"
)

// Rollout — раскатка версии на агентов (M6-T4). В каждый момент активна не более одной.
type Rollout struct {
	ID            string
	Version       string
	BatchSize     int
	Canary        int
	AllowDowntime bool // разрешить drain последнего активного агента
	State         string
	Error         string
	Actor         string
	CreatedAt     time.Time
	FinishedAt    *time.Time
}

// Active — раскатка ещё выполняется.
func (r Rollout) Active() bool { return r.State == RolloutRunning || r.State == RolloutStopping }

// RolloutStep — шаг раскатки: один агент. Seq задаёт порядок выполнения.
type RolloutStep struct {
	RolloutID   string
	AgentID     string
	Seq         int
	Phase       string
	State       string
	FromVersion string
	Error       string
	UpdatedAt   time.Time
}

// RolloutRepo — раскатки и их шаги.
type RolloutRepo interface {
	// Create атомарно создаёт раскатку и шаги. ErrConflict — id занят или уже есть активная раскатка.
	Create(ctx context.Context, r Rollout, steps []RolloutStep) error
	Get(ctx context.Context, id string) (Rollout, error)
	// Active возвращает выполняющуюся раскатку (ErrNotFound, если нет).
	Active(ctx context.Context) (Rollout, error)
	// Latest — самая свежая раскатка (ErrNotFound, если не было).
	Latest(ctx context.Context) (Rollout, error)
	// SetState меняет состояние; для финальных выставляется finished_at.
	SetState(ctx context.Context, id, state, errMsg string) error
	// Steps — шаги по возрастанию Seq.
	Steps(ctx context.Context, id string) ([]RolloutStep, error)
	// SetStep обновляет состояние шага; fromVersion записывается, если не пусто.
	SetStep(ctx context.Context, id, agentID, state, fromVersion, errMsg string) error
}

// Validate проверяет раскатку.
func (r Rollout) Validate() error {
	switch {
	case r.ID == "" || strings.TrimSpace(r.Version) == "":
		return fmt.Errorf("%w: rollout id and version are required", ErrInvalid)
	case r.BatchSize < 1 || r.Canary < 0:
		return fmt.Errorf("%w: rollout batch_size >= 1 and canary >= 0", ErrInvalid)
	case r.State == "":
		return fmt.Errorf("%w: rollout state is required", ErrInvalid)
	}
	return nil
}

// Validate проверяет шаг.
func (s RolloutStep) Validate() error {
	if s.AgentID == "" || s.State == "" || (s.Phase != PhaseCanary && s.Phase != PhaseBatch) {
		return fmt.Errorf("%w: rollout step agent, state and phase are required", ErrInvalid)
	}
	return nil
}
