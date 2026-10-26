package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/server/agents"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Действия аудита управления агентами. Секретов в деталях нет.
const (
	AuditAgentDrain   = "agent.drain"
	AuditAgentUndrain = "agent.undrain"
	AuditAgentRotate  = "agent.cert_rotate"
	AuditAgentMode    = "agent.mode"
	AuditAgentRemove  = "agent.remove"
	AuditAgentWeight  = "agent.weight"
)

// Границы веса агента в балансировке (через UI/API).
const (
	MinAgentWeight = 1
	MaxAgentWeight = 100
)

// ConfirmYes — значение подтверждения деструктивного действия (форма: confirm=yes, API: ?confirm=yes).
const ConfirmYes = "yes"

// Ошибки сервиса агентов.
var (
	// ErrNotConfigured — зависимость операции не подключена (wiring).
	ErrNotConfigured = errors.New("api: функция не настроена")
	// ErrConfirmRequired — деструктивное действие без подтверждения.
	ErrConfirmRequired = errors.New("api: требуется подтверждение")
	// ErrAgentUnreachable — агент не ответил на запрос сервера.
	ErrAgentUnreachable = errors.New("api: агент недоступен")
	// ErrAgentRejected — агент отклонил запрос сервера.
	ErrAgentRejected = errors.New("api: агент отклонил запрос")
)

var agentIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// AgentSource — реестр агентов (реализует *agents.Registry).
type AgentSource interface {
	List() []agents.State
	Get(id string) (agents.State, bool)
}

// AgentDrainer — включение/снятие drain (реализует *agents.Registry).
type AgentDrainer interface {
	SetDraining(ctx context.Context, id string, draining bool) error
}

// CertRotator — принудительная ротация сертификата (реализует *agents.Rotator).
type CertRotator interface {
	RotateNow(ctx context.Context, agentID string) error
}

// AgentRemover — удаление агента с отзывом сертификатов (реализует *agents.Remover).
type AgentRemover interface {
	Remove(ctx context.Context, agentID string) (agents.RemoveResult, error)
}

// ReverseConns — число reverse-соединений агента (реализует *transport.ReversePool).
type ReverseConns interface {
	Conns(agentID string) int
}

// WeightSetter меняет вес агента и применяет его в балансировщике (реализует *agents.Registry).
type WeightSetter interface {
	SetWeight(ctx context.Context, id string, weight int) error
}

// ModeSetter меняет режим связи агента: PUT /_agent/config агенту и сохранение режима в реестре.
// serverURL — адрес agent_gateway (для reverse/both), agentURL — адрес mTLS-порта агента (для dial/both).
type ModeSetter interface {
	SetMode(ctx context.Context, agentID string, mode config.AgentMode, serverURL, agentURL string) error
}

// AgentsConfig — зависимости AgentsService. Пустая зависимость отключает соответствующую операцию
// (ErrNotConfigured), кроме Agents и Audit.
type AgentsConfig struct {
	Agents  AgentSource
	Drainer AgentDrainer
	Rotator CertRotator
	Remover AgentRemover
	Mode    ModeSetter
	Weight  WeightSetter
	Reverse ReverseConns // nil — соединения не показываются, защита «сначала both» отключена
	Audit   store.AuditRepo
	// GatewayURL — публичный адрес agent_gateway (https://host:8444) для режимов reverse/both.
	GatewayURL string
	Logger     *slog.Logger
	Now        func() time.Time
	// OpTimeout — потолок одной операции (удаление ждёт drain до 30 с); 0 → 2 мин.
	OpTimeout time.Duration
}

// AgentsService — управление агентами с валидацией и аудитом. Общий для JSON API и HTML-экрана.
type AgentsService struct {
	cfg AgentsConfig
	log *slog.Logger
	now func() time.Time
}

// NewAgentsService создаёт сервис.
func NewAgentsService(cfg AgentsConfig) *AgentsService {
	s := &AgentsService{cfg: cfg, log: cfg.Logger, now: cfg.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.cfg.OpTimeout <= 0 {
		s.cfg.OpTimeout = 2 * time.Minute
	}
	return s
}

// Can сообщает, какие операции подключены (экран скрывает недоступные иконки).
type Can struct{ Drain, Rotate, Mode, Remove, Weight bool }

// Capabilities — доступные операции.
func (s *AgentsService) Capabilities() Can {
	return Can{
		Drain: s.cfg.Drainer != nil, Rotate: s.cfg.Rotator != nil,
		Mode: s.cfg.Mode != nil, Remove: s.cfg.Remover != nil, Weight: s.cfg.Weight != nil,
	}
}

// Configured — реестр агентов подключён.
func (s *AgentsService) Configured() bool { return s != nil && s.cfg.Agents != nil }

// AgentView — агент со всем, что показывается в таблице и JSON.
type AgentView struct {
	State        agents.State
	ReverseConns int
	HasConns     bool // источник соединений подключён
}

// List — снимок агентов.
func (s *AgentsService) List() []AgentView {
	if s.cfg.Agents == nil {
		return nil
	}
	list := s.cfg.Agents.List()
	out := make([]AgentView, 0, len(list))
	for _, st := range list {
		out = append(out, s.view(st))
	}
	return out
}

// Get — агент по id; store.ErrNotFound, если нет.
func (s *AgentsService) Get(id string) (AgentView, error) {
	if s.cfg.Agents == nil {
		return AgentView{}, ErrNotConfigured
	}
	st, ok := s.cfg.Agents.Get(id)
	if !ok {
		return AgentView{}, store.ErrNotFound
	}
	return s.view(st), nil
}

func (s *AgentsService) view(st agents.State) AgentView {
	v := AgentView{State: st}
	if s.cfg.Reverse != nil {
		v.ReverseConns, v.HasConns = s.cfg.Reverse.Conns(st.Agent.ID), true
	}
	return v
}

func (s *AgentsService) opCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	// Операции с побочными эффектами не должны обрываться закрытием вкладки на полпути.
	return context.WithTimeout(context.WithoutCancel(ctx), s.cfg.OpTimeout)
}

func (s *AgentsService) record(ctx context.Context, act Actor, action, target, detail string) {
	if s.cfg.Audit == nil {
		return
	}
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	if _, err := s.cfg.Audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: action, Target: target, IP: act.IP, Detail: detail,
	}); err != nil {
		s.log.ErrorContext(ctx, "agent audit failed", "action", action, "agent", target, "err", err)
	}
}

// ValidAgentID — идентификатор агента из URL.
func ValidAgentID(id string) bool { return agentIDRe.MatchString(id) }

func (s *AgentsService) exists(id string) error {
	if s.cfg.Agents == nil {
		return ErrNotConfigured
	}
	if _, ok := s.cfg.Agents.Get(id); !ok {
		return store.ErrNotFound
	}
	return nil
}

// SetDraining включает или снимает drain.
func (s *AgentsService) SetDraining(ctx context.Context, act Actor, id string, draining bool) error {
	if s.cfg.Drainer == nil {
		return ErrNotConfigured
	}
	if err := s.exists(id); err != nil {
		return err
	}
	octx, cancel := s.opCtx(ctx)
	defer cancel()
	if err := s.cfg.Drainer.SetDraining(octx, id, draining); err != nil {
		return err
	}
	action := AuditAgentUndrain
	if draining {
		action = AuditAgentDrain
	}
	s.record(ctx, act, action, id, "")
	return nil
}

// SetWeight меняет вес агента (1..100) и сразу применяет его в балансировщике.
func (s *AgentsService) SetWeight(ctx context.Context, act Actor, id string, weight int) error {
	if s.cfg.Weight == nil {
		return ErrNotConfigured
	}
	if err := s.exists(id); err != nil {
		return err
	}
	if weight < MinAgentWeight || weight > MaxAgentWeight {
		return &ValidationError{Fields: FieldErrors{FieldWeight: fmt.Sprintf("Вес — целое число от %d до %d", MinAgentWeight, MaxAgentWeight)}}
	}
	octx, cancel := s.opCtx(ctx)
	defer cancel()
	if err := s.cfg.Weight.SetWeight(octx, id, weight); err != nil {
		return err
	}
	s.record(ctx, act, AuditAgentWeight, id, fmt.Sprintf("weight=%d", weight))
	return nil
}

// Rotate перевыпускает сертификат агента сейчас. confirm — подтверждение (обязательно).
func (s *AgentsService) Rotate(ctx context.Context, act Actor, id string, confirm bool) error {
	if s.cfg.Rotator == nil {
		return ErrNotConfigured
	}
	if !confirm {
		return ErrConfirmRequired
	}
	if err := s.exists(id); err != nil {
		return err
	}
	octx, cancel := s.opCtx(ctx)
	defer cancel()
	if err := s.cfg.Rotator.RotateNow(octx, id); err != nil {
		return err
	}
	s.record(ctx, act, AuditAgentRotate, id, "")
	return nil
}

// ModeInput — запрос на смену режима связи.
type ModeInput struct {
	Mode     config.AgentMode
	AgentURL string // https://host:port; нужен для dial/both, если у агента адрес не задан
}

// FieldAgentURL — поле адреса агента в ошибках валидации.
const (
	FieldMode     = "mode"
	FieldAgentURL = "agent_url"
)

// SetMode меняет режим связи агента.
func (s *AgentsService) SetMode(ctx context.Context, act Actor, id string, in ModeInput) error {
	if s.cfg.Mode == nil {
		return ErrNotConfigured
	}
	v, err := s.Get(id)
	if err != nil {
		return err
	}
	fe := FieldErrors{}
	agentURL := strings.TrimSpace(in.AgentURL)
	switch in.Mode {
	case config.AgentModeDial, config.AgentModeReverse, config.AgentModeBoth:
	default:
		fe[FieldMode] = "Допустимо: dial, reverse, both"
	}
	if agentURL != "" {
		if u, perr := url.Parse(agentURL); perr != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.User != nil {
			fe[FieldAgentURL] = "Адрес вида https://host:порт"
		}
	}
	needURL := in.Mode == config.AgentModeDial || in.Mode == config.AgentModeBoth
	if needURL && agentURL == "" && v.State.Agent.URL == "" && fe[FieldAgentURL] == "" {
		fe[FieldAgentURL] = "Для режимов «→ агент» и «оба» укажите адрес агента: https://host:порт"
	}
	needGW := in.Mode == config.AgentModeReverse || in.Mode == config.AgentModeBoth
	if needGW && s.cfg.GatewayURL == "" && fe[FieldMode] == "" {
		fe[FieldMode] = "Адрес agent_gateway не настроен на сервере"
	}
	// Уход с dial на reverse без живых обратных соединений отрежет агента от сервера.
	if in.Mode == config.AgentModeReverse && v.State.Agent.Mode != store.ModeReverse && v.HasConns && v.ReverseConns == 0 && fe[FieldMode] == "" {
		fe[FieldMode] = "Агент ещё не подключился к серверу сам. Сначала включите «оба», дождитесь соединений, затем «агент →»"
	}
	if len(fe) > 0 {
		return &ValidationError{Fields: fe}
	}
	serverURL := ""
	if needGW {
		serverURL = s.cfg.GatewayURL
	}
	if agentURL == "" {
		agentURL = v.State.Agent.URL
	}
	octx, cancel := s.opCtx(ctx)
	defer cancel()
	if err := s.cfg.Mode.SetMode(octx, id, in.Mode, serverURL, agentURL); err != nil {
		return err
	}
	s.record(ctx, act, AuditAgentMode, id, "mode="+string(in.Mode))
	return nil
}

// RemoveResult — итог удаления для UI/JSON.
type RemoveResult = agents.RemoveResult

// Remove удаляет агента (drain, отзыв сертификатов, удаление записи). confirm обязателен.
func (s *AgentsService) Remove(ctx context.Context, act Actor, id string, confirm bool) (RemoveResult, error) {
	if s.cfg.Remover == nil {
		return RemoveResult{}, ErrNotConfigured
	}
	if !confirm {
		return RemoveResult{}, ErrConfirmRequired
	}
	if err := s.exists(id); err != nil {
		return RemoveResult{}, err
	}
	octx, cancel := s.opCtx(ctx)
	defer cancel()
	res, err := s.cfg.Remover.Remove(octx, id)
	if err != nil {
		return res, err
	}
	s.record(ctx, act, AuditAgentRemove, id, fmt.Sprintf("revoked=%d drain_timeout=%t unchecked=%t", res.Revoked, res.DrainTimedOut, res.DrainUnchecked))
	return res, nil
}

// ---------- TransportModeSetter ----------

// RefSource — адресат агента (реализует *agents.Registry).
type RefSource interface {
	Ref(id string) (transport.AgentRef, bool)
}

// TransportModeSetter — ModeSetter поверх AgentTransport: PUT /_agent/config по текущему каналу,
// затем режим сохраняется в реестре как есть (dial | reverse | both; у both адрес агента обязателен).
type TransportModeSetter struct {
	Agents    store.AgentRepo
	Refs      RefSource
	Transport transport.AgentTransport
	// Refresh применяет изменение реестра (Registry.Refresh); nil — не вызывается.
	Refresh func(ctx context.Context) error
}

type configBody struct {
	Mode      config.AgentMode `json:"mode"`
	ServerURL string           `json:"server_url"`
}

// SetMode реализует ModeSetter.
func (m TransportModeSetter) SetMode(ctx context.Context, id string, mode config.AgentMode, serverURL, agentURL string) error {
	ref, ok := m.Refs.Ref(id)
	if !ok {
		return store.ErrNotFound
	}
	rec, err := m.Agents.Get(ctx, id)
	if err != nil {
		return err
	}
	target := store.AgentMode(mode)
	if mode == config.AgentModeReverse {
		target = store.ModeReverse
	}
	if target != store.ModeReverse && agentURL == "" {
		return fmt.Errorf("%w: пустой адрес агента", store.ErrInvalid)
	}
	payload, err := json.Marshal(configBody{Mode: mode, ServerURL: serverURL})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://agent/_agent/config", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.URL = &url.URL{Path: "/_agent/config"}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.Transport.RoundTrip(ctx, ref, req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAgentUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%w: HTTP %d %s", ErrAgentRejected, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	rec.Mode = target
	if target != store.ModeReverse {
		rec.URL = agentURL
	}
	if _, err := m.Agents.Update(ctx, rec); err != nil {
		return fmt.Errorf("сохранение режима агента: %w", err)
	}
	if m.Refresh != nil {
		return m.Refresh(ctx)
	}
	return nil
}

// ---------- JSON API ----------

// AgentsAPI — JSON-хендлеры /api/v1/agents.
type AgentsAPI struct {
	Service  *AgentsService
	ClientIP func(*http.Request) string // nil — пустой IP в аудите
	Log      *slog.Logger
}

// AgentJSON — агент в ответах API.
type AgentJSON struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	URL          string   `json:"url,omitempty"`
	Mode         string   `json:"mode"`
	Link         string   `json:"link"` // dial | reverse | both (dial + живые обратные соединения)
	ReverseConns *int     `json:"reverse_conns,omitempty"`
	Weight       int      `json:"weight"`
	Status       string   `json:"status"` // up | degraded | down | draining
	Up           bool     `json:"up"`
	Draining     bool     `json:"draining"`
	LastSeen     *string  `json:"last_seen,omitempty"`
	Version      string   `json:"version,omitempty"`
	RPS1m        *float64 `json:"rps_1m,omitempty"`
	Inflight     *int     `json:"inflight,omitempty"`
	RTTMs        *float64 `json:"upstream_rtt_ms,omitempty"`
	CertNotAfter *string  `json:"cert_not_after,omitempty"`
}

// LinkOf — вид связи для UI: dial, reverse или both (сервер ходит сам, агент тоже подключён обратно).
func LinkOf(v AgentView) string {
	switch {
	case v.State.Agent.Mode == store.ModeReverse:
		return "reverse"
	case v.State.Agent.Mode == store.ModeBoth, v.HasConns && v.ReverseConns > 0:
		return "both"
	}
	return "dial"
}

// StatusOf — статус для UI.
func StatusOf(s agents.State) string {
	switch {
	case !s.Up:
		return "down"
	case s.Draining:
		return "draining"
	case s.ConsecutiveFails > 0:
		return "degraded"
	}
	return "up"
}

// ToJSON переводит агента в JSON-вид.
func (v AgentView) ToJSON() AgentJSON {
	st := v.State
	out := AgentJSON{
		ID: st.Agent.ID, Name: st.Agent.Name, URL: st.Agent.URL, Mode: string(st.Agent.Mode), Link: LinkOf(v),
		Weight: st.Agent.Weight, Status: StatusOf(st), Up: st.Up, Draining: st.Draining,
	}
	if v.HasConns {
		n := v.ReverseConns
		out.ReverseConns = &n
	}
	if !st.LastSeen.IsZero() {
		s := st.LastSeen.UTC().Format(time.RFC3339)
		out.LastSeen = &s
	}
	if ls := st.LastStatus; ls != nil {
		out.Version = ls.Version
		rps, inf, rtt := ls.RPS1m, ls.Inflight, ls.UpstreamRTTMs
		out.RPS1m, out.Inflight, out.RTTMs = &rps, &inf, &rtt
		if !ls.CertNotAfter.IsZero() {
			s := ls.CertNotAfter.UTC().Format(time.RFC3339)
			out.CertNotAfter = &s
		}
	}
	return out
}

// Routes регистрирует маршруты; wrap — Protect + RequireAuth.
func (a *AgentsAPI) Routes(m Registrar, wrap Wrap) {
	m.Handle("GET /api/v1/agents", wrap.apply(http.HandlerFunc(a.list)))
	m.Handle("POST /api/v1/agents/{id}/drain", wrap.apply(http.HandlerFunc(a.drain(true))))
	m.Handle("POST /api/v1/agents/{id}/undrain", wrap.apply(http.HandlerFunc(a.drain(false))))
	m.Handle("POST /api/v1/agents/{id}/rotate", wrap.apply(http.HandlerFunc(a.rotate)))
	m.Handle("POST /api/v1/agents/{id}/mode", wrap.apply(http.HandlerFunc(a.mode)))
	m.Handle("POST /api/v1/agents/{id}/weight", wrap.apply(http.HandlerFunc(a.weight)))
	m.Handle("DELETE /api/v1/agents/{id}", wrap.apply(http.HandlerFunc(a.remove)))
}

func (a *AgentsAPI) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func (a *AgentsAPI) actor(r *http.Request) Actor { return actorOf(r, a.ClientIP) }

func (a *AgentsAPI) id(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !ValidAgentID(id) {
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found"})
		return "", false
	}
	return id, true
}

// FailStatus переводит ошибку сервиса агентов в HTTP-код и вид ошибки.
func FailStatus(err error) (code int, kind string) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		return http.StatusUnprocessableEntity, "validation"
	case errors.Is(err, store.ErrNotFound), errors.Is(err, agents.ErrAgentUnknown):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, ErrConfirmRequired):
		return http.StatusBadRequest, "confirm_required"
	case errors.Is(err, ErrNotConfigured):
		return http.StatusNotImplemented, "not_configured"
	case errors.Is(err, agents.ErrRotationInProgress):
		return http.StatusConflict, "in_progress"
	case errors.Is(err, ErrAgentUnreachable), errors.Is(err, ErrAgentRejected):
		return http.StatusBadGateway, "agent_error"
	case errors.Is(err, store.ErrInvalid):
		return http.StatusUnprocessableEntity, "validation"
	}
	return http.StatusInternalServerError, "internal"
}

var failMessages = map[string]string{
	"not_found":        "Агент не найден.",
	"confirm_required": "Требуется подтверждение (confirm=yes).",
	"not_configured":   "Функция не настроена на сервере.",
	"in_progress":      "Операция уже выполняется.",
	"agent_error":      "Агент не ответил или отклонил запрос.",
	"validation":       "Ошибка валидации.",
	"internal":         "Внутренняя ошибка.",
}

func (a *AgentsAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	code, kind := FailStatus(err)
	body := errorJSON{Error: kind, Message: failMessages[kind]}
	var ve *ValidationError
	if errors.As(err, &ve) {
		body.Fields = ve.Fields
	}
	if kind == "internal" || kind == "agent_error" {
		a.log().ErrorContext(r.Context(), "agents api", "path", r.URL.Path, "err", err)
	}
	writeJSON(w, code, body)
}

func (a *AgentsAPI) list(w http.ResponseWriter, _ *http.Request) {
	list := a.Service.List()
	items := make([]AgentJSON, 0, len(list))
	for _, v := range list {
		items = append(items, v.ToJSON())
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *AgentsAPI) respondAgent(w http.ResponseWriter, r *http.Request, id string) {
	v, err := a.Service.Get(id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v.ToJSON())
}

func (a *AgentsAPI) drain(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.id(w, r)
		if !ok {
			return
		}
		if err := a.Service.SetDraining(r.Context(), a.actor(r), id, on); err != nil {
			a.fail(w, r, err)
			return
		}
		a.respondAgent(w, r, id)
	}
}

func (a *AgentsAPI) rotate(w http.ResponseWriter, r *http.Request) {
	id, ok := a.id(w, r)
	if !ok {
		return
	}
	if err := a.Service.Rotate(r.Context(), a.actor(r), id, r.URL.Query().Get("confirm") == ConfirmYes); err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondAgent(w, r, id)
}

func (a *AgentsAPI) mode(w http.ResponseWriter, r *http.Request) {
	id, ok := a.id(w, r)
	if !ok {
		return
	}
	var in struct {
		Mode     config.AgentMode `json:"mode"`
		AgentURL string           `json:"agent_url"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := a.Service.SetMode(r.Context(), a.actor(r), id, ModeInput{Mode: in.Mode, AgentURL: in.AgentURL}); err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondAgent(w, r, id)
}

func (a *AgentsAPI) weight(w http.ResponseWriter, r *http.Request) {
	id, ok := a.id(w, r)
	if !ok {
		return
	}
	var in struct {
		Weight int `json:"weight"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := a.Service.SetWeight(r.Context(), a.actor(r), id, in.Weight); err != nil {
		a.fail(w, r, err)
		return
	}
	a.respondAgent(w, r, id)
}

type removeJSON struct {
	Revoked        int  `json:"revoked"`
	DrainTimedOut  bool `json:"drain_timed_out"`
	DrainUnchecked bool `json:"drain_unchecked"`
}

func (a *AgentsAPI) remove(w http.ResponseWriter, r *http.Request) {
	id, ok := a.id(w, r)
	if !ok {
		return
	}
	res, err := a.Service.Remove(r.Context(), a.actor(r), id, r.URL.Query().Get("confirm") == ConfirmYes)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, removeJSON{Revoked: res.Revoked, DrainTimedOut: res.DrainTimedOut, DrainUnchecked: res.DrainUnchecked})
}
