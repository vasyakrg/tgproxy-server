package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// maxInstallBody — потолок тела запроса установки (ключ до 32 КиБ + поля).
const maxInstallBody = 64 << 10

// DefaultHeartbeat — период комментариев-«пингов» в SSE (держат соединение за прокси).
const DefaultHeartbeat = 15 * time.Second

// InstallAPI — JSON/SSE-хендлеры /api/v1/install-jobs и /api/v1/hostkeys/probe.
type InstallAPI struct {
	Service  *InstallService
	ClientIP func(*http.Request) string
	Log      *slog.Logger
	// Heartbeat — период SSE-комментариев; 0 → 15 с.
	Heartbeat time.Duration
}

// Routes регистрирует маршруты; wrap — Protect + RequireAuth.
func (a *InstallAPI) Routes(m Registrar, wrap Wrap) {
	m.Handle("POST /api/v1/hostkeys/probe", wrap.apply(http.HandlerFunc(a.probe)))
	m.Handle("POST /api/v1/install-jobs", wrap.apply(http.HandlerFunc(a.create)))
	m.Handle("GET /api/v1/install-jobs/{id}", wrap.apply(http.HandlerFunc(a.status)))
	m.Handle("GET /api/v1/install-jobs/{id}/events", wrap.apply(http.HandlerFunc(a.events)))
}

func (a *InstallAPI) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

type hostKeyJSON struct {
	Host        string `json:"host"`
	Algo        string `json:"algo"`
	Fingerprint string `json:"fingerprint"`
	Pinned      bool   `json:"pinned"`
	Match       bool   `json:"match,omitempty"`
}

// InstallError — тело ошибки API установки.
type InstallError struct {
	Error       string      `json:"error"`
	Message     string      `json:"message,omitempty"`
	Fields      FieldErrors `json:"fields,omitempty"`
	Algo        string      `json:"algo,omitempty"`
	Fingerprint string      `json:"fingerprint,omitempty"`
}

// InstallFail переводит ошибку установки в код и тело ответа API. Тексты не содержат секретов.
func InstallFail(err error) (int, InstallError) {
	var ve *ValidationError
	var unknown *installer.ErrHostKeyUnknown
	switch {
	case errors.As(err, &ve):
		return http.StatusUnprocessableEntity, InstallError{Error: "validation", Message: "Ошибка валидации.", Fields: ve.Fields}
	case errors.As(err, &unknown):
		return http.StatusConflict, InstallError{
			Error: "host_key_unknown", Message: "Ключ хоста не закреплён: получите отпечаток через /api/v1/hostkeys/probe и передайте его в confirmed_fingerprint.",
			Algo: unknown.Algo, Fingerprint: unknown.Fingerprint,
		}
	case errors.Is(err, ErrHostKeyChanged), errors.Is(err, installer.ErrHostKeyMismatch):
		return http.StatusConflict, InstallError{Error: "host_key_mismatch", Message: "Ключ хоста отличается от закреплённого: возможна подмена. Если хост переустановлен — выполните на сервере: tgproxy hostkeys forget <host:port>"}
	case errors.Is(err, ErrProbeFailed):
		return http.StatusBadGateway, InstallError{Error: "probe_failed", Message: redact.String(err.Error())}
	case errors.Is(err, ErrPendingGone):
		return http.StatusGone, InstallError{Error: "expired", Message: "Запрос устарел: введите данные заново."}
	case errors.Is(err, ErrNotConfigured):
		return http.StatusNotImplemented, InstallError{Error: "not_configured", Message: "Установка по SSH не настроена на сервере."}
	case errors.Is(err, ErrBadJob), errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, InstallError{Error: "not_found"}
	}
	return http.StatusInternalServerError, InstallError{Error: "internal", Message: "Внутренняя ошибка."}
}

func (a *InstallAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	code, body := InstallFail(err)
	if code == http.StatusInternalServerError || code == http.StatusBadGateway {
		a.log().ErrorContext(r.Context(), "install api", "path", r.URL.Path, "err", redact.Error(err))
	}
	writeJSON(w, code, body)
}

func (a *InstallAPI) probe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Port == 0 {
		in.Port = DefaultSSHPort
	}
	res, err := a.Service.Probe(r.Context(), in.Host, in.Port)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, hostKeyJSON{Host: res.Addr, Algo: res.Algo, Fingerprint: res.Fingerprint, Pinned: res.Pinned, Match: res.Match})
}

type jobCreatedJSON struct {
	ID        string `json:"id"`
	EventsURL string `json:"events_url"`
}

func (a *InstallAPI) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name                 string `json:"name"`
		Host                 string `json:"host"`
		SSHPort              int    `json:"ssh_port"`
		User                 string `json:"user"`
		AgentPort            int    `json:"agent_port"`
		Weight               int    `json:"weight"`
		Password             string `json:"password"`
		PrivateKey           string `json:"private_key"`
		Passphrase           string `json:"passphrase"`
		ConfirmedFingerprint string `json:"confirmed_fingerprint"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInstallBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorJSON{Error: "bad_request", Message: "некорректный JSON"})
		return
	}
	in := InstallInput{
		Name: body.Name, Host: body.Host, SSHPort: body.SSHPort, User: body.User, AgentPort: body.AgentPort, Weight: body.Weight,
		Password: []byte(body.Password), PrivateKey: []byte(body.PrivateKey), Passphrase: []byte(body.Passphrase),
		ConfirmedFingerprint: body.ConfirmedFingerprint,
	}
	defer in.Zero()
	if in.SSHPort == 0 {
		in.SSHPort = DefaultSSHPort
	}
	if in.AgentPort == 0 {
		in.AgentPort = DefaultAgentPort
	}
	if in.Weight == 0 {
		in.Weight = DefaultWeight
	}
	if in.User == "" {
		in.User = "root"
	}
	id, err := a.Service.Start(r.Context(), actorOf(r, a.ClientIP), in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/install-jobs/"+id)
	writeJSON(w, http.StatusAccepted, jobCreatedJSON{ID: id, EventsURL: "/api/v1/install-jobs/" + id + "/events"})
}

type stepJSON struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Status string `json:"status"`
}

type jobJSON struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind,omitempty"`
	AgentID    string     `json:"agent_id,omitempty"`
	Host       string     `json:"host"`
	State      string     `json:"state"`
	Error      string     `json:"error,omitempty"`
	Steps      []stepJSON `json:"steps"`
	CreatedAt  string     `json:"created_at"`
	FinishedAt *string    `json:"finished_at,omitempty"`
	LastSeq    int64      `json:"last_seq"`
}

// JobToJSON переводит снимок задачи в JSON-вид.
func jobToJSON(st installer.JobStatus) jobJSON {
	out := jobJSON{
		ID: st.ID, Kind: st.Kind, AgentID: st.AgentID, Host: st.Host, State: st.State, Error: redact.String(st.Error),
		Steps: make([]stepJSON, 0, len(st.Steps)), CreatedAt: st.CreatedAt.UTC().Format(time.RFC3339), LastSeq: st.LastSeq,
	}
	for _, s := range st.Steps {
		out.Steps = append(out.Steps, stepJSON{Key: s.Key, Label: s.Label, Status: s.Status})
	}
	if st.FinishedAt != nil {
		f := st.FinishedAt.UTC().Format(time.RFC3339)
		out.FinishedAt = &f
	}
	return out
}

func (a *InstallAPI) status(w http.ResponseWriter, r *http.Request) {
	st, err := a.Service.Status(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, jobToJSON(st))
}

// eventJSON — тело SSE-события (data:).
type eventJSON struct {
	Seq     int64  `json:"seq"`
	Kind    string `json:"kind"`
	Step    string `json:"step,omitempty"`
	Status  string `json:"status,omitempty"`
	Level   string `json:"level,omitempty"`
	Message string `json:"message"`
	At      string `json:"at"`
}

func toEventJSON(e installer.Event) eventJSON {
	return eventJSON{
		Seq: e.Seq, Kind: e.Kind, Step: e.Step, Status: e.Status, Level: e.Level,
		Message: redact.String(e.Message), At: e.At.UTC().Format(time.RFC3339),
	}
}

// lastEventID: заголовок Last-Event-ID (его шлёт EventSource при переподключении) или ?last_event_id=.
func lastEventID(r *http.Request) (int64, bool) {
	s := r.Header.Get("Last-Event-ID")
	if s == "" {
		s = r.URL.Query().Get("last_event_id")
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func writeSSE(w http.ResponseWriter, e installer.Event) error {
	b, err := json.Marshal(toEventJSON(e))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.Seq, sseName(e.Kind), b)
	return err
}

// SSE-имена событий: step, log, done, fail. Неуспех назван fail, а не error, чтобы не пересекаться со
// служебным событием error самого EventSource. Неизвестные виды сводятся к log (защита от инъекции строк).
func sseName(kind string) string {
	switch kind {
	case installer.EventStep, installer.EventLog, installer.EventDone:
		return kind
	case installer.EventError:
		return "fail"
	}
	return "log"
}

func terminal(kind string) bool { return kind == installer.EventDone || kind == installer.EventError }

func (a *InstallAPI) events(w http.ResponseWriter, r *http.Request) {
	after, ok := lastEventID(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorJSON{Error: "bad_request", Message: "некорректный Last-Event-ID"})
		return
	}
	missed, live, err := a.Service.Events(r.Context(), r.PathValue("id"), after)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	rc := http.NewResponseController(w)
	// Поток живёт дольше WriteTimeout сервера.
	_ = rc.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, "retry: 2000\n\n"); err != nil {
		return
	}
	if err := rc.Flush(); err != nil {
		return
	}
	for _, e := range missed {
		if writeSSE(w, e) != nil {
			return
		}
		if terminal(e.Kind) {
			_ = rc.Flush()
			return
		}
	}
	_ = rc.Flush()

	hb := a.Heartbeat
	if hb <= 0 {
		hb = DefaultHeartbeat
	}
	tick := time.NewTicker(hb)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-live:
			if !open {
				return
			}
			if writeSSE(w, e) != nil {
				return
			}
			_ = rc.Flush()
			if terminal(e.Kind) {
				return
			}
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}
