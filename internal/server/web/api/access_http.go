package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const maxBodyBytes = 64 << 10

// Mounter — то, куда регистрируются маршруты (*web.Router).
type Mounter interface {
	Mount(pattern string, h http.Handler)
}

// AccessAPI — JSON-хендлеры /api/v1/access-rules.
type AccessAPI struct {
	Service  *AccessService
	ClientIP func(*http.Request) string // nil — хост из RemoteAddr
	// BaseURL — публичный base URL для поля base_url в ответе создания (необязательно).
	BaseURL func() string
	// Stats — запросы за 24 ч и время последнего запроса по имени правила (необязательно).
	Stats func(name string) (requests24h int64, lastSeen time.Time, ok bool)
}

// RuleJSON — правило в ответах API. Ключа (даже хеша) здесь нет, только префикс.
type RuleJSON struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Kind        RuleKind `json:"kind"`
	CIDRs       []string `json:"cidrs"`
	HasKey      bool     `json:"has_key"`
	KeyPrefix   string   `json:"key_prefix,omitempty"`
	RPS         float64  `json:"rps"`
	Enabled     bool     `json:"enabled"`
	CreatedAt   string   `json:"created_at"`
	Requests24h *int64   `json:"requests_24h,omitempty"`
	LastSeen    *string  `json:"last_seen,omitempty"`
}

type createdJSON struct {
	RuleJSON
	Key     string `json:"key,omitempty"` // только в ответе создания
	BaseURL string `json:"base_url,omitempty"`
}

type errorJSON struct {
	Error   string      `json:"error"`
	Message string      `json:"message,omitempty"`
	Fields  FieldErrors `json:"fields,omitempty"`
}

// Routes регистрирует маршруты. wrap — обёртка wiring (Protect + RequireAuth); nil — без обёртки.
func (a *AccessAPI) Routes(m Mounter, wrap Wrap) {
	m.Mount("GET /api/v1/access-rules", wrap.apply(http.HandlerFunc(a.list)))
	m.Mount("POST /api/v1/access-rules", wrap.apply(http.HandlerFunc(a.create)))
	m.Mount("PATCH /api/v1/access-rules/{id}", wrap.apply(http.HandlerFunc(a.patch)))
	m.Mount("DELETE /api/v1/access-rules/{id}", wrap.apply(http.HandlerFunc(a.remove)))
}

func (a *AccessAPI) actor(r *http.Request) Actor {
	ip := ""
	if a.ClientIP != nil {
		ip = a.ClientIP(r)
	}
	s, _ := auth.SessionFromContext(r.Context())
	if s == nil {
		return Actor{IP: ip}
	}
	return Actor{User: s.User, IP: ip}
}

func (a *AccessAPI) toJSON(r store.AccessRule) RuleJSON {
	cidrs := make([]string, 0, len(r.CIDRs))
	for _, p := range r.CIDRs {
		cidrs = append(cidrs, p.String())
	}
	out := RuleJSON{
		ID: r.ID, Name: r.Name, Kind: KindOf(r), CIDRs: cidrs, HasKey: len(r.KeyHash) > 0,
		KeyPrefix: r.KeyPrefix, RPS: r.RPS, Enabled: r.Enabled && r.RevokedAt == nil,
		CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
	}
	if a.Stats != nil {
		if n, seen, ok := a.Stats(r.Name); ok {
			out.Requests24h = &n
			if !seen.IsZero() {
				s := seen.UTC().Format(time.RFC3339)
				out.LastSeen = &s
			}
		}
	}
	return out
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errorJSON{Error: "bad_request", Message: "некорректный JSON"})
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found"})
		return 0, false
	}
	return id, true
}

// fail переводит ошибку сервиса в ответ: 422 (с полями), 404 или 500.
func (a *AccessAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "validation", Message: "ошибка валидации", Fields: ve.Fields})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found"})
	default:
		a.Service.log.ErrorContext(r.Context(), "access-rules api", "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorJSON{Error: "internal"})
	}
}

func (a *AccessAPI) list(w http.ResponseWriter, r *http.Request) {
	rules, err := a.Service.List(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]RuleJSON, 0, len(rules))
	for _, x := range rules {
		items = append(items, a.toJSON(x))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *AccessAPI) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string   `json:"name"`
		CIDRs   []string `json:"cidrs"`
		WithKey bool     `json:"with_key"`
		RPS     float64  `json:"rps"`
	}
	if !decode(w, r, &in) {
		return
	}
	res, err := a.Service.Create(r.Context(), a.actor(r), CreateInput{Name: in.Name, CIDRs: in.CIDRs, WithKey: in.WithKey, RPS: in.RPS})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := createdJSON{RuleJSON: a.toJSON(res.Rule), Key: res.PlainKey}
	if a.BaseURL != nil {
		out.BaseURL = BaseURLFor(a.BaseURL(), res.PlainKey)
	}
	w.Header().Set("Location", "/api/v1/access-rules/"+strconv.FormatInt(res.Rule.ID, 10))
	writeJSON(w, http.StatusCreated, out)
}

func (a *AccessAPI) patch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Name    *string   `json:"name"`
		CIDRs   *[]string `json:"cidrs"`
		RPS     *float64  `json:"rps"`
		Enabled *bool     `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	got, err := a.Service.Update(r.Context(), a.actor(r), id, UpdateInput{Name: in.Name, CIDRs: in.CIDRs, RPS: in.RPS, Enabled: in.Enabled})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.toJSON(got))
}

func (a *AccessAPI) remove(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := a.Service.Delete(r.Context(), a.actor(r), id); err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// BaseURLFor собирает Base URL для бота: {base} для правил только-сеть, {base}/k/<key> с ключом.
func BaseURLFor(base, key string) string {
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	if key == "" {
		return base
	}
	return base + "/k/" + key
}
