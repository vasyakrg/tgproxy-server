package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// BansAPI — JSON-хендлеры /api/v1/bans.
type BansAPI struct {
	Service  *BansService
	ClientIP func(*http.Request) string // nil — пустой IP в аудите
	Country  func(prefix string) string // nil — страна не определяется
	Now      func() time.Time           // nil — time.Now
}

// BanJSON — бан в ответах API.
type BanJSON struct {
	ID           int64   `json:"id"`
	IP           string  `json:"ip"`
	Source       string  `json:"source"`
	Actor        string  `json:"actor"`
	Comment      string  `json:"comment,omitempty"`
	CreatedAt    string  `json:"created_at"`
	ExpiresAt    *string `json:"expires_at"` // null — бессрочно
	RemainingSec *int64  `json:"remaining_sec"`
	Hits         int64   `json:"hits"`
	Level        int     `json:"level"`
	Country      string  `json:"country,omitempty"`
}

// Routes регистрирует маршруты. wrap — Protect + RequireAuth; nil — без обёртки.
func (a *BansAPI) Routes(m Mounter, wrap Wrap) {
	m.Mount("GET /api/v1/bans", wrap.apply(http.HandlerFunc(a.list)))
	m.Mount("POST /api/v1/bans", wrap.apply(http.HandlerFunc(a.create)))
	m.Mount("DELETE /api/v1/bans/{id}", wrap.apply(http.HandlerFunc(a.remove)))
}

func (a *BansAPI) actor(r *http.Request) Actor {
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

func (a *BansAPI) toJSON(b store.Ban) BanJSON {
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	out := BanJSON{
		ID: b.ID, IP: DisplayAddr(b.Prefix), Source: string(b.Source), Actor: b.Actor, Comment: b.Comment,
		CreatedAt: b.CreatedAt.UTC().Format(time.RFC3339), Hits: b.Hits, Level: b.Level,
	}
	if b.ExpiresAt != nil {
		s := b.ExpiresAt.UTC().Format(time.RFC3339)
		left := max(int64(b.ExpiresAt.Sub(now).Seconds()), 0)
		out.ExpiresAt, out.RemainingSec = &s, &left
	}
	if a.Country != nil {
		out.Country = a.Country(b.Prefix.Addr().String())
	}
	return out
}

func (a *BansAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "validation", Message: "ошибка валидации", Fields: ve.Fields})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found"})
	default:
		a.Service.log.ErrorContext(r.Context(), "bans api", "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorJSON{Error: "internal"})
	}
}

func (a *BansAPI) list(w http.ResponseWriter, r *http.Request) {
	bans, err := a.Service.List(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]BanJSON, 0, len(bans))
	for _, b := range bans {
		items = append(items, a.toJSON(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *BansAPI) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP        string `json:"ip"`
		Duration  string `json:"duration"`
		Permanent bool   `json:"permanent"`
		Comment   string `json:"comment"`
	}
	if !decode(w, r, &in) {
		return
	}
	b, err := a.Service.Create(r.Context(), a.actor(r), BanInput{IP: in.IP, Duration: in.Duration, Permanent: in.Permanent, Comment: in.Comment})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, a.toJSON(b))
}

func (a *BansAPI) remove(w http.ResponseWriter, r *http.Request) {
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
