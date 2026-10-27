package api

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// MTProtoAPI — JSON-хендлеры /api/v1/mtproto/secrets.
type MTProtoAPI struct {
	Service  *MTProtoService
	ClientIP func(*http.Request) string // nil — пустой IP в аудите
	// ActiveConns — число активных соединений секрета по имени (необязательно).
	ActiveConns func(name string) int
	// Fresh — middleware «свежий TOTP» (auth.RequireFreshTOTP(5m)). nil — /link закрыт (fail-closed).
	Fresh func(http.Handler) http.Handler
}

// MTProtoSecretJSON — секрет в ответах API. Ключа нет, только префикс.
type MTProtoSecretJSON struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Prefix      string   `json:"prefix"`
	CIDRs       []string `json:"cidrs"`
	MaxConns    int      `json:"max_conns"`
	Enabled     bool     `json:"enabled"`
	Status      string   `json:"status"` // active | grace | disabled | revoked
	CreatedAt   string   `json:"created_at"`
	RevokedAt   *string  `json:"revoked_at,omitempty"`
	GraceUntil  *string  `json:"grace_until,omitempty"`
	RotatedFrom *int64   `json:"rotated_from,omitempty"`
	ActiveConns *int     `json:"active_conns,omitempty"`
}

type mtLinkJSON struct {
	TG    string `json:"tg"`
	HTTPS string `json:"https"`
	QRSVG string `json:"qr_svg,omitempty"`
}

type mtResponse struct {
	MTProtoSecretJSON
	Link      *mtLinkJSON `json:"link,omitempty"`
	LinkError string      `json:"link_error,omitempty"`
	Disabled  bool        `json:"disabled"`
}

// Routes регистрирует маршруты. wrap — Protect+RequireAuth; nil — без обёртки.
func (a *MTProtoAPI) Routes(m Mounter, wrap Wrap) {
	m.Mount("GET /api/v1/mtproto/secrets", wrap.apply(http.HandlerFunc(a.list)))
	m.Mount("POST /api/v1/mtproto/secrets", wrap.apply(http.HandlerFunc(a.create)))
	m.Mount("PATCH /api/v1/mtproto/secrets/{id}", wrap.apply(http.HandlerFunc(a.patch)))
	m.Mount("DELETE /api/v1/mtproto/secrets/{id}", wrap.apply(http.HandlerFunc(a.revoke)))
	m.Mount("POST /api/v1/mtproto/secrets/{id}/rotate", wrap.apply(http.HandlerFunc(a.rotate)))
	m.Mount("GET /api/v1/mtproto/secrets/{id}/link", wrap.apply(a.fresh(http.HandlerFunc(a.reveal))))
}

func (a *MTProtoAPI) fresh(h http.Handler) http.Handler {
	if a.Fresh == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusUnauthorized, errorJSON{Error: "totp_required"})
		})
	}
	return a.Fresh(h)
}

func (a *MTProtoAPI) actor(r *http.Request) Actor { return actorOf(r, a.ClientIP) }

func (a *MTProtoAPI) toJSON(m store.MTProtoSecret) MTProtoSecretJSON {
	now := a.Service.now()
	out := MTProtoSecretJSON{
		ID: m.ID, Name: m.Name, Prefix: m.Prefix, CIDRs: mtCIDRStrings(m.CIDRs), MaxConns: m.MaxConns,
		Enabled: m.Enabled, CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339), RotatedFrom: m.RotatedFrom,
	}
	ts := func(t *time.Time) *string {
		if t == nil {
			return nil
		}
		s := t.UTC().Format(time.RFC3339)
		return &s
	}
	out.RevokedAt, out.GraceUntil = ts(m.RevokedAt), ts(m.GraceUntil)
	switch {
	case m.RevokedAt != nil && m.Active(now):
		out.Status = "grace"
	case m.RevokedAt != nil || (m.GraceUntil != nil && !m.GraceUntil.After(now)):
		out.Status = "revoked"
	case !m.Enabled:
		out.Status = "disabled"
	default:
		out.Status = "active"
	}
	if a.ActiveConns != nil {
		n := a.ActiveConns(m.Name)
		out.ActiveConns = &n
	}
	return out
}

func (a *MTProtoAPI) disabled() bool { return !a.Service.Endpoint().Enabled }

func (a *MTProtoAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "validation", Message: "ошибка валидации", Fields: ve.Fields})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorJSON{Error: "not_found"})
	case errors.Is(err, ErrMTProtoEndpoint):
		writeJSON(w, http.StatusConflict, errorJSON{Error: "endpoint_not_configured", Message: "Задайте mtproto.fronting_domain и public_host/public_base_url."})
	default:
		a.Service.log.ErrorContext(r.Context(), "mtproto api", "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorJSON{Error: "internal"})
	}
}

func (a *MTProtoAPI) list(w http.ResponseWriter, r *http.Request) {
	rows, err := a.Service.List(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]MTProtoSecretJSON, 0, len(rows))
	for _, m := range rows {
		items = append(items, a.toJSON(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "disabled": a.disabled()})
}

// created собирает ответ create/rotate: запись + ссылка один раз.
func (a *MTProtoAPI) created(c MTProtoCreated) mtResponse {
	out := mtResponse{MTProtoSecretJSON: a.toJSON(c.Secret), Disabled: a.disabled()}
	switch {
	case c.LinkErr != nil:
		out.LinkError = "endpoint_not_configured"
	default:
		out.Link = linkJSON(c.Links)
	}
	return out
}

func linkJSON(l MTProtoLinks) *mtLinkJSON {
	return &mtLinkJSON{TG: l.TG, HTTPS: l.HTTPS, QRSVG: qrSVG(l.HTTPS)}
}

func (a *MTProtoAPI) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string   `json:"name"`
		CIDRs    []string `json:"cidrs"`
		MaxConns int      `json:"max_conns"`
	}
	if !decode(w, r, &in) {
		return
	}
	res, err := a.Service.Create(r.Context(), a.actor(r), MTProtoCreateInput{Name: in.Name, CIDRs: in.CIDRs, MaxConns: in.MaxConns})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/mtproto/secrets/"+strconv.FormatInt(res.Secret.ID, 10))
	writeJSON(w, http.StatusCreated, a.created(res))
}

func (a *MTProtoAPI) patch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Name     *string   `json:"name"`
		CIDRs    *[]string `json:"cidrs"`
		MaxConns *int      `json:"max_conns"`
		Enabled  *bool     `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	got, err := a.Service.Update(r.Context(), a.actor(r), id, MTProtoUpdateInput{Name: in.Name, CIDRs: in.CIDRs, MaxConns: in.MaxConns, Enabled: in.Enabled})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.toJSON(got))
}

func (a *MTProtoAPI) revoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("confirm") != "yes" {
		writeJSON(w, http.StatusBadRequest, errorJSON{Error: "confirm_required", Message: "Добавьте ?confirm=yes: отзыв необратим."})
		return
	}
	if _, err := a.Service.Revoke(r.Context(), a.actor(r), id); err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (a *MTProtoAPI) rotate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Grace string `json:"grace"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	var grace time.Duration
	if g := strings.TrimSpace(in.Grace); g != "" && g != "0" {
		d, err := time.ParseDuration(g)
		if err != nil {
			a.fail(w, r, &ValidationError{Fields: FieldErrors{"grace": "Длительность вида 1h, 30m"}})
			return
		}
		grace = d
	}
	res, err := a.Service.Rotate(r.Context(), a.actor(r), id, grace)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.created(res))
}

func (a *MTProtoAPI) reveal(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	l, err := a.Service.Reveal(r.Context(), a.actor(r), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		mtLinkJSON
		Disabled bool `json:"disabled"`
	}{*linkJSON(l), a.disabled()})
}

// NewFreshTOTP — готовый Fresh для MTProtoAPI: auth.RequireFreshTOTP(auth.FreshTOTPWindow).
func NewFreshTOTP(a *auth.Auth) func(http.Handler) http.Handler {
	return a.RequireFreshTOTP(auth.FreshTOTPWindow)
}

// qrSVG рисует QR-код текста в виде SVG (1 модуль = 1 единица viewBox, тихая зона 4). Пусто при ошибке.
func qrSVG(text string) string {
	code, err := qr.Encode(text, qr.M, qr.Auto)
	if err != nil {
		return ""
	}
	return svgOf(code)
}

func svgOf(code barcode.Barcode) string {
	const quiet = 4
	b := code.Bounds()
	w, h := b.Dx(), b.Dy()
	var sb bytes.Buffer
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, w+2*quiet, h+2*quiet)
	fmt.Fprintf(&sb, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, w+2*quiet, h+2*quiet)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, bl, _ := code.At(b.Min.X+x, b.Min.Y+y).RGBA()
			if (r+g+bl)/3 < 0x8000 {
				fmt.Fprintf(&sb, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	sb.WriteString(`"/></svg>`)
	return sb.String()
}
