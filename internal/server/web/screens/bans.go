package screens

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// BansDeps — зависимости экрана «Баны».
type BansDeps struct {
	Auth     *auth.Auth       // RequireAuth и сессия (обязательно)
	Service  *api.BansService // создание/снятие/список банов (обязательно)
	Geo      GeoLookup        // nil — флаги не показываются
	ClientIP func(*http.Request) string
	Logger   *slog.Logger
	Now      func() time.Time
}

// BanRow — строка таблицы банов.
type BanRow struct {
	ID         int64
	IP         string
	Code, Flag string
	Source     string
	SourceTone views.Tone
	Actor      string
	Comment    string
	Left       string
	Permanent  bool
	Hits       string
	Level      int
}

// BansVM — модель страницы «Баны».
type BansVM struct {
	Rows []BanRow
	Geo  bool // база стран подключена (показывать атрибуцию)
}

// Варианты срока в форме бана.
const durPermanent = "permanent"

// BanFormVM — форма ручного бана (модалка на «Баны» и «Ошибки»).
type BanFormVM struct {
	IP       string
	Duration string // 1h | 24h | 7d | permanent
	Comment  string
	From     string // bans | errors: что обновлять после успеха
	Errors   api.FieldErrors
}

type bansScreen struct {
	rt  AccessRouter
	d   BansDeps
	log *slog.Logger
	now func() time.Time
}

// MountBans регистрирует экран «Баны»: GET /bans, GET /bans/new, POST /bans, POST /bans/{id}/delete.
// Все маршруты за Protect + RequireAuth; изменения — только через htmx.
func MountBans(rt AccessRouter, d BansDeps) {
	s := &bansScreen{rt: rt, d: d, log: d.Logger, now: d.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	m := func(pattern string, h http.HandlerFunc) {
		rt.Mount(pattern, auth.Protect(d.Auth.RequireAuth(h)))
	}
	m("GET /bans", s.page)
	m("GET /bans/new", s.newForm)
	m("POST /bans", s.create)
	m("POST /bans/{id}/delete", s.remove)
}

func (s *bansScreen) actor(r *http.Request) api.Actor {
	ip := remoteHost(r)
	if s.d.ClientIP != nil {
		ip = s.d.ClientIP(r)
	}
	if sess, _ := auth.SessionFromContext(r.Context()); sess != nil {
		return api.Actor{User: sess.User, IP: ip}
	}
	return api.Actor{IP: ip}
}

func banLeft(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "< 1 мин"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " мин"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + " ч"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + " дн"
}

func (s *bansScreen) rows(r *http.Request) ([]BanRow, error) {
	list, err := s.d.Service.List(r.Context())
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]BanRow, 0, len(list))
	for _, b := range list {
		out = append(out, s.row(b, now))
	}
	return out, nil
}

func (s *bansScreen) row(b store.Ban, now time.Time) BanRow {
	row := BanRow{
		ID: b.ID, IP: addrString(b.Prefix), Actor: b.Actor, Comment: b.Comment,
		Hits: thousands(b.Hits), Level: b.Level, Source: "вручную", SourceTone: views.ToneNeutral,
		Left: "навсегда", Permanent: b.ExpiresAt == nil,
	}
	if b.Source == store.BanAuto {
		row.Source, row.SourceTone, row.Actor = "авто", views.ToneWarn, "система"
	}
	if b.ExpiresAt != nil {
		row.Left = banLeft(b.ExpiresAt.Sub(now))
	}
	row.Code, row.Flag = geoView(s.d.Geo, b.Prefix.Addr().String())
	return row
}

func (s *bansScreen) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "bans screen", "path", r.URL.Path, "err", err)
	http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
}

func (s *bansScreen) page(w http.ResponseWriter, r *http.Request) {
	rows, err := s.rows(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	renderPage(s.rt, w, r, http.StatusOK, "Баны", views.NavBans, BansPage(BansVM{Rows: rows, Geo: geoAvailable(s.d.Geo)})) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func normFrom(v string) string {
	if v == "errors" {
		return v
	}
	return "bans"
}

func (s *bansScreen) newForm(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/bans") {
		return
	}
	q := r.URL.Query()
	f := BanFormVM{IP: strings.TrimSpace(q.Get("ip")), Duration: "24h", From: normFrom(q.Get("from"))}
	renderFragment(w, r, http.StatusOK, BanForm(f)) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *bansScreen) create(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/bans") || !parseForm(w, r) {
		return
	}
	f := BanFormVM{
		IP: strings.TrimSpace(r.PostFormValue("ip")), Duration: r.PostFormValue("duration"),
		Comment: strings.TrimSpace(r.PostFormValue("comment")), From: normFrom(r.PostFormValue("from")),
	}
	in := api.BanInput{IP: f.IP, Comment: f.Comment}
	if f.Duration == durPermanent {
		in.Permanent = true
	} else {
		in.Duration = f.Duration
	}
	b, err := s.d.Service.Create(r.Context(), s.actor(r), in)
	var ve *api.ValidationError
	switch {
	case errors.As(err, &ve):
		f.Errors = ve.Fields
		renderFragment(w, r, http.StatusUnprocessableEntity, BanForm(f)) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	toast(w, "ok", "Забанен "+addrString(b.Prefix))
	if f.From != "bans" {
		renderFragment(w, r, http.StatusOK, BanModal(true)) //nolint:contextcheck // templ-компонент получает ctx в Render
		return
	}
	rows, err := s.rows(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	renderFragment(w, r, http.StatusOK, templ.Join(BanModal(true), BansSection(rows, true))) //nolint:contextcheck // templ-компонент получает ctx в Render
}

func (s *bansScreen) remove(w http.ResponseWriter, r *http.Request) {
	if !htmxOnlyTo(w, r, "/bans") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	b, err := s.d.Service.Delete(r.Context(), s.actor(r), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	rows, rerr := s.rows(r)
	if rerr != nil {
		s.serverError(w, r, rerr)
		return
	}
	if err == nil {
		toast(w, "ok", "Разбанен "+addrString(b.Prefix))
	} else {
		toast(w, "warn", "Бан уже снят")
	}
	renderFragment(w, r, http.StatusOK, BansSection(rows, false)) //nolint:contextcheck // templ-компонент получает ctx в Render
}
