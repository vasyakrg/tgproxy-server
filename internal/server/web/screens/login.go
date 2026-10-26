package screens

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
)

const loginMaxForm = 8 << 10

// LoginRouter — то, что нужно экрану входа от *web.Router.
type LoginRouter interface {
	Mount(pattern string, h http.Handler)
}

type loginScreen struct {
	d   LoginDeps
	log *slog.Logger
}

// MountLogin регистрирует GET /login, POST /login/{password,totp,reset} и POST /logout.
// Все маршруты за auth.Protect (CSRF, security-заголовки).
func MountLogin(rt LoginRouter, d LoginDeps) {
	s := &loginScreen{d: d, log: d.Logger}
	if s.log == nil {
		s.log = slog.Default()
	}
	m := func(pattern string, h http.HandlerFunc) { rt.Mount(pattern, auth.Protect(h)) }
	m("GET /login", s.page)
	m("POST /login/password", s.password)
	m("POST /login/totp", s.totp)
	m("POST /login/reset", s.reset)
	m("POST /logout", s.logout)
}

func (s *loginScreen) ip(r *http.Request) string {
	if s.d.ClientIP != nil {
		return s.d.ClientIP(r)
	}
	return remoteHost(r)
}

func isHX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// render отдаёт карточку (htmx) или всю страницу (обычный POST/GET).
func (s *loginScreen) render(w http.ResponseWriter, r *http.Request, status int, v LoginView) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Add("Vary", "HX-Request")
	w.WriteHeader(status)
	c := templ.Component(LoginPage(v)) //nolint:contextcheck // templ-компонент получает ctx в Render
	if isHX(r) {
		c = LoginCard(v) //nolint:contextcheck // templ-компонент получает ctx в Render
	}
	_ = c.Render(r.Context(), w)
}

func (s *loginScreen) page(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.Auth.Sessions().Get(r); err == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.render(w, r, http.StatusOK, LoginView{})
}

func pendingCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: auth.PendingCookie, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
}

func (s *loginScreen) form(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, loginMaxForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "некорректная форма", http.StatusBadRequest)
		return false
	}
	return true
}

// success завершает вход: htmx -> HX-Redirect, иначе 303 на «/».
func (s *loginScreen) success(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	s.d.Auth.Sessions().SetCookie(w, sess)
	http.SetCookie(w, pendingCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")
	if isHX(r) {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *loginScreen) password(w http.ResponseWriter, r *http.Request) {
	if !s.form(w, r) {
		return
	}
	username, password := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password")
	ip := s.ip(r)
	pending, _, err := s.d.Auth.PasswordStep(r.Context(), username, password, ip)
	if err != nil {
		s.fail(w, r, StepPassword, username, err)
		return
	}
	if !s.d.Auth.TOTPRequired(username) { // DEV: allow_password_only
		sess, err := s.d.Auth.TOTPStep(r.Context(), pending, "", ip)
		if err != nil {
			s.fail(w, r, StepPassword, username, err)
			return
		}
		s.success(w, r, sess)
		return
	}
	http.SetCookie(w, pendingCookie(pending, int(auth.PendingTTL/time.Second)))
	s.render(w, r, http.StatusOK, LoginView{Step: StepTOTP})
}

func (s *loginScreen) totp(w http.ResponseWriter, r *http.Request) {
	if !s.form(w, r) {
		return
	}
	c, err := r.Cookie(auth.PendingCookie)
	if err != nil {
		s.fail(w, r, StepTOTP, "", auth.ErrPendingInvalid)
		return
	}
	code := strings.Join(strings.Fields(r.PostFormValue("code")), "")
	sess, err := s.d.Auth.TOTPStep(r.Context(), c.Value, code, s.ip(r))
	if err != nil {
		s.fail(w, r, StepTOTP, "", err)
		return
	}
	s.success(w, r, sess)
}

// reset — «← Другой пользователь»: сбрасывает pending и возвращает первый шаг.
func (s *loginScreen) reset(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.PendingCookie); err == nil {
		_ = s.d.Auth.Sessions().Destroy(r.Context(), c.Value)
	}
	http.SetCookie(w, pendingCookie("", -1))
	if !isHX(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, LoginView{})
}

func (s *loginScreen) logout(w http.ResponseWriter, r *http.Request) {
	if sess, err := s.d.Auth.Sessions().Get(r); err == nil {
		if err := s.d.Auth.Logout(context.WithoutCancel(r.Context()), sess, s.ip(r)); err != nil {
			s.log.ErrorContext(r.Context(), "logout", "err", err)
		}
	}
	s.d.Auth.Sessions().ClearCookie(w)
	http.SetCookie(w, pendingCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")
	if isHX(r) {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// fail переводит ошибку шага в сообщение. Сообщение об ошибке пароля/кода одинаковое:
// не раскрывает, что именно неверно.
func (s *loginScreen) fail(w http.ResponseWriter, r *http.Request, step LoginStep, username string, err error) {
	v := LoginView{Step: step, Username: username}
	status := http.StatusUnauthorized
	var fe *auth.FailError
	switch {
	case errors.As(err, &fe):
		v.Message = "Неверный логин, пароль или код. Осталось попыток: " + strconv.Itoa(fe.AttemptsLeft) + "."
	case errors.Is(err, auth.ErrRateLimited):
		status = http.StatusTooManyRequests
		v.Message = "Слишком много попыток. Повторите через минуту."
		w.Header().Set("Retry-After", "60")
	case errors.Is(err, auth.ErrLockedOut):
		status = http.StatusTooManyRequests
		v.Message = "Вход временно заблокирован, попробуйте через " + loginLockoutMinutes + " мин."
		w.Header().Set("Retry-After", strconv.Itoa(int(auth.LockoutDuration/time.Second)))
	case errors.Is(err, auth.ErrTOTPNotConfigured):
		status = http.StatusForbidden
		v.Step = StepPassword
		v.Message = "Для этого пользователя не настроен TOTP. Выполните на сервере: tgproxy totp enroll"
	case errors.Is(err, auth.ErrPendingInvalid):
		http.SetCookie(w, pendingCookie("", -1))
		v.Step = StepPassword
		v.Message = "Сессия входа истекла, начните заново."
	default:
		s.log.ErrorContext(r.Context(), "login step failed", "step", int(step), "err", err)
		status = http.StatusInternalServerError
		v.Message = "Внутренняя ошибка. Попробуйте позже."
	}
	s.render(w, r, status, v)
}
