package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

const maxBodyBytes = 4 << 10

type errBody struct {
	Error        string `json:"error"`
	Message      string `json:"message,omitempty"`
	AttemptsLeft *int   `json:"attempts_left,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{Error: "bad_request", Message: "некорректный запрос"})
		return false
	}
	return true
}

// Routes регистрирует /api/v1/auth/{login,totp,logout,me}. Все маршруты уже под Protect
// (CSRF + заголовки); /me и /logout-сессия определяются по cookie.
func (a *Auth) Routes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/auth/login", Protect(http.HandlerFunc(a.handleLogin)))
	mux.Handle("POST /api/v1/auth/totp", Protect(http.HandlerFunc(a.handleTOTP)))
	mux.Handle("POST /api/v1/auth/logout", Protect(http.HandlerFunc(a.handleLogout)))
	mux.Handle("POST /api/v1/auth/totp/confirm", Protect(a.RequireAuth(http.HandlerFunc(a.handleTOTPConfirm))))
	mux.Handle("GET /api/v1/auth/me", Protect(a.RequireAuth(http.HandlerFunc(a.handleMe))))
}

// writeFail переводит ошибку шага входа в HTTP-ответ.
func (a *Auth) writeFail(w http.ResponseWriter, err error) {
	var fe *FailError
	switch {
	case errors.As(err, &fe):
		code, msg := "invalid_credentials", "Неверное имя пользователя или пароль."
		if errors.Is(fe.Err, ErrInvalidCode) {
			code, msg = "invalid_code", "Неверный код."
		}
		left := fe.AttemptsLeft
		writeJSON(w, http.StatusUnauthorized, errBody{Error: code, Message: msg, AttemptsLeft: &left})
	case errors.Is(err, ErrRateLimited):
		w.Header().Set("Retry-After", strconv.Itoa(int(rateWindow/time.Second)))
		writeJSON(w, http.StatusTooManyRequests, errBody{Error: "rate_limited", Message: "Слишком много попыток. Повторите через минуту."})
	case errors.Is(err, ErrLockedOut):
		w.Header().Set("Retry-After", strconv.Itoa(int(LockoutDuration/time.Second)))
		writeJSON(w, http.StatusTooManyRequests, errBody{Error: "locked_out", Message: "Вход временно заблокирован на 15 минут."})
	case errors.Is(err, ErrTOTPNotConfigured):
		writeJSON(w, http.StatusForbidden, errBody{Error: "totp_not_configured", Message: "Настройте TOTP: tgproxy totp enroll."})
	case errors.Is(err, ErrPendingInvalid):
		http.SetCookie(w, cookie(PendingCookie, "", -1))
		writeJSON(w, http.StatusUnauthorized, errBody{Error: "pending_expired", Message: "Сессия входа истекла, начните заново."})
	default:
		a.log.Error("login step failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{Error: "internal", Message: "Внутренняя ошибка."})
	}
}

type userBody struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

func (a *Auth) startSession(w http.ResponseWriter, s *Session) {
	a.sessions.SetCookie(w, s)
	http.SetCookie(w, cookie(PendingCookie, "", -1))
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	ip := a.clientIP(r)
	pending, _, err := a.PasswordStep(r.Context(), in.Username, in.Password, ip)
	if err != nil {
		a.writeFail(w, err)
		return
	}
	if !a.TOTPRequired(in.Username) { // DEV: allow_password_only
		s, err := a.TOTPStep(r.Context(), pending, "", ip)
		if err != nil {
			a.writeFail(w, err)
			return
		}
		a.startSession(w, s)
		writeJSON(w, http.StatusOK, map[string]any{"totp_required": false, "user": a.userBody(s)})
		return
	}
	// pending — в HttpOnly-cookie, JS его не видит.
	http.SetCookie(w, cookie(PendingCookie, pending, int(PendingTTL/time.Second)))
	writeJSON(w, http.StatusOK, map[string]any{"totp_required": true})
}

func (a *Auth) handleTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	c, err := r.Cookie(PendingCookie)
	if err != nil {
		a.writeFail(w, ErrPendingInvalid)
		return
	}
	s, err := a.TOTPStep(r.Context(), c.Value, in.Code, a.clientIP(r))
	if err != nil {
		a.writeFail(w, err)
		return
	}
	a.startSession(w, s)
	writeJSON(w, http.StatusOK, map[string]any{"user": a.userBody(s)})
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s, err := a.sessions.Get(r); err == nil {
		if err := a.Logout(r.Context(), s, a.clientIP(r)); err != nil {
			a.log.Error("logout", "err", err)
		}
	}
	a.sessions.ClearCookie(w)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) handleMe(w http.ResponseWriter, r *http.Request) {
	s, _ := SessionFromContext(r.Context())
	writeJSON(w, http.StatusOK, a.userBody(s))
}

func (a *Auth) userBody(s *Session) userBody {
	b := userBody{Username: s.User, ExpiresAt: s.ExpiresAt.UTC().Format(time.RFC3339)}
	if u, ok := a.users.Get(s.User); ok {
		b.DisplayName, b.Email = u.DisplayName, u.Email
	}
	return b
}
