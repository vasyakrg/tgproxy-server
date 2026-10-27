package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// FreshTOTPWindow — окно «свежего» TOTP для чувствительных действий (показ ссылки MTProto).
const FreshTOTPWindow = 5 * time.Minute

func freshKey(token string) string { return "totp:fresh:" + hashToken(token) }

// MarkTOTPFresh отмечает, что в сессии только что успешно проверен TOTP (время хранится
// в эфемерном хранилище под хешем токена, схема БД не меняется).
func (a *Auth) MarkTOTPFresh(ctx context.Context, s *Session) error {
	ts := strconv.FormatInt(a.now().Unix(), 10)
	if err := a.store.RateState().Set(ctx, freshKey(s.Token), []byte(ts), FreshTOTPWindow); err != nil {
		return err
	}
	return nil
}

// TOTPFresh сообщает, что TOTP в сессии проверялся не позднее window назад.
func (a *Auth) TOTPFresh(ctx context.Context, s *Session, window time.Duration) bool {
	w, err := a.store.RateState().Get(ctx, freshKey(s.Token))
	if err != nil {
		return false
	}
	ts, err := strconv.ParseInt(string(w.Value), 10, 64)
	if err != nil {
		return false
	}
	age := a.now().Sub(time.Unix(ts, 0))
	return age >= 0 && age <= window
}

// ConfirmTOTP повторно проверяет TOTP-код залогиненного пользователя и отмечает сессию свежей.
// Ошибки как у TOTPStep: ErrRateLimited, ErrLockedOut, *FailError{ErrInvalidCode}, ErrPendingInvalid.
func (a *Auth) ConfirmTOTP(ctx context.Context, s *Session, code, ip string) error {
	if err := a.gate(ctx, "totp", s.User, ip); err != nil {
		return err
	}
	usr, ok := a.users.Get(s.User)
	if !ok || usr.Disabled {
		return ErrPendingInvalid
	}
	if err := a.checkTOTP(ctx, s.User, usr, code, ip); err != nil {
		return err
	}
	return a.MarkTOTPFresh(ctx, s)
}

// RequireFreshTOTP пропускает запрос только при свежем TOTP в сессии; иначе 401 {"error":"totp_required"}.
// Ставится ВНУТРИ RequireAuth (нужна сессия в контексте); без сессии — тоже totp_required.
func (a *Auth) RequireFreshTOTP(window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, ok := SessionFromContext(r.Context())
			if !ok || s == nil || !a.TOTPFresh(r.Context(), s, window) {
				writeJSON(w, http.StatusUnauthorized, errBody{Error: "totp_required", Message: "Подтвердите TOTP-кодом."})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *Auth) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	s, ok := SessionFromContext(r.Context())
	if !ok || s == nil {
		deny(w, r)
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := a.ConfirmTOTP(r.Context(), s, in.Code, a.clientIP(r)); err != nil {
		if errors.Is(err, ErrPendingInvalid) || errors.Is(err, store.ErrNotFound) {
			deny(w, r)
			return
		}
		a.writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fresh_for_seconds": int(FreshTOTPWindow / time.Second)})
}
