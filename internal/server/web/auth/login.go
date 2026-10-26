package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Лимиты входа (architecture §8).
const (
	RateLimitPerMinute = 5
	LockoutThreshold   = 10 // неудач на пару (user, подсеть /24 IPv4 или /64 IPv6)
	// LockoutThresholdGlobal — неудач на пользователя суммарно из любых подсетей (порог выше,
	// чтобы одиночный чужой хост не мог заблокировать админа целиком).
	LockoutThresholdGlobal = 30
	LockoutDuration        = 15 * time.Minute
	failWindow             = LockoutDuration
	rateWindow             = time.Minute
	maxUsernameLen         = 128
)

// Ошибки входа. Сообщения намеренно не раскрывают, что именно неверно.
var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrInvalidCode        = errors.New("auth: invalid code")
	ErrRateLimited        = errors.New("auth: rate limited")
	ErrLockedOut          = errors.New("auth: locked out")
	ErrPendingInvalid     = errors.New("auth: pending login expired or invalid")
	ErrTOTPNotConfigured  = errors.New("auth: totp is not configured: run `tgproxy totp enroll`")
)

// FailError — неудачная попытка с числом оставшихся до блокировки попыток.
type FailError struct {
	Err          error
	AttemptsLeft int
}

func (e *FailError) Error() string { return e.Err.Error() }
func (e *FailError) Unwrap() error { return e.Err }

// LockoutNotifier — алерт о блокировке входа (реализует notify.Evaluator).
type LockoutNotifier interface {
	LoginLockout(ctx context.Context, user, ip string)
}

// Store — нужные auth части store.Store.
type Store interface {
	Sessions() store.SessionRepo
	RateState() store.RateStateRepo
	Audit() store.AuditRepo
}

// Options — зависимости Auth.
type Options struct {
	Users    *Users
	Store    Store
	TOTP     *TOTP
	Notifier LockoutNotifier // nil допустим
	// AllowPasswordOnly — DEV: пользователь без TOTP-секрета входит по одному паролю.
	AllowPasswordOnly bool
	Logger            *slog.Logger
	Now               func() time.Time             // nil -> time.Now
	ClientIP          func(r *http.Request) string // nil -> хост из RemoteAddr
}

// Auth — сервис веб-аутентификации.
type Auth struct {
	users    *Users
	store    Store
	totp     *TOTP
	notifier LockoutNotifier
	sessions *Manager
	allowPwd bool
	log      *slog.Logger
	now      func() time.Time
	clientIP func(r *http.Request) string
}

// New собирает Auth и подписывается на изменения users-файла для инвалидации сессий.
func New(o Options) *Auth {
	a := &Auth{
		users: o.Users, store: o.Store, totp: o.TOTP, notifier: o.Notifier,
		allowPwd: o.AllowPasswordOnly, log: o.Logger, now: o.Now, clientIP: o.ClientIP,
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.clientIP == nil {
		a.clientIP = remoteIP
	}
	a.sessions = NewManager(o.Store.Sessions(), a.now)
	o.Users.OnChange(func(names []string) {
		for _, n := range names {
			if _, err := a.sessions.DestroyUser(context.Background(), n); err != nil {
				a.log.Error("destroy sessions of changed user", "user", n, "err", err)
			}
		}
	})
	return a
}

// Sessions — менеджер сессий.
func (a *Auth) Sessions() *Manager { return a.sessions }

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func userKey(name string) string {
	h := sha256.Sum256([]byte(name))
	return hex.EncodeToString(h[:8])
}

// TOTPRequired — нужен ли второй шаг для пользователя (false только в режиме allow_password_only).
func (a *Auth) TOTPRequired(username string) bool {
	u, ok := a.users.Get(username)
	return !ok || u.TOTPSecretEnc != "" || !a.allowPwd
}

// gate: lockout и лимит 5/мин на IP+user. Применяется ДО проверки секретов.
func (a *Auth) gate(ctx context.Context, step, username, ip string) error {
	uk := userKey(username)
	for _, k := range []string{lockKey(username, ip), lockKeyGlobal(username)} {
		if _, err := a.store.RateState().Get(ctx, k); err == nil {
			return ErrLockedOut
		} else if !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("auth: lockout state: %w", err)
		}
	}
	n, err := a.store.RateState().Incr(ctx, "login:rl:"+step+":"+ip+"|"+uk, rateWindow)
	if err != nil {
		return fmt.Errorf("auth: rate state: %w", err)
	}
	if n > RateLimitPerMinute {
		if n == RateLimitPerMinute+1 { // в аудит — один раз за окно
			a.audit(ctx, a.actorFor(username), AuditLoginBlocked, ip, "rate_limited")
		}
		return ErrRateLimited
	}
	return nil
}

func (a *Auth) actorFor(username string) string {
	if _, ok := a.users.Get(username); ok {
		return username
	}
	return ""
}

// ipNet сводит IP к подсети учёта блокировок: /24 для IPv4, /64 для IPv6.
// Нераспознанная строка остаётся как есть (отдельная «подсеть»).
func ipNet(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	bits := 64
	if addr.Is4() {
		bits = 24
	}
	pfx, err := addr.Prefix(bits)
	if err != nil {
		return ip
	}
	return pfx.String()
}

func failKey(username, ip string) string   { return "login:fail:" + userKey(username) + "|" + ipNet(ip) }
func lockKey(username, ip string) string   { return "login:lock:" + userKey(username) + "|" + ipNet(ip) }
func failKeyGlobal(username string) string { return "login:failg:" + userKey(username) }
func lockKeyGlobal(username string) string { return "login:lockg:" + userKey(username) }

// registerFailure учитывает неудачу по паре (user, подсеть) и глобально по user; при достижении
// порога включает соответствующий lockout и шлёт алерт. Возвращает минимум оставшихся попыток.
func (a *Auth) registerFailure(ctx context.Context, username, ip, reason string) (int, error) {
	known := a.actorFor(username) != ""
	rs := a.store.RateState()
	n, err := rs.Incr(ctx, failKey(username, ip), failWindow)
	if err != nil {
		return 0, fmt.Errorf("auth: fail counter: %w", err)
	}
	ng, err := rs.Incr(ctx, failKeyGlobal(username), failWindow)
	if err != nil {
		return 0, fmt.Errorf("auth: fail counter: %w", err)
	}
	a.audit(ctx, a.actorFor(username), AuditLoginFail, ip, reason)
	if n >= LockoutThreshold {
		if err := a.lock(ctx, username, ip, lockKey(username, ip), failKey(username, ip), "threshold_reached", known); err != nil {
			return 0, err
		}
	}
	if ng >= LockoutThresholdGlobal {
		if err := a.lock(ctx, username, ip, lockKeyGlobal(username), failKeyGlobal(username), "threshold_reached_global", known); err != nil {
			return 0, err
		}
	}
	return max(0, min(LockoutThreshold-int(n), LockoutThresholdGlobal-int(ng))), nil
}

func (a *Auth) lock(ctx context.Context, username, ip, lockK, failK, detail string, known bool) error {
	rs := a.store.RateState()
	first, err := rs.SetNX(ctx, lockK, []byte("1"), LockoutDuration)
	if err != nil {
		return fmt.Errorf("auth: lockout state: %w", err)
	}
	if first {
		_ = rs.Delete(ctx, failK)
		a.audit(ctx, a.actorFor(username), AuditLoginLockout, ip, detail)
		if known && a.notifier != nil {
			a.notifier.LoginLockout(ctx, username, ip)
		}
	}
	return nil
}

func (a *Auth) failuresLeft(ctx context.Context, username, ip string) int {
	count := func(k string) int {
		w, err := a.store.RateState().Get(ctx, k)
		if err != nil {
			return 0
		}
		var n int
		_, _ = fmt.Sscanf(string(w.Value), "%d", &n)
		return n
	}
	return max(0, min(LockoutThreshold-count(failKey(username, ip)), LockoutThresholdGlobal-count(failKeyGlobal(username))))
}

// PasswordStep — шаг 1: проверка пароля. Возвращает pending-токен (5 минут) для TOTPStep.
// attemptsLeft — сколько неудач осталось до блокировки.
// Ошибки: ErrRateLimited, ErrLockedOut, ErrTOTPNotConfigured, *FailError{ErrInvalidCredentials}.
func (a *Auth) PasswordStep(ctx context.Context, username, password, ip string) (string, int, error) {
	if len(username) > maxUsernameLen {
		username = username[:maxUsernameLen]
	}
	if err := a.gate(ctx, "pw", username, ip); err != nil {
		return "", 0, err
	}
	usr, ok := a.users.Get(username)
	valid := false
	if ok && !usr.Disabled {
		valid = Verify(password, usr.Password)
	} else {
		VerifyDummy(password)
	}
	if !valid {
		left, err := a.registerFailure(ctx, username, ip, "bad_credentials")
		if err != nil {
			return "", 0, err
		}
		return "", left, &FailError{Err: ErrInvalidCredentials, AttemptsLeft: left}
	}
	if usr.TOTPSecretEnc == "" && !a.allowPwd {
		a.audit(ctx, username, AuditLoginNoTOTP, ip, "totp_not_configured")
		return "", 0, ErrTOTPNotConfigured
	}
	p, err := a.sessions.create(ctx, username, ip, kindPending, PendingTTL, PendingTTL)
	if err != nil {
		return "", 0, err
	}
	return p.Token, a.failuresLeft(ctx, username, ip), nil
}

// TOTPStep — шаг 2: проверка кода по pending-токену; при успехе создаётся новая полная сессия
// (новый id — ротация) и pending удаляется.
// Ошибки: ErrPendingInvalid, ErrRateLimited, ErrLockedOut, ErrTOTPNotConfigured, *FailError{ErrInvalidCode}.
func (a *Auth) TOTPStep(ctx context.Context, pending, code, ip string) (*Session, error) {
	p, err := a.sessions.lookup(ctx, pending, kindPending)
	if err != nil {
		if errors.Is(err, ErrNoSession) {
			return nil, ErrPendingInvalid
		}
		return nil, err
	}
	if err := a.gate(ctx, "totp", p.User, ip); err != nil {
		return nil, err
	}
	usr, ok := a.users.Get(p.User)
	if !ok || usr.Disabled {
		_ = a.sessions.Destroy(ctx, pending)
		return nil, ErrPendingInvalid
	}
	if usr.TOTPSecretEnc != "" {
		verr := a.totp.Verify(ctx, p.User, usr.TOTPSecretEnc, code, a.now())
		switch {
		case errors.Is(verr, ErrTOTPInvalid), errors.Is(verr, ErrTOTPReplayed):
			reason := "bad_totp"
			if errors.Is(verr, ErrTOTPReplayed) {
				reason = "totp_replay"
			}
			left, err := a.registerFailure(ctx, p.User, ip, reason)
			if err != nil {
				return nil, err
			}
			return nil, &FailError{Err: ErrInvalidCode, AttemptsLeft: left}
		case verr != nil:
			a.log.Error("totp verification error", "user", p.User, "err", verr)
			return nil, fmt.Errorf("auth: totp: %w", verr)
		}
	} else if !a.allowPwd {
		return nil, ErrTOTPNotConfigured
	}
	_ = a.sessions.Destroy(ctx, pending)
	s, err := a.sessions.Create(ctx, p.User, ip)
	if err != nil {
		return nil, err
	}
	_ = a.store.RateState().Delete(ctx, failKey(p.User, ip))
	_ = a.store.RateState().Delete(ctx, failKeyGlobal(p.User))
	a.audit(ctx, p.User, AuditLoginOK, ip, "")
	return s, nil
}

// Logout уничтожает сессию и пишет аудит.
func (a *Auth) Logout(ctx context.Context, s *Session, ip string) error {
	if err := a.sessions.Destroy(ctx, s.Token); err != nil {
		return err
	}
	a.audit(ctx, s.User, AuditLogout, ip, "")
	return nil
}

// Authenticate проверяет cookie запроса и продлевает idle-дедлайн.
func (a *Auth) Authenticate(r *http.Request) (*Session, error) {
	s, err := a.sessions.Get(r)
	if err != nil {
		return nil, err
	}
	if u, ok := a.users.Get(s.User); !ok || u.Disabled {
		_ = a.sessions.Destroy(r.Context(), s.Token)
		return nil, ErrNoSession
	}
	if err := a.sessions.Touch(r.Context(), s); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNoSession
		}
		return nil, err
	}
	return s, nil
}
