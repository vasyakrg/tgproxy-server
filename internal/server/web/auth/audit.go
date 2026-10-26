package auth

import (
	"context"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Действия аудита.
const (
	AuditLoginOK       = "login.ok"
	AuditLoginFail     = "login.fail"
	AuditLogout        = "logout"
	AuditLoginLockout  = "login.lockout"
	AuditLoginBlocked  = "login.blocked"
	AuditLoginNoTOTP   = "login.totp_not_configured"
	auditUnknownActor  = "-"
	auditMaxFieldBytes = 128
)

// audit пишет запись в журнал. Пароли, TOTP-коды и токены сюда не передаются:
// detail — только код причины. Для неизвестных имён actor = "-" (в поле могли набрать пароль).
func (a *Auth) audit(ctx context.Context, actor, action, ip, detail string) {
	if actor == "" {
		actor = auditUnknownActor
	}
	if len(detail) > auditMaxFieldBytes {
		detail = detail[:auditMaxFieldBytes]
	}
	_, err := a.store.Audit().Append(ctx, store.AuditEntry{
		At: a.now(), Actor: actor, Action: action, Target: actor, IP: ip, Detail: detail,
	})
	if err != nil {
		a.log.Error("audit append failed", "action", action, "err", err)
	}
}
