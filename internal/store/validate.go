package store

import (
	"fmt"
	"strings"
)

// HashLen — длина хеша ключа/токена (SHA-256).
const HashLen = 32

// Validate проверяет правило доступа. Правило без сети и без ключа запрещено:
// это открытый relay к Bot API (architecture §3).
func (r AccessRule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("%w: access rule name is required", ErrInvalid)
	}
	if len(r.CIDRs) == 0 && len(r.KeyHash) == 0 {
		return fmt.Errorf("%w: access rule needs cidrs or key", ErrInvalid)
	}
	if len(r.KeyHash) != 0 && len(r.KeyHash) != HashLen {
		return fmt.Errorf("%w: key hash must be %d bytes", ErrInvalid, HashLen)
	}
	for _, p := range r.CIDRs {
		if !p.IsValid() {
			return fmt.Errorf("%w: invalid cidr", ErrInvalid)
		}
	}
	if r.RPS < 0 {
		return fmt.Errorf("%w: rps must be >= 0", ErrInvalid)
	}
	return nil
}

// Validate проверяет агента.
func (a Agent) Validate() error {
	if a.ID == "" || strings.TrimSpace(a.Name) == "" {
		return fmt.Errorf("%w: agent id and name are required", ErrInvalid)
	}
	switch a.Mode {
	case ModeDial, ModeBoth:
		if a.URL == "" {
			return fmt.Errorf("%w: dial/both agent needs url", ErrInvalid)
		}
	case ModeReverse:
	default:
		return fmt.Errorf("%w: agent mode %q", ErrInvalid, a.Mode)
	}
	if a.Weight < 0 {
		return fmt.Errorf("%w: weight must be >= 0", ErrInvalid)
	}
	return a.ValidateSSHTarget()
}

// ValidateSSHTarget проверяет SSH-цель: пустой хост допустим только вместе с портом 0.
func (a Agent) ValidateSSHTarget() error {
	switch {
	case a.SSHHost == "" && a.SSHPort == 0:
		return nil
	case a.SSHHost == "" || len(a.SSHHost) > 253 || strings.ContainsAny(a.SSHHost, " \t\r\n/@\\"):
		return fmt.Errorf("%w: invalid ssh host", ErrInvalid)
	case a.SSHPort < 1 || a.SSHPort > 65535:
		return fmt.Errorf("%w: ssh port must be 1..65535", ErrInvalid)
	}
	return nil
}

// Validate проверяет сессию.
func (s Session) Validate() error {
	if s.ID == "" || s.User == "" {
		return fmt.Errorf("%w: session id and user are required", ErrInvalid)
	}
	if s.Kind != "pending" && s.Kind != "full" {
		return fmt.Errorf("%w: session kind %q", ErrInvalid, s.Kind)
	}
	return nil
}

// Validate проверяет запись журнала ошибок.
func (e ErrorEvent) Validate() error {
	switch e.Outcome {
	case OutcomeRetried, OutcomeFailedToBot, OutcomePassedToBot:
		return nil
	}
	return fmt.Errorf("%w: error outcome %q", ErrInvalid, e.Outcome)
}

// Validate проверяет элемент outbox.
func (o OutboxItem) Validate() error {
	if o.DedupKey == "" || o.Type == "" {
		return fmt.Errorf("%w: outbox dedup key and type are required", ErrInvalid)
	}
	if o.State != OutboxFiring && o.State != OutboxResolved {
		return fmt.Errorf("%w: outbox state %q", ErrInvalid, o.State)
	}
	return nil
}

// Validate проверяет enrollment.
func (e Enrollment) Validate() error {
	if e.ID == "" || len(e.TokenHash) != HashLen || strings.TrimSpace(e.Name) == "" || e.Weight < 0 {
		return fmt.Errorf("%w: enrollment", ErrInvalid)
	}
	return nil
}

// Validate проверяет задачу установки.
func (j InstallJob) Validate() error {
	if j.ID == "" || j.Host == "" || j.Kind == "" || j.State == "" {
		return fmt.Errorf("%w: install job id, host, kind and state are required", ErrInvalid)
	}
	return nil
}

// Validate проверяет событие задачи установки.
func (e InstallJobEvent) Validate() error {
	if e.JobID == "" || e.Kind == "" {
		return fmt.Errorf("%w: install event job id and kind are required", ErrInvalid)
	}
	return nil
}

// Validate проверяет бан: префикс — IPv4 /32 или IPv6 /64 без битов хоста.
func (b Ban) Validate() error {
	p := b.Prefix
	if !p.IsValid() {
		return fmt.Errorf("%w: ban prefix", ErrInvalid)
	}
	want := 32
	if p.Addr().Is6() {
		want = 64
	}
	if p.Addr().Is4In6() || p.Bits() != want || p != p.Masked() {
		return fmt.Errorf("%w: ban prefix must be IPv4 /32 or IPv6 /64", ErrInvalid)
	}
	if b.Source != BanAuto && b.Source != BanManual {
		return fmt.Errorf("%w: ban source %q", ErrInvalid, b.Source)
	}
	if b.Level < 0 {
		return fmt.Errorf("%w: ban level", ErrInvalid)
	}
	return nil
}

// Validate проверяет секрет MTProto.
func (s MTProtoSecret) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("%w: mtproto secret name is required", ErrInvalid)
	}
	if len(s.SecretEnc) == 0 || s.Prefix == "" {
		return fmt.Errorf("%w: mtproto secret needs sealed key and prefix", ErrInvalid)
	}
	if s.MaxConns < 0 {
		return fmt.Errorf("%w: max_conns must be >= 0", ErrInvalid)
	}
	for _, p := range s.CIDRs {
		if !p.IsValid() {
			return fmt.Errorf("%w: invalid cidr", ErrInvalid)
		}
	}
	return nil
}

// Validate проверяет запись журнала MTProto.
func (s MTProtoSession) Validate() error {
	if s.SecretID <= 0 || s.BytesIn < 0 || s.BytesOut < 0 {
		return fmt.Errorf("%w: mtproto session needs secret_id and non-negative bytes", ErrInvalid)
	}
	if s.EndedAt.Before(s.StartedAt) {
		return fmt.Errorf("%w: mtproto session ended before start", ErrInvalid)
	}
	return nil
}
