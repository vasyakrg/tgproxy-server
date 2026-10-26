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
	case ModeDial:
		if a.URL == "" {
			return fmt.Errorf("%w: dial agent needs url", ErrInvalid)
		}
	case ModeReverse:
	default:
		return fmt.Errorf("%w: agent mode %q", ErrInvalid, a.Mode)
	}
	if a.Weight < 0 {
		return fmt.Errorf("%w: weight must be >= 0", ErrInvalid)
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
