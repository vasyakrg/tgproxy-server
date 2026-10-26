package tgapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrEnvelopeTooLarge is returned when the body exceeds the read limit.
var ErrEnvelopeTooLarge = errors.New("tgapi: response envelope exceeds limit")

// ResponseParameters mirrors Telegram's ResponseParameters.
type ResponseParameters struct {
	RetryAfter      int   `json:"retry_after,omitempty"`
	MigrateToChatID int64 `json:"migrate_to_chat_id,omitempty"`
}

// Envelope is the part of a Bot API response the proxy cares about. The
// "result" field is intentionally not decoded.
type Envelope struct {
	OK          bool                `json:"ok"`
	ErrorCode   int                 `json:"error_code,omitempty"`
	Description string              `json:"description,omitempty"`
	Parameters  *ResponseParameters `json:"parameters,omitempty"`
}

// ParseEnvelope reads at most limit bytes (plus one to detect overflow) from r
// and decodes the envelope.
func ParseEnvelope(r io.Reader, limit int64) (*Envelope, error) {
	if limit < 0 {
		limit = 0
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("tgapi: read envelope: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, ErrEnvelopeTooLarge
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("tgapi: decode envelope: %w", err)
	}
	return &env, nil
}

func hasDescription(env *Envelope, code int, substr string) bool {
	return env != nil && !env.OK && env.ErrorCode == code &&
		strings.Contains(strings.ToLower(env.Description), substr)
}

// IsNotModified reports Telegram's "message is not modified" error of edit*
// methods, which a retry must treat as success.
func IsNotModified(env *Envelope) bool {
	return hasDescription(env, 400, "message is not modified")
}

// IsNotFound reports that the message to delete no longer exists, which a
// retry of deleteMessage must treat as success.
func IsNotFound(env *Envelope) bool {
	return hasDescription(env, 400, "message to delete not found")
}
