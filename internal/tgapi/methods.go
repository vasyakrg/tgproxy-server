// Package tgapi contains Telegram Bot API specifics: method classification,
// request path parsing, response envelope handling and error rendering.
package tgapi

import "strings"

// Class describes how safely a method can be retried (architecture §6).
type Class int

const (
	// Safe methods are idempotent: retried on any transport or 5xx failure.
	Safe Class = iota
	// Semi methods are retried after write errors; "not modified" counts as success.
	Semi
	// Unsafe methods are retried only before anything was sent.
	Unsafe
)

// String returns the metric label of the class.
func (c Class) String() string {
	switch c {
	case Safe:
		return "safe"
	case Semi:
		return "semi"
	default:
		return "unsafe"
	}
}

// Classify returns the retry class of a Bot API method (case-insensitive).
// Unknown methods are Unsafe.
func Classify(method string) Class {
	m := strings.ToLower(method)
	switch m {
	case "setwebhook":
		return Unsafe // handled by webhook policy, never retried blindly
	case "answercallbackquery", "answerinlinequery", "stoppoll", "sendchataction",
		"stopmessagelivelocation":
		return Semi
	}
	for _, p := range safePrefixes {
		if strings.HasPrefix(m, p) {
			return Safe
		}
	}
	for _, p := range semiPrefixes {
		if strings.HasPrefix(m, p) {
			return Semi
		}
	}
	return Unsafe
}

var (
	// get*, set* (except setWebhook), delete*, pin/unpin, ban/restrict/promote.
	safePrefixes = []string{"get", "set", "delete", "pin", "unpin", "ban", "unban", "restrict", "promote"}
	// edit*, answer* (callback/inline/shipping/pre-checkout/web-app queries).
	semiPrefixes = []string{"edit", "answer"}
)

// IsWebhookSetter reports whether method is setWebhook.
func IsWebhookSetter(method string) bool { return strings.EqualFold(method, "setWebhook") }

// IsLongPoll reports whether method is getUpdates.
func IsLongPoll(method string) bool { return strings.EqualFold(method, "getUpdates") }
