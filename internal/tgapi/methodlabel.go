package tgapi

import "strings"

// MethodOther is the metric label for any method outside the Bot API list.
const MethodOther = "other"

// MethodLabel normalises a method name for use as a metric label: known Bot API
// methods are returned lower-cased, everything else collapses into "other".
// This bounds label cardinality regardless of what clients send.
func MethodLabel(method string) string {
	if len(method) == 0 || len(method) > 64 {
		return MethodOther
	}
	m := strings.ToLower(method)
	if _, ok := knownMethods[m]; ok {
		return m
	}
	return MethodOther
}

// KnownMethodCount returns the number of distinct non-"other" labels.
func KnownMethodCount() int { return len(knownMethods) }
