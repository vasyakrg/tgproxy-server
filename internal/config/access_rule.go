package config

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// RuleIssueCode — машинный код нарушения правила доступа (UI/API переводят его в своё сообщение).
type RuleIssueCode string

// Коды нарушений CheckAccessRule.
const (
	IssueName         RuleIssueCode = "name"          // имя не соответствует ^[\p{L}\p{N} ._-]{1,64}$ (без ведущих/хвостовых пробелов)
	IssueKeyForms     RuleIssueCode = "key_forms"     // key_sha256 и key_file одновременно
	IssueKeyHash      RuleIssueCode = "key_hash"      // key_sha256 — не 64 hex
	IssueNoNetNoKey   RuleIssueCode = "no_net_no_key" // нет ни сетей, ни ключа: открытый relay
	IssueInvalidCIDR  RuleIssueCode = "invalid_cidr"  // невалидный префикс
	IssueOpenRelay    RuleIssueCode = "open_relay"    // 0.0.0.0/0 или ::/0 без ключа
	IssueHostBits     RuleIssueCode = "host_bits"     // у префикса выставлены биты хоста
	IssueNegativeRate RuleIssueCode = "negative_rps"  // rps < 0
)

// RuleIssue — одно нарушение правила доступа.
type RuleIssue struct {
	Field string // name | key_sha256 | cidrs | rps | "" (правило целиком)
	Index int    // индекс в cidrs; -1 — не к элементу
	Code  RuleIssueCode
	Msg   string // англоязычное сообщение (как в ошибках конфига)
}

func (i RuleIssue) path() string {
	switch {
	case i.Field == "":
		return ""
	case i.Index >= 0:
		return fmt.Sprintf(".%s[%d]", i.Field, i.Index)
	}
	return "." + i.Field
}

// ValidRuleName сообщает, допустимо ли имя правила: Unicode-буквы, цифры, пробел и «._-», 1–64 символа, без ведущих/хвостовых пробелов.
func ValidRuleName(name string) bool {
	return ruleRe.MatchString(name) && name == strings.TrimSpace(name)
}

// CheckAccessRule проверяет одно правило доступа (кроме уникальности имени). Единый источник
// правил: используется и при загрузке конфига, и в UI/API создания правил.
func CheckAccessRule(r AccessRule) []RuleIssue {
	var out []RuleIssue
	add := func(field string, idx int, code RuleIssueCode, format string, args ...any) {
		out = append(out, RuleIssue{Field: field, Index: idx, Code: code, Msg: fmt.Sprintf(format, args...)})
	}
	if !ValidRuleName(r.Name) {
		add("name", -1, IssueName, "invalid name %q", r.Name)
	}
	if r.KeySHA256 != "" && r.KeyFile != "" {
		add("", -1, IssueKeyForms, "key_sha256 and key_file are mutually exclusive")
	}
	if r.KeySHA256 != "" {
		if b, err := hex.DecodeString(r.KeySHA256); err != nil || len(b) != 32 {
			add("key_sha256", -1, IssueKeyHash, "want 64 hex characters (SHA-256)")
		}
	}
	if len(r.CIDRs) == 0 && !r.HasKey() {
		add("", -1, IssueNoNetNoKey, "rule without networks and without key is an open relay to the Bot API")
	}
	for j, n := range r.CIDRs {
		switch {
		case !n.IsValid():
			add("cidrs", j, IssueInvalidCIDR, "invalid prefix")
		case n.Bits() == 0 && !r.HasKey():
			add("cidrs", j, IssueOpenRelay, "%s without a key is an open relay to the Bot API", n)
		case n != n.Masked():
			add("cidrs", j, IssueHostBits, "%s has host bits set, want %s", n, n.Masked())
		}
	}
	if r.RPS < 0 {
		add("rps", -1, IssueNegativeRate, "must not be negative, got %g", r.RPS)
	}
	return out
}
