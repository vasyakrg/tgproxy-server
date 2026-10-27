package notify

import (
	"html"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
)

func escapeHTML(s string) string { return html.EscapeString(s) }

func icon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityInfo:
		return "ℹ️"
	default:
		return "⚠️"
	}
}

func headline(a Alert) string {
	t := a.Title
	if t == "" {
		t = string(a.Type)
	}
	return redact.String(t)
}

// formatAlert собирает HTML-текст сообщения; любые токены маскируются.
func formatAlert(a Alert) string {
	var b strings.Builder
	b.WriteString(icon(a.Severity) + " <b>" + escapeHTML(redact.String(headline(a))) + "</b>")
	if a.Text != "" {
		b.WriteString("\n" + escapeHTML(redact.String(a.Text)))
	}
	return b.String()
}

// resolvedTitle — заголовок «восстановлено» по типу и агенту.
func resolvedTitle(t AlertType, agent string) string {
	who := ""
	if agent != "" {
		who = " " + agent
	}
	switch t {
	case AgentDown:
		return "Агент" + who + " снова доступен"
	case AgentDegraded:
		return "Агент" + who + ": доля ошибок в норме"
	case Overload:
		return "Агент" + who + ": нагрузка в норме"
	case CertExpiring:
		return "Сертификат агента" + who + " обновлён"
	case IngressCertExpiring, IngressCertInvalid:
		return "Сертификат входа в норме"
	case VersionMismatch:
		return "Версия агента" + who + " совпадает с сервером"
	case AllAgentsDown:
		return "Доступность агентов восстановлена"
	case MTProtoDCUnreachable:
		return "MTProto: DC снова доступен"
	case MTProtoNoCapableAgents:
		return "MTProto: снова есть агенты с поддержкой"
	case MTProtoOverload:
		return "MTProto: нагрузка в норме"
	default:
		return "Восстановлено: " + string(t) + who
	}
}
