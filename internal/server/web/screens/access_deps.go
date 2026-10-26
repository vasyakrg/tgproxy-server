package screens

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/metrics"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// topBotsLimit — сколько ботов показывать в таблице «Активные боты за 24 часа».
const topBotsLimit = 20

// AccessEnv — то, что экрану «Доступ» даёт wiring.
type AccessEnv interface {
	// PublicBaseURL — публичный base URL прокси (config public_base_url), без завершающего «/».
	PublicBaseURL() string
	// RuleStats — запросов за 24 ч и время последнего запроса по имени правила.
	// ok=false — данных пока нет (в UI «—»); ok=true и нулевой lastSeen — запросов не было.
	RuleStats(name string) (requests24h int64, lastSeen time.Time, ok bool)
}

// BotSource — счётчик активных ботов (реализует *metrics.TopBots).
type BotSource interface {
	Top(k int) []metrics.BotStat
}

// AccessDeps — зависимости экрана «Доступ».
type AccessDeps struct {
	Auth     *auth.Auth                 // RequireAuth и сессия (обязательно)
	Service  *api.AccessService         // CRUD правил (обязательно)
	Env      AccessEnv                  // nil — пустой base URL (берётся из Host запроса) и «—» в статистике
	Bots     BotSource                  // nil — пустая таблица ботов
	ClientIP func(*http.Request) string // nil — хост из RemoteAddr
	Logger   *slog.Logger               // nil — slog.Default()
	Now      func() time.Time           // nil — time.Now
}

// RuleRow — строка таблицы правил.
type RuleRow struct {
	ID        int64
	Name      string
	Enabled   bool
	KindLabel string
	KindTone  views.Tone
	CIDRs     []string
	KeyPrefix string // «tgp_k7Qm…» или «—»
	Limit     string
	Requests  string
	LastSeen  string
	SeenMuted bool
}

// BotRow — строка таблицы активных ботов.
type BotRow struct {
	BotID    string
	Rule     string
	Requests string
	Errors   string
	R429     string
	Limited  bool
}

// AccessVM — модель страницы «Доступ».
type AccessVM struct {
	BaseURL string
	Rows    []RuleRow
	Bots    []BotRow
}

// RuleFormVM — модель формы правила.
type RuleFormVM struct {
	ID        int64 // 0 — новое правило
	Name      string
	CIDRs     string
	RPS       string
	WithKey   bool // только создание
	Enabled   bool // только изменение
	KeyPrefix string
	Errors    api.FieldErrors
}

// IsNew — форма создания.
func (f RuleFormVM) IsNew() bool { return f.ID == 0 }

// Action — URL отправки формы.
func (f RuleFormVM) Action() string {
	if f.IsNew() {
		return "/access"
	}
	return "/access/" + strconv.FormatInt(f.ID, 10)
}

// CreatedVM — результат создания (ключ виден только здесь).
type CreatedVM struct {
	Name    string
	Key     string
	BaseURL string
}

func kindView(k api.RuleKind) (string, views.Tone) {
	switch k {
	case api.KindKey:
		return "ключ", views.ToneAccent
	case api.KindBoth:
		return "сеть + ключ", views.ToneTG
	case api.KindNetwork:
	}
	return "сеть", views.ToneNeutral
}

// thousands форматирует число с неразрывными пробелами: 694 120.
func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteString(" ")
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// agoRu: «только что», «4 мин назад», «3 ч назад», «2 дн назад».
func agoRu(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "только что"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " мин назад"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + " ч назад"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + " дн назад"
}

func makeRuleRow(r store.AccessRule, env AccessEnv, now time.Time) RuleRow {
	label, tone := kindView(api.KindOf(r))
	row := RuleRow{
		ID: r.ID, Name: r.Name, Enabled: r.Enabled && r.RevokedAt == nil,
		KindLabel: label, KindTone: tone, KeyPrefix: "—",
		Limit: "без лимита", Requests: "—", LastSeen: "—", SeenMuted: true,
	}
	for _, p := range r.CIDRs {
		row.CIDRs = append(row.CIDRs, p.String())
	}
	if r.KeyPrefix != "" {
		row.KeyPrefix = r.KeyPrefix + "…"
	}
	if r.RPS > 0 {
		row.Limit = strconv.FormatFloat(r.RPS, 'f', -1, 64) + " rps"
	}
	if env != nil {
		if n, seen, ok := env.RuleStats(r.Name); ok {
			row.Requests = thousands(n)
			if seen.IsZero() {
				row.LastSeen = "не было"
			} else {
				row.LastSeen, row.SeenMuted = agoRu(now, seen), false
			}
		}
	}
	return row
}

func botRows(src BotSource) []BotRow {
	if src == nil {
		return nil
	}
	top := src.Top(topBotsLimit)
	out := make([]BotRow, 0, len(top))
	for _, b := range top {
		errPct := 0.0
		if b.Requests > 0 {
			errPct = float64(b.Errors) * 100 / float64(b.Requests)
		}
		out = append(out, BotRow{
			BotID: strconv.FormatInt(b.BotID, 10), Rule: b.Rule,
			Requests: thousands(int64(b.Requests)), //nolint:gosec // счётчик окна 24ч << MaxInt64
			Errors:   fmtPct(errPct),
			R429:     thousands(int64(b.R429)), //nolint:gosec // см. выше
			Limited:  b.R429 > 0,
		})
	}
	return out
}
