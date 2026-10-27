package screens

import (
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// MTProtoDeps — зависимости экрана «MTProto».
type MTProtoDeps struct {
	Auth    *auth.Auth          // RequireAuth, сессия, свежий TOTP (обязательно)
	Service *api.MTProtoService // CRUD секретов (обязательно)
	// Stats — матрица агент×DC (nil — пустая матрица).
	Stats api.MTProtoStatsSource
	// ActiveConns — активные соединения секрета по имени (nil — «—»).
	ActiveConns func(name string) int
	ClientIP    func(*http.Request) string // nil — хост из RemoteAddr
	Logger      *slog.Logger               // nil — slog.Default()
	Now         func() time.Time           // nil — time.Now
}

// MTSecretRow — строка таблицы секретов. Ключа здесь нет.
type MTSecretRow struct {
	ID         int64
	Name       string
	Prefix     string // «ab12…»
	Status     string // active | grace | disabled | revoked
	StatusText string
	StatusTone views.Tone
	CIDRs      []string
	Conns      string
	CanLink    bool
	CanRotate  bool
	CanRevoke  bool
}

// MTCell — ячейка матрицы agent×DC.
type MTCell struct {
	Present bool
	Up      bool
	Text    string
}

// MTAgentRow — строка матрицы.
type MTAgentRow struct {
	ID      string
	Capable bool
	Streams string
	Cells   []MTCell
}

// MTMatrixVM — матрица агент×DC.
type MTMatrixVM struct {
	Enabled bool
	DCs     []int
	Agents  []MTAgentRow
}

// MTProtoVM — модель страницы.
type MTProtoVM struct {
	Disabled   bool // mtproto.enabled=false
	NoEndpoint bool // не заданы host/fronting_domain: ссылки недоступны
	Rows       []MTSecretRow
	Matrix     MTMatrixVM
}

// MTFormVM — форма создания секрета.
type MTFormVM struct {
	Name     string
	CIDRs    string
	MaxConns string
	Errors   api.FieldErrors
}

// MTRotateVM — форма ротации.
type MTRotateVM struct {
	ID     int64
	Name   string
	Grace  string
	Errors api.FieldErrors
}

// MTRevokeVM — подтверждение отзыва.
type MTRevokeVM struct {
	ID   int64
	Name string
}

// MTTOTPVM — запрос кода TOTP перед показом ссылки.
type MTTOTPVM struct {
	ID    int64
	Name  string
	Error string
}

// MTLinkVM — ссылка и QR. Единственное место, где рендерится ключ секрета.
type MTLinkVM struct {
	Title string
	Name  string
	Note  string // пояснение (ротация, grace)
	Fresh bool   // секрет только что создан/повёрнут: «показано один раз»
	TG    string
	HTTPS string
	QR    string
	// Err — ссылку собрать не удалось (endpoint не настроен).
	Err string
}

const mtEndpointErr = "Не заданы mtproto.fronting_domain и public_host/public_base_url: ссылка недоступна. Секрет сохранён."

var mtGraceOptions = []struct{ Value, Label string }{
	{"0", "Сразу отозвать старый"},
	{"1h", "1 час"},
	{"24h", "24 часа"},
	{"168h", "7 дней"},
}

func mtStatus(m store.MTProtoSecret, now time.Time) (key, text string, tone views.Tone) {
	switch {
	case m.RevokedAt != nil && m.Active(now):
		until := ""
		if m.GraceUntil != nil {
			until = " до " + m.GraceUntil.UTC().Format("02.01 15:04") + " UTC"
		}
		return "grace", "grace" + until, views.ToneWarn
	case m.RevokedAt != nil || (m.GraceUntil != nil && !m.GraceUntil.After(now)):
		return "revoked", "отозван", views.ToneErr
	case !m.Enabled:
		return "disabled", "выключен", views.ToneNeutral
	}
	return "active", "активен", views.ToneOK
}

func mtSecretRow(m store.MTProtoSecret, conns func(string) int, now time.Time) MTSecretRow {
	key, text, tone := mtStatus(m, now)
	row := MTSecretRow{
		ID: m.ID, Name: m.Name, Prefix: m.Prefix + "…", Status: key, StatusText: text, StatusTone: tone,
		Conns: "—",
	}
	for _, p := range m.CIDRs {
		row.CIDRs = append(row.CIDRs, p.String())
	}
	if conns != nil {
		row.Conns = strconv.Itoa(conns(m.Name))
		if m.MaxConns > 0 {
			row.Conns += " / " + strconv.Itoa(m.MaxConns)
		}
	} else if m.MaxConns > 0 {
		row.Conns = "— / " + strconv.Itoa(m.MaxConns)
	}
	row.CanLink = key == "active" || key == "grace"
	row.CanRotate = key == "active" || key == "disabled"
	row.CanRevoke = key != "revoked"
	return row
}

func mtMatrix(s api.MTProtoStats) MTMatrixVM {
	vm := MTMatrixVM{Enabled: s.Enabled}
	set := map[int]struct{}{}
	for _, a := range s.Agents {
		for _, c := range a.DC {
			set[c.DC] = struct{}{}
		}
	}
	for dc := range set {
		vm.DCs = append(vm.DCs, dc)
	}
	slices.Sort(vm.DCs)
	for _, a := range s.Agents {
		row := MTAgentRow{ID: a.AgentID, Capable: a.Capable, Streams: strconv.Itoa(a.Streams)}
		by := make(map[int]api.MTProtoDCStat, len(a.DC))
		for _, c := range a.DC {
			by[c.DC] = c
		}
		for _, dc := range vm.DCs {
			c, ok := by[dc]
			switch {
			case !ok:
				row.Cells = append(row.Cells, MTCell{Text: "—"})
			case c.Up:
				row.Cells = append(row.Cells, MTCell{Present: true, Up: true,
					Text: fmtMs(c.RTTMs) + " · " + strconv.Itoa(c.Streams) + " стр."})
			default:
				row.Cells = append(row.Cells, MTCell{Present: true, Text: "недоступен"})
			}
		}
		vm.Agents = append(vm.Agents, row)
	}
	return vm
}

func (f MTFormVM) maxConnsInt() (int, string) {
	v := strings.TrimSpace(f.MaxConns)
	if v == "" {
		return 0, ""
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, "Целое число от 0 (0 — без лимита)"
	}
	return n, ""
}
