package screens

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/views"
)

// AgentsPollInterval — период живого обновления таблицы агентов (htmx every).
const AgentsPollInterval = 5 * time.Second

// certWarnDays — за сколько дней до конца срока сертификат подсвечивается.
const certWarnDays = 14

// AgentsDeps — зависимости экранов «Агенты» и мастера «Новый агент».
// Любой из сервисов может быть nil: соответствующая часть экрана покажет «не настроено».
type AgentsDeps struct {
	Auth *auth.Auth // обязательно
	// Service — список и управление агентами (drain, сертификат, режим, удаление).
	Service *api.AgentsService
	// Install — мастер установки по SSH (ветка «SSH»).
	Install *api.InstallService
	// Enroll — токены для агентов за NAT (ветка «NAT»).
	Enroll *api.EnrollService
	// ServerVersion — версия сервера; отличающаяся версия агента подсвечивается.
	ServerVersion string
	ClientIP      func(*http.Request) string // nil — хост из RemoteAddr
	Logger        *slog.Logger               // nil — slog.Default()
	Now           func() time.Time           // nil — time.Now
}

// StatusOpt — вариант фильтра по статусу.
type StatusOpt struct{ Value, Label string }

// statusOpts — варианты фильтра «Статус» (как в макете).
var statusOpts = []StatusOpt{
	{"", "Все"}, {"up", "В работе"}, {"degraded", "Деградация"}, {"down", "Недоступен"}, {"draining", "Drain"},
}

// AgentRowVM — строка таблицы агентов.
type AgentRowVM struct {
	ID, Name, Addr string
	LinkLabel      string
	LinkTone       views.Tone
	LinkConns      string // «2 соед.» или пусто
	Status         views.Status
	Weight         string
	RPS, RTT       string
	Inflight       string
	Version        string
	VersionStale   bool
	Cert           string
	CertTone       string // "", "warn", "err"
	Seen           string
	SeenMuted      bool
	Draining       bool
}

// AgentsVM — модель страницы «Агенты».
type AgentsVM struct {
	Rows          []AgentRowVM
	Total, Up     int
	ServerVersion string
	Query         string
	Status        string
	StatusOpts    []StatusOpt
	Can           api.Can
	PollSec       int
}

// Summary — «N агентов · M в работе · версия сервера vX».
func (v AgentsVM) Summary() string {
	s := agentsWord(v.Total) + " · " + strconv.Itoa(v.Up) + " в работе"
	if v.ServerVersion != "" {
		s += " · версия сервера " + v.ServerVersion
	}
	return s
}

func agentsWord(n int) string {
	last, last2 := n%10, n%100
	w := "агентов"
	switch {
	case last2 >= 11 && last2 <= 14:
	case last == 1:
		w = "агент"
	case last >= 2 && last <= 4:
		w = "агента"
	}
	return strconv.Itoa(n) + " " + w
}

func (v AgentsVM) pollMS() string { return strconv.Itoa(v.PollSec) + "s" }

// ModeFormVM — форма смены режима связи.
type ModeFormVM struct {
	ID, Name   string
	Mode       string // dial | reverse | both
	AgentURL   string
	NeedURL    bool // у агента нет адреса (reverse): подсказка про поле
	Conns      string
	Errors     api.FieldErrors
	CanReverse bool
}

// WeightFormVM — форма веса агента.
type WeightFormVM struct {
	ID, Name, Weight string
	Errors           api.FieldErrors
}

// RemovedVM — итог удаления агента.
type RemovedVM struct {
	Name           string
	Revoked        int
	DrainTimedOut  bool
	DrainUnchecked bool
}

// MoreVM — карточка «⋯» агента.
type MoreVM struct {
	Row        AgentRowVM
	URL        string
	Mode       string
	CanRemove  bool
	CertNotice string
}

// ConfirmVM — диалог подтверждения опасного действия.
type ConfirmVM struct {
	Title, Text, Note string
	Action            string // URL POST
	Label             string // подпись кнопки
	Danger            bool
	Target            string // CSS-селектор hx-target; пусто — #agent-modal-body
}

func (c ConfirmVM) target() string {
	if c.Target == "" {
		return "#agent-modal-body"
	}
	return c.Target
}
