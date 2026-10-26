package screens

import (
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
)

// Режимы мастера.
const (
	WizardSSH = "ssh"
	WizardNAT = "nat"
)

// Варианты TTL токена (минуты).
var ttlOpts = []struct {
	Minutes int
	Label   string
}{{15, "15 минут"}, {60, "1 час"}, {360, "6 часов"}, {1440, "24 часа"}}

// SSHFormVM — шаг 1 ветки SSH. Секретов здесь нет по построению: ни ключ, ни пароль, ни passphrase
// в модель формы не попадают и в ответах не повторяются.
type SSHFormVM struct {
	Name, Host, SSHPort, User, AgentPort, Weight string
	Auth                                         string // key | password
	Errors                                       api.FieldErrors
	Retype                                       bool // напомнить, что секреты нужно ввести заново
	Disabled                                     bool // установщик не настроен
}

// DefaultSSHForm — значения по умолчанию из макета.
func DefaultSSHForm() SSHFormVM {
	return SSHFormVM{
		SSHPort: strconv.Itoa(api.DefaultSSHPort), User: "root", AgentPort: strconv.Itoa(api.DefaultAgentPort),
		Weight: strconv.Itoa(api.DefaultWeight), Auth: "key",
	}
}

func sshFormFrom(in api.InstallInput) SSHFormVM {
	return SSHFormVM{
		Name: in.Name, Host: in.Host, SSHPort: strconv.Itoa(in.SSHPort), User: in.User,
		AgentPort: strconv.Itoa(in.AgentPort), Weight: strconv.Itoa(in.Weight), Auth: "key",
	}
}

// HostKeyVM — шаг 2: подтверждение отпечатка.
type HostKeyVM struct {
	PendingID   string
	Addr        string
	Algo        string
	Fingerprint string
	Name        string
}

// NATFormVM — форма токена.
type NATFormVM struct {
	Name, Weight string
	TTL          int // минуты
	Errors       api.FieldErrors
}

// DefaultNATForm — значения по умолчанию.
func DefaultNATForm() NATFormVM {
	return NATFormVM{Weight: strconv.Itoa(api.DefaultWeight), TTL: 60}
}

// NATIssuedVM — выпущенный токен (команда показывается один раз).
type NATIssuedVM struct {
	ID, Name, Cmdline string
	Expires           string
}

// PendingRowVM — ожидающий токен.
type PendingRowVM struct {
	ID, Name, Weight, Expires, Left string
}

func pendingRows(items []api.EnrollmentItem, now time.Time) []PendingRowVM {
	out := make([]PendingRowVM, 0, len(items))
	for _, e := range items {
		out = append(out, PendingRowVM{
			ID: e.ID, Name: e.Name, Weight: strconv.Itoa(e.Weight),
			Expires: e.ExpiresAt.Local().Format("15:04"), Left: leftRu(e.ExpiresAt.Sub(now)),
		})
	}
	return out
}

// leftRu: «осталось 42 мин».
func leftRu(d time.Duration) string {
	switch {
	case d <= 0:
		return "истёк"
	case d < time.Minute:
		return "< 1 мин"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " мин"
	}
	return strconv.Itoa(int(d/time.Hour)) + " ч " + strconv.Itoa(int(d%time.Hour/time.Minute)) + " мин"
}

// WizardVM — страница мастера.
type WizardVM struct {
	Mode          string
	SSH           SSHFormVM
	NAT           NATFormVM
	Pending       []PendingRowVM
	NATConfigured bool
}

// JobStepVM — шаг установки.
type JobStepVM struct{ Key, Label, Status string }

// JobVM — шаг «Установка».
type JobVM struct {
	ID, Title, State, Error string
	// Emergency — задача аварийного обновления (а не установки нового агента).
	Emergency             bool
	StartedMS, FinishedMS int64
	Steps                 []JobStepVM
	EventsURL, StatusURL  string
}

// stateLabel — подпись состояния задачи.
func (j JobVM) stateLabel() string {
	switch j.State {
	case "done":
		return "готово"
	case "failed":
		return "не удалось"
	}
	return "выполняется"
}
