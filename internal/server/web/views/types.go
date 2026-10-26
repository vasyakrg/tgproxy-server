package views

import (
	"strconv"

	"github.com/a-h/templ"
)

// Status — статус агента для StatusPill.
type Status string

// Статусы агента.
const (
	StatusUp       Status = "up"
	StatusDegraded Status = "degraded"
	StatusDown     Status = "down"
	StatusUpdating Status = "updating"
	StatusDraining Status = "draining"
)

// Label — подпись статуса по умолчанию.
func (s Status) Label() string {
	switch s {
	case StatusUp:
		return "В работе"
	case StatusDegraded:
		return "Деградация"
	case StatusDown:
		return "Недоступен"
	case StatusUpdating:
		return "Обновляется"
	case StatusDraining:
		return "Drain"
	}
	return string(s)
}

// Tone — цветовой акцент KPI и Chip.
type Tone string

// Тона.
const (
	ToneNeutral Tone = ""
	ToneOK      Tone = "ok"
	ToneWarn    Tone = "warn"
	ToneErr     Tone = "err"
	ToneAccent  Tone = "accent"
	ToneTG      Tone = "tg"
)

func (t Tone) kpiClass() string {
	if t == ToneNeutral {
		return ""
	}
	return "kpi-" + string(t)
}

func (t Tone) chipClass() string {
	if t == ToneNeutral {
		return ""
	}
	return "chip-" + string(t)
}

// ToastKind — вид уведомления.
type ToastKind string

// Виды тостов.
const (
	ToastInfo ToastKind = "info"
	ToastOK   ToastKind = "ok"
	ToastWarn ToastKind = "warn"
	ToastErr  ToastKind = "err"
)

// ButtonKind — вид кнопки.
type ButtonKind string

// Виды кнопок.
const (
	ButtonSecondary ButtonKind = "secondary"
	ButtonPrimary   ButtonKind = "primary"
	ButtonDanger    ButtonKind = "danger"
	ButtonLink      ButtonKind = "link"
)

func (k ButtonKind) class() string {
	switch k {
	case ButtonPrimary:
		return "btn-primary"
	case ButtonDanger:
		return "btn-danger"
	case ButtonLink:
		return "btn-link"
	case ButtonSecondary:
		return ""
	}
	return ""
}

// FieldProps — параметры Field.
type FieldProps struct {
	ID, Name, Label string
	Type            string // text (по умолчанию), password, number, ...
	Value           string
	Placeholder     string
	Autocomplete    string
	Hint, Error     string
	Required        bool
	Attrs           templ.Attributes // доп. атрибуты input (inputmode, hx-*, data-*)
}

func (f FieldProps) fieldID() string {
	if f.ID != "" {
		return f.ID
	}
	return "f-" + f.Name
}

func (f FieldProps) inputType() string {
	if f.Type == "" {
		return "text"
	}
	return f.Type
}

func (f FieldProps) describedBy() string {
	var s string
	if f.Hint != "" {
		s = f.fieldID() + "-hint"
	}
	if f.Error != "" {
		if s != "" {
			s += " "
		}
		s += f.fieldID() + "-error"
	}
	return s
}

func sizeStr(n int) string {
	if n <= 0 {
		n = 20
	}
	return strconv.Itoa(n)
}
