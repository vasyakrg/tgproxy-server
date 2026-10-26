package screens

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/vasyakrg/tgproxy-server/internal/server/web"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/auth"
)

// Тексты о блокировке выводятся из констант auth, чтобы не расходиться с реальными лимитами.
var (
	loginLockoutThreshold = strconv.Itoa(auth.LockoutThreshold)
	loginLockoutMinutes   = strconv.Itoa(int(auth.LockoutDuration.Minutes()))
)

// LoginStep — шаг формы входа.
type LoginStep int

// Шаги входа.
const (
	StepPassword LoginStep = iota
	StepTOTP
)

// LoginView — модель карточки входа.
type LoginView struct {
	Step     LoginStep
	Username string // подставляется обратно в поле при ошибке; пароль и код — никогда
	Message  string // ошибка или пояснение под формой
}

// LoginDeps — зависимости экрана входа.
type LoginDeps struct {
	Auth *auth.Auth // обязательно
	// ClientIP — IP клиента для лимитов и аудита; ОБЯЗАН совпадать с auth.Options.ClientIP.
	// nil — хост из RemoteAddr.
	ClientIP func(*http.Request) string
	Logger   *slog.Logger // nil — slog.Default()
}

type sessionProvider struct{ a *auth.Auth }

// Current реализует web.Session: логин текущей сессии для сайдбара. Продления idle-дедлайна нет
// (это делает RequireAuth). CSRF-токена нет: защита — http.CrossOriginProtection.
func (p sessionProvider) Current(r *http.Request) (user, csrf string, ok bool) {
	s, err := p.a.Sessions().Get(r)
	if err != nil {
		return "", "", false
	}
	return s.User, "", true
}

// NewSessionProvider возвращает web.Deps.Session на основе Auth.
func NewSessionProvider(a *auth.Auth) web.Session { return sessionProvider{a} }
