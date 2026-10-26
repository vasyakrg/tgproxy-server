// Package enroll — подключение агента за NAT по одноразовому токену
// (architecture §4.1, plan M5-T9): выпуск токена (Service.Issue) и обработчик
// POST /enroll на agent_gateway (Service.Handler) и GET /enroll/package/<deb>
// (Service.PackageHandler) — установка пакета на чистый хост по тому же токену.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Лимиты и умолчания.
const (
	TokenBytes     = 32
	DefaultTTL     = time.Hour
	MaxTTL         = 24 * time.Hour
	DefaultWeight  = 100
	MaxNameLen     = 64
	DefaultPerMin  = 5
	maxBodyBytes   = 16 << 10
	agentIDRetries = 5
)

// Authority — подмножество *pki.Authority.
type Authority interface {
	SignAgentCSR(ctx context.Context, csrPEM []byte, agentID string, ttl time.Duration) (certPEM []byte, serial string, err error)
	CertPEM() []byte
	CAFingerprint() string
}

// Config — зависимости Service.
type Config struct {
	Enrollments store.EnrollmentRepo
	Agents      store.AgentRepo
	Audit       store.AuditRepo
	CA          Authority
	// GatewayURL — публичный URL agent_gateway (https://host:8444), попадает в команду для агента.
	GatewayURL string
	Logger     *slog.Logger
	Now        func() time.Time
	// Packages — проверенный пакет агента (кэш загрузок сервера) для установочной
	// команды и GET /enroll/package/. nil — команда установки не выдаётся.
	Packages PackageSource
	// PerMinute — лимит попыток на IP в минуту (по умолчанию 5).
	PerMinute int
	// Notify вызывается после успешного enrollment (алерт agent_enrolled).
	Notify func(ctx context.Context, agentID, name string)
	// Observe получает результат попытки (enroll_attempts_total{result}):
	// ok, rate_limited, bad_request, bad_csr, denied, error.
	Observe func(result string)
}

// Service выпускает токены и принимает enrollment.
type Service struct {
	cfg Config
	log *slog.Logger
	now func() time.Time
	lim *limiter
	// pkgLim — отдельный лимит на GET /enroll/package/ (скачивание + повторы curl не должны
	// съедать лимит самого /enroll).
	pkgLim *limiter
}

// New создаёт Service.
func New(cfg Config) (*Service, error) {
	if cfg.Enrollments == nil || cfg.Agents == nil || cfg.Audit == nil || cfg.CA == nil {
		return nil, errors.New("enroll: Enrollments, Agents, Audit and CA are required")
	}
	u, err := url.Parse(cfg.GatewayURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("enroll: gateway url %q must be https://host[:port]", cfg.GatewayURL)
	}
	s := &Service{cfg: cfg, log: cfg.Logger, now: cfg.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	per := cfg.PerMinute
	if per <= 0 {
		per = DefaultPerMin
	}
	s.lim = newLimiter(per, time.Minute, s.now)
	s.pkgLim = newLimiter(per*2, time.Minute, s.now)
	return s, nil
}

// IssueRequest — параметры выпуска токена.
type IssueRequest struct {
	Name      string
	Weight    int // 0 → DefaultWeight
	CreatedBy string
	TTL       time.Duration // 0 → 1 час, максимум 24 часа
	// InstalledOnly — выдать только короткую команду для хоста, где tgproxy уже
	// установлен (пакет из кэша не требуется).
	InstalledOnly bool
}

// Issued — результат выпуска.
type Issued struct {
	ID    string
	Token string // показывается один раз
	// Cmdline — основная команда для чистого хоста: ставит пакет с сервера и регистрирует
	// агента. При IssueRequest.InstalledOnly совпадает с CmdlineInstalled.
	Cmdline string
	// CmdlineInstalled — регистрация агента, если tgproxy уже установлен на хосте.
	CmdlineInstalled string
	ExpiresAt        time.Time
}

// Issue выпускает токен с весом по умолчанию. cmdline — команда для агента.
func (s *Service) Issue(ctx context.Context, name string, ttl time.Duration) (token, cmdline string, err error) {
	is, err := s.IssueFor(ctx, IssueRequest{Name: name, TTL: ttl})
	if err != nil {
		return "", "", err
	}
	return is.Token, is.Cmdline, nil
}

// IssueFor выпускает токен: 32 байта crypto/rand; в БД только SHA-256.
func (s *Service) IssueFor(ctx context.Context, req IssueRequest) (Issued, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > MaxNameLen {
		return Issued{}, fmt.Errorf("%w: enrollment name must be 1..%d chars", store.ErrInvalid, MaxNameLen)
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		return Issued{}, fmt.Errorf("%w: ttl exceeds %s", store.ErrInvalid, MaxTTL)
	}
	weight := req.Weight
	if weight == 0 {
		weight = DefaultWeight
	}
	// Пакет проверяется до выпуска токена: нерабочая команда (и висящий токен) не выдаются.
	var pkg PackageInfo
	if !req.InstalledOnly {
		if s.cfg.Packages == nil {
			return Issued{}, fmt.Errorf("%w: источник пакетов не настроен", ErrPackageUnavailable)
		}
		var perr error
		if pkg, perr = s.cfg.Packages.Current(); perr != nil {
			return Issued{}, perr
		}
	}
	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return Issued{}, fmt.Errorf("enroll: random: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(raw))
	idRaw := make([]byte, 8)
	if _, err := rand.Read(idRaw); err != nil {
		return Issued{}, fmt.Errorf("enroll: random: %w", err)
	}
	now := s.now()
	e := store.Enrollment{
		ID: hex.EncodeToString(idRaw), TokenHash: hash[:], Name: name, Weight: weight,
		CreatedBy: req.CreatedBy, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if err := s.cfg.Enrollments.Create(ctx, e); err != nil {
		return Issued{}, fmt.Errorf("enroll: create: %w", err)
	}
	s.audit(ctx, req.CreatedBy, "enrollment.create", name, "", "id="+e.ID)
	installed := s.enrollCmd(token)
	cmd := installed
	if !req.InstalledOnly {
		cmd = s.installCmd(token, pkg)
	}
	return Issued{ID: e.ID, Token: token, Cmdline: cmd, CmdlineInstalled: installed, ExpiresAt: e.ExpiresAt}, nil
}

// enrollCmd — регистрация агента, когда tgproxy уже установлен. Токен идёт через stdin:
// printf — встроенная команда шелла, в `ps` его нет (в отличие от `sudo TGP_ENROLL_TOKEN=…`
// или --token). Алфавит токена безопасен в одинарных кавычках.
func (s *Service) enrollCmd(token string) string { return s.enrollCmdAs(token, "sudo") }

// enrollCmdAs — то же с заданным префиксом повышения прав ("sudo" или "$S").
func (s *Service) enrollCmdAs(token, priv string) string {
	return fmt.Sprintf("printf %%s '%s' | %s tgproxy agent enroll --token-stdin --server %s --ca-fingerprint %s",
		token, priv, s.cfg.GatewayURL, s.cfg.CA.CAFingerprint())
}

// installCmd — одна копируемая целиком команда для чистого Debian/Ubuntu (amd64): скачивает
// пакет с agent_gateway, сверяет sha256 из подписанного checksums.txt, ставит через apt-get
// (с зависимостями), регистрирует агента и включает сервис.
//
// Подробности безопасности:
//   - токен для скачивания передаётся заголовком через stdin (curl -H @-) от встроенного
//     printf — ни в argv curl, ни в ps его нет;
//   - TLS: только CA сервера (--cacert из PEM в команде), TLS 1.3, схема https; проверка
//     по имени хоста gateway (он в SAN серверного сертификата), без -k;
//   - цепочка выполняется в подоболочке с set -eu: любая ошибка останавливает цепочку,
//     временный каталог удаляется по trap EXIT.
func (s *Service) installCmd(token string, pkg PackageInfo) string {
	deb := pkg.Name
	lines := []string{
		"(",
		"set -eu",
		"T=$(mktemp -d)",
		`trap 'rm -rf "$T"' EXIT`,
		`chmod 755 "$T"`, // apt (пользователь _apt) должен прочитать deb
		// root — без sudo; иначе sudo (на чистом хосте под root его может не быть вовсе)
		`S=; [ "$(id -u)" -eq 0 ] || S=sudo`,
		`[ "$(dpkg --print-architecture)" = ` + AgentArch + ` ] || { echo "tgproxy: need ` + AgentArch + `" >&2; exit 1; }`,
		`command -v curl >/dev/null || { $S apt-get update -qq && $S apt-get install -y -qq curl ca-certificates; }`,
		"printf -- '" + pemForPrintf(s.cfg.CA.CertPEM()) + `' >"$T/ca.pem"`,
		fmt.Sprintf(`printf 'Authorization: Bearer %%s\n' '%s' | curl -fsS --proto =https --tlsv1.3 --cacert "$T/ca.pem" -H @- -o "$T/%s" '%s%s%s'`,
			token, deb, s.cfg.GatewayURL, PackagePathPrefix, deb),
		fmt.Sprintf(`(cd "$T" && echo '%s  %s' | sha256sum -c -)`, pkg.SHA256, deb),
		fmt.Sprintf(`$S apt-get install -y "$T/%s"`, deb),
		s.enrollCmdAs(token, "$S"),
		"$S systemctl enable --now tgproxy-agent",
		")",
	}
	return strings.Join(lines, "\n")
}

// pemForPrintf превращает PEM в аргумент-формат printf (переводы строк как \n); алфавит
// PEM не содержит %, \ и ', поэтому безопасен в одинарных кавычках.
func pemForPrintf(pem []byte) string {
	return strings.ReplaceAll(strings.TrimRight(string(pem), "\n"), "\n", `\n`) + `\n`
}

func (s *Service) audit(ctx context.Context, actor, action, target, ip, detail string) {
	if actor == "" {
		actor = "enroll"
	}
	if _, err := s.cfg.Audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: action, Target: target, IP: ip, Detail: detail,
	}); err != nil {
		s.log.Error("enroll: audit append failed", "action", action, "err", err)
	}
}

func (s *Service) observe(result string) {
	if s.cfg.Observe != nil {
		s.cfg.Observe(result)
	}
}

// agentSlug строит id агента из имени (pki.ValidAgentID).
func agentSlug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-._")
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-._")
	}
	if s == "" {
		return "agent"
	}
	return s
}
