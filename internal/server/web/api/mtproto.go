package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/mtproto/link"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Действия аудита секретов MTProto. Ключ в аудит не попадает (только id, имя, префикс).
const (
	AuditMTProtoCreate = "mtproto_secret.create"
	AuditMTProtoUpdate = "mtproto_secret.update"
	AuditMTProtoRevoke = "mtproto_secret.revoke"
	AuditMTProtoRotate = "mtproto_secret.rotate"
	AuditMTProtoReveal = "mtproto_secret.reveal"
	AuditMTProtoPurge  = "mtproto_secret.purge"
)

const (
	mtKeyLen      = 16
	mtPrefixBytes = 2
	mtMaxConns    = 1_000_000
	mtMaxGrace    = 30 * 24 * time.Hour
	mtAADFmt      = "mtproto/%d"
)

var mtNameRe = regexp.MustCompile(`^[\p{L}\p{N}](?:[\p{L}\p{N} ._-]{0,62}[\p{L}\p{N}._-])?$`)

// ErrMTProtoEndpoint — не заданы хост или fronting_domain для ссылки.
var ErrMTProtoEndpoint = errors.New("mtproto: endpoint is not configured")

// ErrMTProtoActive — секрет ещё действует (не отозван или не истёк grace): удалять нельзя, сначала отзыв.
var ErrMTProtoActive = errors.New("mtproto: secret is still active")

// Sealer — шифрование секретов (pki.KEK).
type Sealer interface {
	Seal(pt, aad []byte) ([]byte, error)
	Open(ct, aad []byte) ([]byte, error)
}

// MTProtoEndpoint — то, что попадает в ссылку подключения.
type MTProtoEndpoint struct {
	Host    string
	Port    int
	Domain  string
	Enabled bool // mtproto.enabled; при false API работает, ответы помечаются disabled
}

// ResolveMTProtoEndpoint собирает параметры ссылки из конфига: host = public_host или хост
// public_base_url; порт = public_port, иначе порт листенера (shared — listen.proxy, dedicated — mtproto.listen).
func ResolveMTProtoEndpoint(m config.MTProtoConfig, publicBaseURL, proxyListen string) MTProtoEndpoint {
	ep := MTProtoEndpoint{Host: m.PublicHost, Domain: m.FrontingDomain, Enabled: m.Enabled}
	if ep.Host == "" {
		if u, err := url.Parse(publicBaseURL); err == nil {
			ep.Host = u.Hostname()
		}
	}
	listen := m.Listen
	if listen == "" || listen == "shared" {
		listen = proxyListen
	}
	ep.Port = m.PublicPort
	if ep.Port == 0 {
		if _, p, err := net.SplitHostPort(listen); err == nil {
			ep.Port, _ = strconv.Atoi(p)
		}
	}
	return ep
}

// MTProtoService — CRUD секретов MTProto с валидацией и аудитом. Общий для JSON API, UI и CLI-логики.
type MTProtoService struct {
	secrets  store.MTProtoSecretRepo
	audit    store.AuditRepo
	sealer   Sealer
	endpoint func() MTProtoEndpoint
	log      *slog.Logger
	now      func() time.Time
}

// NewMTProtoService создаёт сервис; endpoint, log и now могут быть nil (endpoint nil — ссылки недоступны).
func NewMTProtoService(secrets store.MTProtoSecretRepo, audit store.AuditRepo, sealer Sealer, endpoint func() MTProtoEndpoint, log *slog.Logger, now func() time.Time) *MTProtoService {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	if endpoint == nil {
		endpoint = func() MTProtoEndpoint { return MTProtoEndpoint{} }
	}
	return &MTProtoService{secrets: secrets, audit: audit, sealer: sealer, endpoint: endpoint, log: log, now: now}
}

// Endpoint возвращает текущие параметры ссылки.
func (s *MTProtoService) Endpoint() MTProtoEndpoint { return s.endpoint() }

// MTProtoCreateInput — ввод создания.
type MTProtoCreateInput struct {
	Name     string
	CIDRs    []string
	MaxConns int
}

// MTProtoUpdateInput — частичное обновление; nil — «не менять».
type MTProtoUpdateInput struct {
	Name     *string
	CIDRs    *[]string
	MaxConns *int
	Enabled  *bool
}

// MTProtoLinks — ссылки подключения.
type MTProtoLinks struct{ TG, HTTPS string }

// MTProtoCreated — результат создания/ротации. Links непусты только здесь (и в Reveal).
type MTProtoCreated struct {
	Secret store.MTProtoSecret
	Links  MTProtoLinks
	// LinkErr — ссылку собрать не удалось (нет host/fronting_domain); секрет при этом создан.
	LinkErr error
}

func newMTKey() ([mtKeyLen]byte, error) {
	var k [mtKeyLen]byte
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("mtproto: key: %w", err)
	}
	return k, nil
}

func (s *MTProtoService) sealer0(key [mtKeyLen]byte) store.SealFunc {
	return func(id int64) ([]byte, error) {
		return s.sealer.Seal(key[:], []byte(fmt.Sprintf(mtAADFmt, id)))
	}
}

func (s *MTProtoService) links(key [mtKeyLen]byte) (MTProtoLinks, error) {
	ep := s.endpoint()
	if ep.Host == "" || ep.Domain == "" || ep.Port <= 0 {
		return MTProtoLinks{}, ErrMTProtoEndpoint
	}
	tg, https := link.Build(ep.Host, ep.Port, key, ep.Domain)
	return MTProtoLinks{TG: tg, HTTPS: https}, nil
}

func checkMTName(name string) FieldErrors {
	if !mtNameRe.MatchString(name) {
		return FieldErrors{FieldName: "Буквы, цифры, пробел, «.», «_», «-»; до 64 символов"}
	}
	return nil
}

func checkMTMaxConns(n int) FieldErrors {
	if n < 0 || n > mtMaxConns {
		return FieldErrors{"max_conns": fmt.Sprintf("От 0 до %d (0 — без лимита)", mtMaxConns)}
	}
	return nil
}

func mergeFE(parts ...FieldErrors) FieldErrors {
	out := FieldErrors{}
	for _, p := range parts {
		for k, v := range p {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	return out
}

// List возвращает все секреты (включая отозванные).
func (s *MTProtoService) List(ctx context.Context) ([]store.MTProtoSecret, error) {
	return s.secrets.List(ctx)
}

// Create генерирует ключ, шифрует его KEK и создаёт секрет.
func (s *MTProtoService) Create(ctx context.Context, act Actor, in MTProtoCreateInput) (MTProtoCreated, error) {
	name := strings.TrimSpace(in.Name)
	cidrs, cfe := ParseCIDRs(in.CIDRs)
	if fe := mergeFE(checkMTName(name), cfe, checkMTMaxConns(in.MaxConns)); len(fe) > 0 {
		return MTProtoCreated{}, &ValidationError{Fields: fe}
	}
	key, err := newMTKey()
	if err != nil {
		return MTProtoCreated{}, err
	}
	got, err := s.secrets.Create(ctx, name, s.sealer0(key), hex.EncodeToString(key[:mtPrefixBytes]), cidrs, in.MaxConns)
	if err != nil {
		return MTProtoCreated{}, mapMTErr(err)
	}
	s.record(ctx, act, AuditMTProtoCreate, got, "")
	res := MTProtoCreated{Secret: got}
	res.Links, res.LinkErr = s.links(key)
	return res, nil
}

// Update применяет изменения.
func (s *MTProtoService) Update(ctx context.Context, act Actor, id int64, in MTProtoUpdateInput) (store.MTProtoSecret, error) {
	cur, err := s.secrets.Get(ctx, id)
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	if cur.RevokedAt != nil {
		return store.MTProtoSecret{}, &ValidationError{Fields: FieldErrors{FieldGeneral: "Секрет отозван, изменение невозможно"}}
	}
	var fes []FieldErrors
	if in.Name != nil {
		cur.Name = strings.TrimSpace(*in.Name)
		fes = append(fes, checkMTName(cur.Name))
	}
	if in.CIDRs != nil {
		var cfe FieldErrors
		cur.CIDRs, cfe = ParseCIDRs(*in.CIDRs)
		fes = append(fes, cfe)
	}
	if in.MaxConns != nil {
		cur.MaxConns = *in.MaxConns
		fes = append(fes, checkMTMaxConns(cur.MaxConns))
	}
	if in.Enabled != nil {
		cur.Enabled = *in.Enabled
	}
	if fe := mergeFE(fes...); len(fe) > 0 {
		return store.MTProtoSecret{}, &ValidationError{Fields: fe}
	}
	got, err := s.secrets.Update(ctx, cur)
	if err != nil {
		return store.MTProtoSecret{}, mapMTErr(err)
	}
	s.record(ctx, act, AuditMTProtoUpdate, got, "")
	return got, nil
}

// Revoke отзывает секрет немедленно.
func (s *MTProtoService) Revoke(ctx context.Context, act Actor, id int64) (store.MTProtoSecret, error) {
	cur, err := s.secrets.Get(ctx, id)
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	if err := s.secrets.Revoke(ctx, id, s.now()); err != nil {
		return store.MTProtoSecret{}, err
	}
	s.record(ctx, act, AuditMTProtoRevoke, cur, "")
	return cur, nil
}

// MTProtoPurgeable — секрет можно удалить окончательно: он отозван и больше не принимается (grace нет или истёк).
func MTProtoPurgeable(m store.MTProtoSecret, now time.Time) bool {
	return m.RevokedAt != nil && (m.GraceUntil == nil || !m.GraceUntil.After(now))
}

// Purge окончательно удаляет отозванный секрет с истёкшим grace (в том числе переименованный
// «<имя>~<id>» после ротации). Активный секрет — ErrMTProtoActive. Пишет аудит mtproto_secret.purge.
func (s *MTProtoService) Purge(ctx context.Context, act Actor, id int64) (store.MTProtoSecret, error) {
	cur, err := s.secrets.Get(ctx, id)
	if err != nil {
		return store.MTProtoSecret{}, err
	}
	if !MTProtoPurgeable(cur, s.now()) {
		return store.MTProtoSecret{}, ErrMTProtoActive
	}
	if err := s.secrets.Delete(ctx, id); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.MTProtoSecret{}, ErrMTProtoActive
		}
		return store.MTProtoSecret{}, err
	}
	s.record(ctx, act, AuditMTProtoPurge, cur, "")
	return cur, nil
}

// PurgeRevoked удаляет все секреты, пригодные для удаления (см. MTProtoPurgeable); возвращает их число.
func (s *MTProtoService) PurgeRevoked(ctx context.Context, act Actor) (int, error) {
	all, err := s.secrets.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range all {
		if !MTProtoPurgeable(m, s.now()) {
			continue
		}
		if _, err := s.Purge(ctx, act, m.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) || errors.Is(err, ErrMTProtoActive) {
				continue // удалён/изменён параллельно
			}
			return n, err
		}
		n++
	}
	return n, nil
}

// Rotate создаёт новый секрет (новый ключ) вместо id; старый действует ещё grace (0 — сразу отзывается).
func (s *MTProtoService) Rotate(ctx context.Context, act Actor, id int64, grace time.Duration) (MTProtoCreated, error) {
	if grace < 0 || grace > mtMaxGrace {
		return MTProtoCreated{}, &ValidationError{Fields: FieldErrors{"grace": "От 0 до 720h"}}
	}
	cur, err := s.secrets.Get(ctx, id)
	if err != nil {
		return MTProtoCreated{}, err
	}
	if cur.RevokedAt != nil {
		return MTProtoCreated{}, &ValidationError{Fields: FieldErrors{FieldGeneral: "Секрет отозван, ротация невозможна"}}
	}
	key, err := newMTKey()
	if err != nil {
		return MTProtoCreated{}, err
	}
	var until time.Time
	if grace > 0 {
		until = s.now().Add(grace)
	}
	got, err := s.secrets.Rotate(ctx, id, s.sealer0(key), hex.EncodeToString(key[:mtPrefixBytes]), until)
	if err != nil {
		return MTProtoCreated{}, mapMTErr(err)
	}
	detail := fmt.Sprintf("from=%d grace=%s", id, grace)
	s.record(ctx, act, AuditMTProtoRotate, got, detail)
	res := MTProtoCreated{Secret: got}
	res.Links, res.LinkErr = s.links(key)
	return res, nil
}

// Reveal расшифровывает ключ и собирает ссылки. Вызывающий обязан проверить свежий TOTP.
// Пишет аудит mtproto_secret.reveal.
func (s *MTProtoService) Reveal(ctx context.Context, act Actor, id int64) (MTProtoLinks, error) {
	cur, err := s.secrets.Get(ctx, id)
	if err != nil {
		return MTProtoLinks{}, err
	}
	if cur.RevokedAt != nil && (cur.GraceUntil == nil || !cur.GraceUntil.After(s.now())) {
		return MTProtoLinks{}, store.ErrNotFound
	}
	pt, err := s.sealer.Open(cur.SecretEnc, []byte(fmt.Sprintf(mtAADFmt, cur.ID)))
	if err != nil {
		return MTProtoLinks{}, fmt.Errorf("mtproto: open secret %d: %w", id, err)
	}
	if len(pt) != mtKeyLen {
		return MTProtoLinks{}, fmt.Errorf("mtproto: secret %d has invalid length", id)
	}
	var key [mtKeyLen]byte
	copy(key[:], pt)
	l, err := s.links(key)
	if err != nil {
		return MTProtoLinks{}, err
	}
	s.record(ctx, act, AuditMTProtoReveal, cur, "")
	return l, nil
}

func mapMTErr(err error) error {
	switch {
	case errors.Is(err, store.ErrConflict):
		return &ValidationError{Fields: FieldErrors{FieldName: "Секрет с таким названием уже существует"}}
	case errors.Is(err, store.ErrInvalid):
		return &ValidationError{Fields: FieldErrors{FieldGeneral: "Секрет не прошёл проверку"}}
	}
	return err
}

func (s *MTProtoService) record(ctx context.Context, act Actor, action string, m store.MTProtoSecret, extra string) {
	actor := act.User
	if actor == "" {
		actor = "-"
	}
	detail := fmt.Sprintf("id=%d prefix=%s cidrs=%d max_conns=%d enabled=%t", m.ID, m.Prefix, len(m.CIDRs), m.MaxConns, m.Enabled)
	if extra != "" {
		detail += " " + extra
	}
	if _, err := s.audit.Append(ctx, store.AuditEntry{
		At: s.now(), Actor: actor, Action: action, Target: m.Name, IP: act.IP, Detail: detail,
	}); err != nil {
		s.log.ErrorContext(ctx, "mtproto secret audit failed", "action", action, "secret", m.Name, "err", err)
	}
}

// mtCIDRStrings — сети секрета в строках.
func mtCIDRStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}
