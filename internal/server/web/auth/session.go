package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Параметры сессий.
const (
	SessionCookie  = "__Host-sid"
	PendingCookie  = "__Host-pending"
	SessionIdleTTL = 30 * time.Minute
	SessionAbsTTL  = 12 * time.Hour
	PendingTTL     = 5 * time.Minute

	kindFull    = "full"
	kindPending = "pending"
	tokenBytes  = 32
)

// ErrNoSession — нет действующей сессии.
var ErrNoSession = errors.New("auth: no valid session")

// Session — сессия вместе с сырым токеном (в БД хранится только SHA-256).
type Session struct {
	Token         string
	User          string
	IP            string
	CreatedAt     time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
}

// Manager — веб-сессии поверх store.SessionRepo.
type Manager struct {
	repo store.SessionRepo
	now  func() time.Time
}

// NewManager создаёт менеджер; now == nil -> time.Now.
func NewManager(repo store.SessionRepo, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{repo: repo, now: now}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// create заводит запись заданного вида с новым случайным id (поэтому логин всегда ротирует id).
func (m *Manager) create(ctx context.Context, user, ip, kind string, idle, abs time.Duration) (*Session, error) {
	tok, err := newToken()
	if err != nil {
		return nil, err
	}
	now := m.now()
	s := &Session{Token: tok, User: user, IP: ip, CreatedAt: now, IdleExpiresAt: now.Add(idle), ExpiresAt: now.Add(abs)}
	err = m.repo.Create(ctx, store.Session{
		ID: hashToken(tok), User: user, Kind: kind, IP: ip,
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: s.IdleExpiresAt, ExpiresAt: s.ExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: create session: %w", err)
	}
	return s, nil
}

// Create создаёт полную сессию (idle 30m / abs 12h).
func (m *Manager) Create(ctx context.Context, user, ip string) (*Session, error) {
	return m.create(ctx, user, ip, kindFull, SessionIdleTTL, SessionAbsTTL)
}

func (m *Manager) lookup(ctx context.Context, token, kind string) (*Session, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrNoSession
	}
	id := hashToken(token)
	rec, err := m.repo.Get(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("auth: get session: %w", err)
	}
	now := m.now()
	if rec.Kind != kind || !rec.IdleExpiresAt.After(now) || !rec.ExpiresAt.After(now) {
		if !rec.IdleExpiresAt.After(now) || !rec.ExpiresAt.After(now) {
			_ = m.repo.Delete(ctx, id)
		}
		return nil, ErrNoSession
	}
	return &Session{Token: token, User: rec.User, IP: rec.IP, CreatedAt: rec.CreatedAt, IdleExpiresAt: rec.IdleExpiresAt, ExpiresAt: rec.ExpiresAt}, nil
}

// Get возвращает действующую полную сессию из cookie запроса.
func (m *Manager) Get(r *http.Request) (*Session, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, ErrNoSession
	}
	return m.lookup(r.Context(), c.Value, kindFull)
}

// Touch продлевает idle-дедлайн (не дальше абсолютного).
func (m *Manager) Touch(ctx context.Context, s *Session) error {
	idle := m.now().Add(SessionIdleTTL)
	if err := m.repo.Touch(ctx, hashToken(s.Token), idle); err != nil {
		return fmt.Errorf("auth: touch session: %w", err)
	}
	s.IdleExpiresAt = idle
	if idle.After(s.ExpiresAt) {
		s.IdleExpiresAt = s.ExpiresAt
	}
	return nil
}

// Destroy удаляет сессию по токену.
func (m *Manager) Destroy(ctx context.Context, token string) error {
	if err := m.repo.Delete(ctx, hashToken(token)); err != nil {
		return fmt.Errorf("auth: destroy session: %w", err)
	}
	return nil
}

// DestroyUser удаляет все сессии пользователя (в том числе pending).
func (m *Manager) DestroyUser(ctx context.Context, user string) (int, error) {
	n, err := m.repo.DeleteByUser(ctx, user)
	if err != nil {
		return 0, fmt.Errorf("auth: destroy user sessions: %w", err)
	}
	return n, nil
}

func cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
}

// SetCookie выставляет cookie сессии (Secure; HttpOnly; SameSite=Strict; Path=/).
func (m *Manager) SetCookie(w http.ResponseWriter, s *Session) {
	left := max(int(s.ExpiresAt.Sub(m.now()).Seconds()), 1)
	http.SetCookie(w, cookie(SessionCookie, s.Token, left))
}

// ClearCookie удаляет cookie сессии.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, cookie(SessionCookie, "", -1))
}
