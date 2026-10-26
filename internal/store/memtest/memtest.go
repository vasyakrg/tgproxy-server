// Package memtest — in-memory реализация store.Store для unit-тестов потребителей.
// Семантика сверяется с SQLite общим набором storetest. Не для продакшена.
package memtest

import (
	"bytes"
	"cmp"
	"context"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// Store — потокобезопасное in-memory хранилище.
type Store struct {
	mu sync.Mutex

	agents    map[string]store.Agent
	agentsVer int64

	rules    map[int64]store.AccessRule
	rulesID  int64
	rulesVer int64

	sessions map[string]store.Session
	rates    map[string]store.RateWindow

	outbox   []store.OutboxItem
	outboxID int64

	samples map[store.Resolution]map[[2]string]store.Sample // ключ: agent, ts

	audit   []store.AuditEntry
	auditID int64

	hostKeys map[string]store.HostKey

	certs  map[string]store.CertRecord
	denied map[string]store.DeniedCert
	ca     *store.CARecord

	enrolls map[string]store.Enrollment

	errs  []store.ErrorEvent
	errID int64
}

var _ store.Store = (*Store)(nil)

// New создаёт пустое хранилище.
func New() *Store {
	return &Store{
		agents:    map[string]store.Agent{},
		agentsVer: 1,
		rulesVer:  1,
		rules:     map[int64]store.AccessRule{},
		sessions:  map[string]store.Session{},
		rates:     map[string]store.RateWindow{},
		samples: map[store.Resolution]map[[2]string]store.Sample{
			store.Res10s: {}, store.Res5m: {},
		},
		hostKeys: map[string]store.HostKey{},
		certs:    map[string]store.CertRecord{},
		denied:   map[string]store.DeniedCert{},
		enrolls:  map[string]store.Enrollment{},
	}
}

// Close — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Close() error { return nil }

// Agents — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Agents() store.AgentRepo { return agentRepo{s} }

// AccessRules — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) AccessRules() store.AccessRuleRepo { return ruleRepo{s} }

// Sessions — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Sessions() store.SessionRepo { return sessionRepo{s} }

// Outbox — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Outbox() store.OutboxRepo { return outboxRepo{s} }

// RateState — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) RateState() store.RateStateRepo { return rateRepo{s} }

// History — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) History() store.HistoryRepo { return historyRepo{s} }

// Audit — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Audit() store.AuditRepo { return auditRepo{s} }

// HostKeys — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) HostKeys() store.HostKeyRepo { return hostKeyRepo{s} }

// Certs — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Certs() store.CertRepo { return certRepo{s} }

// Enrollments — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Enrollments() store.EnrollmentRepo { return enrollRepo{s} }

// Errors — доступ к репозиторию/ресурсу хранилища (store.Store).
func (s *Store) Errors() store.ErrorEventRepo { return errRepo{s} }

// trunc приводит время к точности хранения SQLite (миллисекунды, UTC).
func trunc(t time.Time) time.Time { return time.UnixMilli(t.UnixMilli()).UTC() }

func nowMS() time.Time { return trunc(time.Now()) }

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return slices.Clone(b)
}

// ---- agents ----

type agentRepo struct{ s *Store }

func (r agentRepo) Create(_ context.Context, a store.Agent) (store.Agent, error) {
	if err := a.Validate(); err != nil {
		return store.Agent{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if r.nameTaken(a.Name, "") {
		return store.Agent{}, store.ErrConflict
	}
	if _, ok := r.s.agents[a.ID]; ok {
		return store.Agent{}, store.ErrConflict
	}
	a.CreatedAt = nowMS()
	a.UpdatedAt = a.CreatedAt
	r.s.agents[a.ID] = a
	r.s.agentsVer++
	return a, nil
}

func (r agentRepo) nameTaken(name, exceptID string) bool {
	for id, x := range r.s.agents {
		if x.Name == name && id != exceptID {
			return true
		}
	}
	return false
}

func (r agentRepo) Get(_ context.Context, id string) (store.Agent, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	a, ok := r.s.agents[id]
	if !ok {
		return store.Agent{}, store.ErrNotFound
	}
	return a, nil
}

func (r agentRepo) List(context.Context) ([]store.Agent, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	out := make([]store.Agent, 0, len(r.s.agents))
	for _, a := range r.s.agents {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b store.Agent) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (r agentRepo) Update(_ context.Context, a store.Agent) (store.Agent, error) {
	if err := a.Validate(); err != nil {
		return store.Agent{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	cur, ok := r.s.agents[a.ID]
	if !ok {
		return store.Agent{}, store.ErrNotFound
	}
	if r.nameTaken(a.Name, a.ID) {
		return store.Agent{}, store.ErrConflict
	}
	a.CreatedAt = cur.CreatedAt
	a.UpdatedAt = nowMS()
	r.s.agents[a.ID] = a
	r.s.agentsVer++
	return a, nil
}

func (r agentRepo) mutate(id string, f func(*store.Agent)) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	a, ok := r.s.agents[id]
	if !ok {
		return store.ErrNotFound
	}
	f(&a)
	a.UpdatedAt = nowMS()
	r.s.agents[id] = a
	r.s.agentsVer++
	return nil
}

func (r agentRepo) SetWeight(_ context.Context, id string, weight int) error {
	if weight < 0 {
		return store.ErrInvalid
	}
	return r.mutate(id, func(a *store.Agent) { a.Weight = weight })
}

func (r agentRepo) SetDraining(_ context.Context, id string, d bool) error {
	return r.mutate(id, func(a *store.Agent) { a.Draining = d })
}

func (r agentRepo) Delete(_ context.Context, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.agents[id]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.agents, id)
	r.s.agentsVer++
	return nil
}

func (r agentRepo) Version(context.Context) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.s.agentsVer, nil
}

// ---- access rules ----

type ruleRepo struct{ s *Store }

func cloneRule(a store.AccessRule) store.AccessRule {
	a.CIDRs = slices.Clone(a.CIDRs)
	a.KeyHash = clone(a.KeyHash)
	if a.RevokedAt != nil {
		t := *a.RevokedAt
		a.RevokedAt = &t
	}
	return a
}

func (r ruleRepo) conflict(a store.AccessRule) bool {
	for id, x := range r.s.rules {
		if id == a.ID {
			continue
		}
		if x.Name == a.Name || (len(a.KeyHash) > 0 && bytes.Equal(x.KeyHash, a.KeyHash)) {
			return true
		}
	}
	return false
}

func (r ruleRepo) Create(_ context.Context, a store.AccessRule) (store.AccessRule, error) {
	if err := a.Validate(); err != nil {
		return store.AccessRule{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	a.ID = 0
	if r.conflict(a) {
		return store.AccessRule{}, store.ErrConflict
	}
	r.s.rulesID++
	a.ID = r.s.rulesID
	a.CreatedAt = nowMS()
	if len(a.KeyHash) == 0 {
		a.KeyHash = nil
	}
	if a.RevokedAt != nil {
		t := trunc(*a.RevokedAt)
		a.RevokedAt = &t
	}
	r.s.rules[a.ID] = cloneRule(a)
	r.s.rulesVer++
	return cloneRule(a), nil
}

func (r ruleRepo) Get(_ context.Context, id int64) (store.AccessRule, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	a, ok := r.s.rules[id]
	if !ok {
		return store.AccessRule{}, store.ErrNotFound
	}
	return cloneRule(a), nil
}

func (r ruleRepo) GetByName(_ context.Context, name string) (store.AccessRule, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, a := range r.s.rules {
		if a.Name == name {
			return cloneRule(a), nil
		}
	}
	return store.AccessRule{}, store.ErrNotFound
}

func (r ruleRepo) List(context.Context) ([]store.AccessRule, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.AccessRule
	for _, a := range r.s.rules {
		out = append(out, cloneRule(a))
	}
	slices.SortFunc(out, func(a, b store.AccessRule) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

func (r ruleRepo) Update(_ context.Context, a store.AccessRule) (store.AccessRule, error) {
	if a.Name == "" || a.RPS < 0 {
		return store.AccessRule{}, store.ErrInvalid
	}
	for _, p := range a.CIDRs {
		if !p.IsValid() {
			return store.AccessRule{}, store.ErrInvalid
		}
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	cur, ok := r.s.rules[a.ID]
	if !ok {
		return store.AccessRule{}, store.ErrNotFound
	}
	cur.Name, cur.CIDRs, cur.RPS, cur.Enabled = a.Name, slices.Clone(a.CIDRs), a.RPS, a.Enabled
	if len(cur.CIDRs) == 0 && len(cur.KeyHash) == 0 {
		return store.AccessRule{}, store.ErrInvalid
	}
	if r.conflict(cur) {
		return store.AccessRule{}, store.ErrConflict
	}
	r.s.rules[a.ID] = cur
	r.s.rulesVer++
	return cloneRule(cur), nil
}

func (r ruleRepo) Revoke(_ context.Context, id int64) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	cur, ok := r.s.rules[id]
	if !ok {
		return store.ErrNotFound
	}
	cur.Enabled = false
	if cur.RevokedAt == nil {
		t := nowMS()
		cur.RevokedAt = &t
	}
	r.s.rules[id] = cur
	r.s.rulesVer++
	return nil
}

func (r ruleRepo) Delete(_ context.Context, id int64) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.rules[id]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.rules, id)
	r.s.rulesVer++
	return nil
}

func (r ruleRepo) Version(context.Context) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.s.rulesVer, nil
}

// ---- sessions ----

type sessionRepo struct{ s *Store }

func alive(s store.Session, now time.Time) bool {
	return s.IdleExpiresAt.After(now) && s.ExpiresAt.After(now)
}

func (r sessionRepo) Create(_ context.Context, s store.Session) error {
	if err := s.Validate(); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.sessions[s.ID]; ok {
		return store.ErrConflict
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	if s.LastSeenAt.IsZero() {
		s.LastSeenAt = s.CreatedAt
	}
	s.CreatedAt, s.LastSeenAt = trunc(s.CreatedAt), trunc(s.LastSeenAt)
	s.IdleExpiresAt, s.ExpiresAt = trunc(s.IdleExpiresAt), trunc(s.ExpiresAt)
	r.s.sessions[s.ID] = s
	return nil
}

func (r sessionRepo) Get(_ context.Context, id string) (store.Session, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	s, ok := r.s.sessions[id]
	if !ok || !alive(s, time.Now()) {
		return store.Session{}, store.ErrNotFound
	}
	return s, nil
}

func (r sessionRepo) Touch(_ context.Context, id string, idle time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	now := time.Now()
	s, ok := r.s.sessions[id]
	if !ok || !alive(s, now) {
		return store.ErrNotFound
	}
	s.LastSeenAt = trunc(now)
	s.IdleExpiresAt = trunc(idle)
	if s.IdleExpiresAt.After(s.ExpiresAt) {
		s.IdleExpiresAt = s.ExpiresAt
	}
	r.s.sessions[id] = s
	return nil
}

func (r sessionRepo) Delete(_ context.Context, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	delete(r.s.sessions, id)
	return nil
}

func (r sessionRepo) DeleteByUser(_ context.Context, user string) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for id, s := range r.s.sessions {
		if s.User == user {
			delete(r.s.sessions, id)
			n++
		}
	}
	return n, nil
}

func (r sessionRepo) DeleteExpired(context.Context) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n, now := 0, time.Now()
	for id, s := range r.s.sessions {
		if !alive(s, now) {
			delete(r.s.sessions, id)
			n++
		}
	}
	return n, nil
}

// ---- rate state ----

type rateRepo struct{ s *Store }

func (r rateRepo) live(key string, now time.Time) (store.RateWindow, bool) {
	w, ok := r.s.rates[key]
	if !ok || !w.ExpiresAt.After(now) {
		return store.RateWindow{}, false
	}
	return w, true
}

func (r rateRepo) Get(_ context.Context, key string) (store.RateWindow, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	w, ok := r.live(key, time.Now())
	if !ok {
		return store.RateWindow{}, store.ErrNotFound
	}
	w.Value = clone(w.Value)
	return w, nil
}

func (r rateRepo) put(key string, v []byte, exp time.Time) {
	if v == nil {
		v = []byte{}
	}
	r.s.rates[key] = store.RateWindow{Key: key, Value: clone(v), ExpiresAt: trunc(exp)}
}

func (r rateRepo) Set(_ context.Context, key string, v []byte, ttl time.Duration) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.put(key, v, time.Now().Add(ttl))
	return nil
}

func (r rateRepo) SetNX(_ context.Context, key string, v []byte, ttl time.Duration) (bool, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	now := time.Now()
	if _, ok := r.live(key, now); ok {
		return false, nil
	}
	r.put(key, v, now.Add(ttl))
	return true, nil
}

func (r rateRepo) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	now := time.Now()
	w, ok := r.live(key, now)
	if !ok {
		r.put(key, []byte("1"), now.Add(ttl))
		return 1, nil
	}
	cur, _ := strconv.ParseInt(string(w.Value), 10, 64)
	cur++
	r.put(key, []byte(strconv.FormatInt(cur, 10)), w.ExpiresAt)
	return cur, nil
}

func (r rateRepo) Delete(_ context.Context, key string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	delete(r.s.rates, key)
	return nil
}

func (r rateRepo) DeleteExpired(context.Context) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n, now := 0, time.Now()
	for k, w := range r.s.rates {
		if !w.ExpiresAt.After(now) {
			delete(r.s.rates, k)
			n++
		}
	}
	return n, nil
}
