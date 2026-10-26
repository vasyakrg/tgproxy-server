package agents

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/pki"
	"github.com/vasyakrg/tgproxy-server/internal/store"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

// Эндпоинты ротации на стороне агента (architecture §4).
const (
	CSRPath  = "/_agent/csr"
	CertPath = "/_agent/cert"
)

// Параметры ротации по умолчанию.
const (
	DefaultRotateInterval = time.Minute
	DefaultRotateGrace    = 10 * time.Minute
	DefaultBackoffBase    = time.Minute
	DefaultBackoffMax     = time.Hour
	DefaultRotateTimeout  = 30 * time.Second
	// rotateCooldown — после успеха автоматическая ротация агента не
	// запускается повторно, пока статус не успел обновиться.
	rotateCooldown = 5 * time.Minute
	maxRotateBody  = 64 << 10

	// ReasonRotated — причина записи в denylist для заменённых сертификатов.
	ReasonRotated        = "rotated"
	reasonRotationFailed = "rotation_failed"
)

// Ошибки ротации.
var (
	ErrRotationInProgress = errors.New("agents: rotation already in progress")
	ErrAgentUnknown       = errors.New("agents: unknown agent")
)

// AgentSource — чтение состава агентов (реализует *Registry).
type AgentSource interface {
	List() []State
	Get(id string) (State, bool)
	Ref(id string) (transport.AgentRef, bool)
}

var _ AgentSource = (*Registry)(nil)

// CertSigner подписывает CSR агента (реализует *pki.Authority).
type CertSigner interface {
	SignAgentCSR(ctx context.Context, csrPEM []byte, agentID string, ttl time.Duration) (certPEM []byte, serial string, err error)
}

var _ CertSigner = (*pki.Authority)(nil)

// Revoker заносит серийник в denylist (реализует *pki.Denylist).
type Revoker interface {
	Revoke(ctx context.Context, serial, reason string) error
}

// Caller — часть AgentTransport, нужная для вызова эндпоинтов агента.
type Caller interface {
	RoundTrip(ctx context.Context, agent transport.AgentRef, req *http.Request) (*http.Response, error)
}

// RotatorConfig — зависимости и параметры Rotator. Source, Caller, Signer,
// Revoker и Certs обязательны; остальное имеет значения по умолчанию.
type RotatorConfig struct {
	Source  AgentSource
	Caller  Caller
	Signer  CertSigner
	Revoker Revoker
	Certs   store.CertRepo

	Interval    time.Duration // период проверки (1m)
	Grace       time.Duration // задержка отзыва старого серийника (10m)
	BackoffBase time.Duration // первая пауза после ошибки (1m), далее ×2
	BackoffMax  time.Duration // потолок паузы (1h)
	Timeout     time.Duration // таймаут одной ротации (30s)
	TTL         time.Duration // срок нового сертификата (pki.DefaultTTL)

	Now      func() time.Time
	NewTimer TimerFunc
	Log      *slog.Logger
	// OnEvent вызывается после каждой попытки ротации (nil — только лог).
	OnEvent func(RotationEvent)
}

// RotationEvent — итог попытки ротации.
type RotationEvent struct {
	AgentID   string
	At        time.Time
	OK        bool
	NewSerial string
	Err       error
}

type rotState struct {
	fails    int
	nextAt   time.Time // не раньше (backoff)
	cooldown time.Time // не раньше (после успеха)
}

// Rotator ротирует сертификаты агентов на 2/3 срока (architecture §8).
//
// Отложенный отзыв старых серийников не хранится отдельно: он выводится из
// CertRepo (reconcile на каждом Tick), поэтому переживает рестарт.
type Rotator struct {
	cfg RotatorConfig

	mu    sync.Mutex
	busy  map[string]struct{}
	state map[string]*rotState
}

// NewRotator создаёт Rotator.
func NewRotator(cfg RotatorConfig) (*Rotator, error) {
	if cfg.Source == nil || cfg.Caller == nil || cfg.Signer == nil || cfg.Revoker == nil || cfg.Certs == nil {
		return nil, errors.New("agents: rotator requires source, caller, signer, revoker and certs")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultRotateInterval
	}
	if cfg.Grace < 0 {
		cfg.Grace = 0
	} else if cfg.Grace == 0 {
		cfg.Grace = DefaultRotateGrace
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = DefaultBackoffBase
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = DefaultBackoffMax
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultRotateTimeout
	}
	if cfg.TTL <= 0 {
		cfg.TTL = pki.DefaultTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.NewTimer == nil {
		cfg.NewTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
			t := time.NewTimer(d)
			return t.C, t.Stop
		}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Rotator{cfg: cfg, busy: map[string]struct{}{}, state: map[string]*rotState{}}, nil
}

// Run вызывает Tick каждые Interval до отмены ctx.
func (r *Rotator) Run(ctx context.Context) {
	for {
		r.Tick(ctx)
		ch, stop := r.cfg.NewTimer(r.cfg.Interval)
		select {
		case <-ctx.Done():
			stop()
			return
		case <-ch:
		}
	}
}

// Tick выполняет созревшие отложенные отзывы и ротирует агентов, у которых
// сертификат прожил ≥2/3 срока. Агенты в backoff/cooldown и down пропускаются.
func (r *Rotator) Tick(ctx context.Context) {
	r.reconcile(ctx)
	now := r.cfg.Now()
	for _, st := range r.cfg.Source.List() {
		if ctx.Err() != nil {
			return
		}
		id := st.Agent.ID
		if !st.Up || st.LastStatus == nil || st.LastStatus.CertNotAfter.IsZero() {
			continue
		}
		if !r.eligible(id, now) {
			continue
		}
		if !r.due(ctx, id, st.LastStatus.CertNotAfter, now) {
			continue
		}
		if err := r.rotate(ctx, id, false); err != nil && !errors.Is(err, ErrRotationInProgress) {
			r.cfg.Log.Warn("agents: cert rotation failed", "agent", id, "err", err)
		}
	}
	r.reconcile(ctx)
}

// RotateNow принудительно ротирует сертификат агента (кнопка UI), игнорируя
// срок и backoff. ErrRotationInProgress — если ротация уже идёт.
func (r *Rotator) RotateNow(ctx context.Context, agentID string) error {
	return r.rotate(ctx, agentID, true)
}

func (r *Rotator) eligible(id string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.busy[id]; busy {
		return false
	}
	s := r.state[id]
	return s == nil || (!now.Before(s.nextAt) && !now.Before(s.cooldown))
}

// due: пора ли ротировать. NotBefore берётся из CertRepo по совпадению
// NotAfter, иначе вычисляется по сроку 90 дней.
func (r *Rotator) due(ctx context.Context, id string, notAfter, now time.Time) bool {
	notBefore := notAfter.Add(-pki.DefaultTTL)
	if recs, err := r.cfg.Certs.ListByAgent(ctx, id); err == nil {
		for _, c := range recs {
			if c.NotAfter.Truncate(time.Second).Equal(notAfter.Truncate(time.Second)) {
				notBefore = c.NotBefore
				break
			}
		}
	}
	return pki.DueForRotation(&x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}, now)
}

func (r *Rotator) rotate(ctx context.Context, id string, manual bool) error {
	ref, ok := r.cfg.Source.Ref(id)
	if !ok {
		return fmt.Errorf("%w: %q", ErrAgentUnknown, id)
	}
	r.mu.Lock()
	if _, busy := r.busy[id]; busy {
		r.mu.Unlock()
		return ErrRotationInProgress
	}
	r.busy[id] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.busy, id)
		r.mu.Unlock()
	}()

	octx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()
	serial, err := r.doRotate(octx, ref)
	now := r.cfg.Now()

	r.mu.Lock()
	s := r.state[id]
	if s == nil {
		s = &rotState{}
		r.state[id] = s
	}
	if err != nil {
		s.fails++
		s.nextAt = now.Add(r.backoff(s.fails))
	} else {
		s.fails, s.nextAt = 0, time.Time{}
		s.cooldown = now.Add(rotateCooldown)
	}
	r.mu.Unlock()

	ev := RotationEvent{AgentID: id, At: now, OK: err == nil, NewSerial: serial, Err: err}
	if err == nil {
		r.cfg.Log.Info("agents: cert rotated", "agent", id, "serial", serial, "manual", manual)
	}
	if r.cfg.OnEvent != nil {
		r.cfg.OnEvent(ev)
	}
	return err
}

func (r *Rotator) backoff(fails int) time.Duration {
	d := r.cfg.BackoffBase
	for i := 1; i < fails && d < r.cfg.BackoffMax; i++ {
		d *= 2
	}
	return min(d, r.cfg.BackoffMax)
}

// doRotate: CSR → подпись → PUT. Возвращает новый серийник и серийники
// сертификатов, которые нужно отозвать после грейса.
func (r *Rotator) doRotate(ctx context.Context, ref transport.AgentRef) (string, error) {
	csr, err := r.fetchCSR(ctx, ref)
	if err != nil {
		return "", err
	}
	certPEM, serial, err := r.cfg.Signer.SignAgentCSR(ctx, csr, ref.ID, r.cfg.TTL)
	if err != nil {
		return "", fmt.Errorf("sign csr: %w", err)
	}
	if err := r.putCert(ctx, ref, certPEM); err != nil {
		// Новый сертификат не доставлен — отзываем его сразу.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if rerr := r.cfg.Revoker.Revoke(rctx, serial, reasonRotationFailed); rerr != nil {
			r.cfg.Log.Warn("agents: revoke undelivered cert failed", "agent", ref.ID, "serial", serial, "err", rerr)
		}
		return "", err
	}
	return serial, nil
}

// staleCerts возвращает для агента неотозванные сертификаты, кроме самого
// свежего (по CreatedAt, затем NotBefore), и сам свежий. Отозванные
// (в т.ч. rotation_failed) в выборе актуального не участвуют.
func (r *Rotator) staleCerts(ctx context.Context, id string, denied map[string]struct{}) (stale []store.CertRecord, newest store.CertRecord, ok bool) {
	recs, err := r.cfg.Certs.ListByAgent(ctx, id)
	if err != nil {
		r.cfg.Log.Warn("agents: list certs failed", "agent", id, "err", err)
		return nil, newest, false
	}
	var live []store.CertRecord
	for _, c := range recs {
		if _, d := denied[c.Serial]; !d {
			live = append(live, c)
		}
	}
	if len(live) < 2 {
		return nil, newest, false
	}
	ni := 0
	for i, c := range live {
		n := live[ni]
		if c.CreatedAt.After(n.CreatedAt) || (c.CreatedAt.Equal(n.CreatedAt) && c.NotBefore.After(n.NotBefore)) {
			ni = i
		}
	}
	newest = live[ni]
	for i, c := range live {
		if i != ni {
			stale = append(stale, c)
		}
	}
	return stale, newest, true
}

func (r *Rotator) deniedSet(ctx context.Context) (map[string]struct{}, bool) {
	list, err := r.cfg.Certs.ListDenied(ctx)
	if err != nil {
		r.cfg.Log.Warn("agents: list denied failed", "err", err)
		return nil, false
	}
	m := make(map[string]struct{}, len(list))
	for _, d := range list {
		m[d.Serial] = struct{}{}
	}
	return m, true
}

func (r *Rotator) fetchCSR(ctx context.Context, ref transport.AgentRef) ([]byte, error) {
	resp, err := r.call(ctx, ref, http.MethodPost, CSRPath, nil)
	if err != nil {
		return nil, fmt.Errorf("request csr: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRotateBody))
		return nil, fmt.Errorf("request csr: agent status %d", resp.StatusCode)
	}
	var body struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRotateBody)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode csr response: %w", err)
	}
	if body.CSR == "" {
		return nil, errors.New("agent returned empty csr")
	}
	return []byte(body.CSR), nil
}

func (r *Rotator) putCert(ctx context.Context, ref transport.AgentRef, certPEM []byte) error {
	payload, err := json.Marshal(struct {
		Cert string `json:"cert"`
	}{Cert: string(certPEM)})
	if err != nil {
		return err
	}
	resp, err := r.call(ctx, ref, http.MethodPut, CertPath, payload)
	if err != nil {
		return fmt.Errorf("put cert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRotateBody))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("put cert: agent status %d", resp.StatusCode)
	}
	return nil
}

func (r *Rotator) call(ctx context.Context, ref transport.AgentRef, method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://agent"+path, rd)
	if err != nil {
		return nil, err
	}
	req.URL = &url.URL{Path: path}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return r.cfg.Caller.RoundTrip(ctx, ref, req)
}

// reconcile отзывает (причина "rotated") неотозванные сертификаты агента,
// кроме самого свежего, если преемник выдан не позже now-Grace. Состояние
// выводится из CertRepo, поэтому переживает рестарт. Если агент в статусе
// сообщает срок, не совпадающий со свежим сертификатом, он ещё не на нём —
// старый не трогаем.
func (r *Rotator) reconcile(ctx context.Context) {
	denied, ok := r.deniedSet(ctx)
	if !ok {
		return
	}
	now := r.cfg.Now()
	for _, st := range r.cfg.Source.List() {
		stale, newest, ok := r.staleCerts(ctx, st.Agent.ID, denied)
		if !ok || now.Before(newest.CreatedAt.Add(r.cfg.Grace)) {
			continue
		}
		if st.LastStatus != nil && !st.LastStatus.CertNotAfter.IsZero() &&
			!st.LastStatus.CertNotAfter.Truncate(time.Second).Equal(newest.NotAfter.Truncate(time.Second)) {
			continue
		}
		for _, c := range stale {
			if err := r.cfg.Revoker.Revoke(ctx, c.Serial, ReasonRotated); err != nil {
				r.cfg.Log.Warn("agents: revoke rotated cert failed", "serial", c.Serial, "err", err)
			}
		}
	}
}

// PendingRevokes — число сертификатов, ожидающих отзыва (вычисляется по CertRepo).
func (r *Rotator) PendingRevokes() int {
	ctx := context.Background()
	denied, ok := r.deniedSet(ctx)
	if !ok {
		return 0
	}
	n := 0
	for _, st := range r.cfg.Source.List() {
		stale, _, _ := r.staleCerts(ctx, st.Agent.ID, denied)
		n += len(stale)
	}
	return n
}
