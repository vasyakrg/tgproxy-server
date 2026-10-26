package installer

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// DefaultDialTimeout — таймаут TCP-подключения и SSH-рукопожатия.
const DefaultDialTimeout = 15 * time.Second

// Ошибки подключения.
var (
	// ErrHostKeyMismatch — ключ хоста не совпал с закреплённым (возможна подмена).
	ErrHostKeyMismatch = errors.New("installer: host key mismatch")
	// ErrPassphraseRequired — приватный ключ зашифрован, а passphrase не задана.
	ErrPassphraseRequired = errors.New("installer: ключ зашифрован, нужна passphrase")
	// ErrBadPassphrase — passphrase не подходит к ключу.
	ErrBadPassphrase = errors.New("installer: неверная passphrase для ключа")
	// ErrNoAuth — не задан способ аутентификации.
	ErrNoAuth = errors.New("installer: не задан пароль или приватный ключ")
)

// ErrHostKeyUnknown — ключ хоста ещё не закреплён (TOFU): нужно подтвердить отпечаток.
type ErrHostKeyUnknown struct {
	Algo        string
	Fingerprint string
}

func (e *ErrHostKeyUnknown) Error() string {
	if e.Fingerprint == "" {
		return "installer: ключ хоста не закреплён, подтвердите отпечаток"
	}
	return fmt.Sprintf("installer: ключ хоста не закреплён: %s %s", e.Algo, e.Fingerprint)
}

// Target — куда и под кем подключаться.
type Target struct {
	Host string
	Port int
	User string
}

// Addr — "host:port" (IPv6 в скобках); это же ключ пина в HostKeyRepo.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

func (t Target) validate() error {
	if err := validateHost(t.Host); err != nil {
		return err
	}
	if err := validatePort("ssh port", t.Port); err != nil {
		return err
	}
	return validateUser(t.User)
}

// Auth — способ аутентификации. Срезы принадлежат задаче и обнуляются Zero.
type Auth struct {
	Password      []byte
	PrivateKeyPEM []byte
	Passphrase    []byte
	// Signer — готовый ключ (серверный ключ tgproxy-deploy).
	Signer ssh.Signer
}

// Clone копирует секреты (вызывающий сам обнуляет свои буферы).
func (a Auth) Clone() Auth {
	return Auth{
		Password:      append([]byte(nil), a.Password...),
		PrivateKeyPEM: append([]byte(nil), a.PrivateKeyPEM...),
		Passphrase:    append([]byte(nil), a.Passphrase...),
		Signer:        a.Signer,
	}
}

// Zero затирает секреты в памяти.
func (a *Auth) Zero() {
	clear(a.Password)
	clear(a.PrivateKeyPEM)
	clear(a.Passphrase)
	a.Password, a.PrivateKeyPEM, a.Passphrase, a.Signer = nil, nil, nil, nil
}

// empty — способ аутентификации не задан.
func (a Auth) empty() bool {
	return len(a.Password) == 0 && len(a.PrivateKeyPEM) == 0 && a.Signer == nil
}

// secrets — значения, которые нельзя выводить в события и логи.
func (a Auth) secrets() [][]byte {
	var out [][]byte
	for _, s := range [][]byte{a.Password, a.Passphrase} {
		if len(s) > 0 {
			out = append(out, s)
		}
	}
	if len(a.PrivateKeyPEM) > 0 {
		out = append(out, a.PrivateKeyPEM)
		// Построчно: вывод удалённых утилит может склеить/переформатировать PEM.
		for _, l := range bytes.Split(a.PrivateKeyPEM, []byte("\n")) {
			if l = bytes.TrimSpace(l); len(l) >= 16 && !bytes.HasPrefix(l, []byte("-----")) {
				out = append(out, l)
			}
		}
	}
	return out
}

// methods строит методы аутентификации; ошибки ключа — понятные и до подключения.
func (a Auth) methods() ([]ssh.AuthMethod, error) {
	var ms []ssh.AuthMethod
	if a.Signer != nil {
		ms = append(ms, ssh.PublicKeys(a.Signer))
	}
	if len(a.PrivateKeyPEM) > 0 {
		sg, err := parseKey(a.PrivateKeyPEM, a.Passphrase)
		if err != nil {
			return nil, err
		}
		ms = append(ms, ssh.PublicKeys(sg))
	}
	if len(a.Password) > 0 {
		pw := a.Password // ссылка: после Zero пароль недоступен
		ms = append(ms, ssh.PasswordCallback(func() (string, error) {
			if len(pw) == 0 {
				return "", errors.New("installer: credentials already wiped")
			}
			return string(pw), nil
		}))
	}
	if len(ms) == 0 {
		return nil, ErrNoAuth
	}
	return ms, nil
}

func parseKey(pemBytes, passphrase []byte) (ssh.Signer, error) {
	var (
		sg  ssh.Signer
		err error
	)
	if len(passphrase) > 0 {
		sg, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
	} else {
		sg, err = ssh.ParsePrivateKey(pemBytes)
	}
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return sg, nil
	case errors.As(err, &missing):
		return nil, ErrPassphraseRequired
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, ErrBadPassphrase
	default:
		return nil, errors.New("installer: не удалось разобрать приватный ключ")
	}
}

// Validate проверяет, что ключ разбирается (до начала задачи).
func (a Auth) Validate() error {
	_, err := a.methods()
	return err
}

// HostKeyAlerter — получатель алерта hostkey_mismatch (notify.Evaluator).
type HostKeyAlerter interface {
	HostKeyMismatch(ctx context.Context, agentID, host string)
}

// HostKeyPolicy — как проверять ключ хоста: только по пину из Repo.
type HostKeyPolicy struct {
	Repo    store.HostKeyRepo
	AgentID string // для алерта
	Alerter HostKeyAlerter
	Timeout time.Duration // 0 → DefaultDialTimeout
}

// HostKeyInfo — отпечаток ключа хоста, показываемый для подтверждения.
type HostKeyInfo struct {
	Algo        string
	Fingerprint string
	PublicKey   []byte
}

func (p HostKeyPolicy) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return DefaultDialTimeout
}

func algosFor(key ssh.PublicKey) []string {
	if key.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{key.Type()}
}

// connect устанавливает TCP и выполняет рукопожатие с учётом ctx.
func connect(ctx context.Context, addr string, timeout time.Duration, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("installer: подключение к %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if !stop() && err == nil {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// Dial подключается по SSH. Ключ хоста обязан быть закреплён в policy.Repo
// (ssh.FixedHostKey); не закреплён → *ErrHostKeyUnknown, не совпал →
// ErrHostKeyMismatch и алерт hostkey_mismatch.
func Dial(ctx context.Context, t Target, a Auth, p HostKeyPolicy) (*ssh.Client, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if p.Repo == nil {
		return nil, errors.New("installer: host key repo is required")
	}
	methods, err := a.methods()
	if err != nil {
		return nil, err
	}
	var pinned ssh.PublicKey
	switch rec, gerr := p.Repo.Get(ctx, t.Addr()); {
	case gerr == nil:
		if pinned, err = ssh.ParsePublicKey(rec.PublicKey); err != nil {
			return nil, fmt.Errorf("installer: закреплённый ключ хоста повреждён: %w", err)
		}
	case errors.Is(gerr, store.ErrNotFound):
	default:
		return nil, fmt.Errorf("installer: чтение ключа хоста: %w", gerr)
	}

	var hkErr error
	cfg := &ssh.ClientConfig{
		User:    t.User,
		Auth:    methods,
		Timeout: p.timeout(),
		HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
			if pinned == nil {
				hkErr = &ErrHostKeyUnknown{Algo: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
				return hkErr
			}
			if err := ssh.FixedHostKey(pinned)(host, remote, key); err != nil {
				hkErr = fmt.Errorf("%w: ожидался %s, получен %s", ErrHostKeyMismatch,
					ssh.FingerprintSHA256(pinned), ssh.FingerprintSHA256(key))
				return hkErr
			}
			return nil
		},
	}
	if pinned != nil {
		cfg.HostKeyAlgorithms = algosFor(pinned)
	}
	cl, err := connect(ctx, t.Addr(), p.timeout(), cfg)
	if err != nil {
		if hkErr != nil {
			if errors.Is(hkErr, ErrHostKeyMismatch) && p.Alerter != nil {
				p.Alerter.HostKeyMismatch(context.WithoutCancel(ctx), p.AgentID, t.Addr())
			}
			return nil, hkErr
		}
		return nil, fmt.Errorf("installer: ssh %s@%s: %w", t.User, t.Addr(), err)
	}
	return cl, nil
}

var errProbeDone = errors.New("installer: host key captured")

// Probe подключается без аутентификации и возвращает ключ хоста (TOFU).
func Probe(ctx context.Context, t Target, timeout time.Duration) (HostKeyInfo, error) {
	if err := validateHost(t.Host); err != nil {
		return HostKeyInfo{}, err
	}
	if err := validatePort("ssh port", t.Port); err != nil {
		return HostKeyInfo{}, err
	}
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	var got HostKeyInfo
	cfg := &ssh.ClientConfig{
		User: "probe",
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = HostKeyInfo{Algo: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), PublicKey: key.Marshal()}
			return errProbeDone
		},
	}
	_, err := connect(ctx, t.Addr(), timeout, cfg)
	if got.Fingerprint != "" {
		return got, nil
	}
	if err == nil {
		err = errors.New("host key not received")
	}
	return HostKeyInfo{}, fmt.Errorf("installer: чтение ключа хоста %s: %w", t.Addr(), err)
}

// ProbeHostKey — первое подключение без аутентификации: возвращает алгоритм и
// отпечаток ключа хоста для подтверждения в UI. Ключ при этом не сохраняется.
func ProbeHostKey(ctx context.Context, t Target) (algo, fingerprint string, err error) {
	info, err := Probe(ctx, t, 0)
	if err != nil {
		return "", "", err
	}
	return info.Algo, info.Fingerprint, nil
}

// algoLabel — как показывать алгоритм в UI ("ED25519").
func algoLabel(algo string) string {
	switch algo {
	case ssh.KeyAlgoED25519:
		return "ED25519"
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return "RSA"
	case ssh.KeyAlgoECDSA256:
		return "ECDSA-256"
	case ssh.KeyAlgoECDSA384:
		return "ECDSA-384"
	case ssh.KeyAlgoECDSA521:
		return "ECDSA-521"
	}
	return algo
}

// Label — "ED25519 · SHA256:…" для экрана подтверждения.
func (h HostKeyInfo) Label() string { return algoLabel(h.Algo) + " · " + h.Fingerprint }
