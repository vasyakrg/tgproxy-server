package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

const (
	totpPeriod = 30
	totpSkew   = 1
	totpDigits = otp.DigitsSix
	// replayTTL покрывает все шаги окна ±skew плюс запас.
	replayTTL = time.Duration(2*totpSkew+2) * totpPeriod * time.Second
)

// Sealer шифрует секреты ключом KEK (реализацию даёт internal/pki).
type Sealer interface {
	Seal(pt, aad []byte) ([]byte, error)
	Open(ct, aad []byte) ([]byte, error)
}

// Ошибки TOTP.
var (
	ErrTOTPInvalid  = errors.New("auth: invalid totp code")
	ErrTOTPReplayed = errors.New("auth: totp code already used")
)

// TOTP — генерация/проверка кодов с секретами под KEK и защитой от повторного использования.
type TOTP struct {
	sealer Sealer
	state  store.RateStateRepo // может быть nil только в CLI (Enroll)
	issuer string
}

// NewTOTP создаёт сервис. state нужен для Verify (anti-replay).
func NewTOTP(sealer Sealer, state store.RateStateRepo, issuer string) *TOTP {
	if issuer == "" {
		issuer = "tgproxy"
	}
	return &TOTP{sealer: sealer, state: state, issuer: issuer}
}

// Enrollment — результат регистрации TOTP.
type Enrollment struct {
	Secret string // base32; показывать пользователю один раз
	URI    string // otpauth://totp/...
	Sealed string // значение для users-файла: totp_secret_enc
}

func totpAAD(user string) []byte { return []byte("totp:" + user) }

// Enroll генерирует новый секрет для пользователя и шифрует его KEK.
func (t *TOTP) Enroll(user string) (*Enrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.issuer,
		AccountName: user,
		Period:      totpPeriod,
		SecretSize:  20,
		Digits:      totpDigits,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: totp generate: %w", err)
	}
	sealed, err := t.sealer.Seal([]byte(key.Secret()), totpAAD(user))
	if err != nil {
		return nil, fmt.Errorf("auth: totp seal: %w", err)
	}
	return &Enrollment{
		Secret: key.Secret(),
		URI:    key.URL(),
		Sealed: base64.StdEncoding.EncodeToString(sealed),
	}, nil
}

// QR рисует QR-код otpauth URI псевдографикой (полублоки), по строкам.
func (e *Enrollment) QR() (string, error) {
	code, err := qr.Encode(e.URI, qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("auth: qr: %w", err)
	}
	return renderQR(code), nil
}

// Verify проверяет код по зашифрованному секрету пользователя в окне ±1 шаг (30 с).
// Повторное использование шага тем же пользователем отклоняется (ErrTOTPReplayed).
func (t *TOTP) Verify(ctx context.Context, user, sealed, code string, now time.Time) error {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return fmt.Errorf("auth: totp secret encoding: %w", err)
	}
	secret, err := t.sealer.Open(raw, totpAAD(user))
	if err != nil {
		return fmt.Errorf("auth: totp open: %w", err)
	}
	if len(code) != int(totpDigits) {
		return ErrTOTPInvalid
	}
	cur := now.Unix() / totpPeriod
	matched := int64(-1)
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := cur + d
		if step < 0 {
			continue
		}
		want, err := hotp.GenerateCodeCustom(string(secret), uint64(step), hotp.ValidateOpts{Digits: totpDigits, Algorithm: otp.AlgorithmSHA1}) //nolint:gosec // step >= 0
		if err != nil {
			return fmt.Errorf("auth: totp generate: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && matched < 0 {
			matched = step
		}
	}
	if matched < 0 {
		return ErrTOTPInvalid
	}
	if t.state == nil {
		return errors.New("auth: totp anti-replay store is not configured")
	}
	ok, err := t.state.SetNX(ctx, "totp:used:"+user+":"+strconv.FormatInt(matched, 10), []byte("1"), replayTTL)
	if err != nil {
		return fmt.Errorf("auth: totp replay state: %w", err)
	}
	if !ok {
		return ErrTOTPReplayed
	}
	return nil
}
