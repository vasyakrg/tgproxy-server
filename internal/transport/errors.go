package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// SourceServerAgent — отказ возник на участке server → agent (соединение,
// TLS, обрыв), а не в ответе агента.
const SourceServerAgent = "server→agent"

// PhaseError — транспортная ошибка с фазой и источником.
type PhaseError struct {
	Phase  string // tgapi.Phase*
	Source string // SourceServerAgent | tgapi.SourceAgent
	Err    error
}

func (e *PhaseError) Error() string {
	msg := "<nil>"
	if e.Err != nil {
		msg = e.Err.Error()
	}
	return "transport: " + e.Phase + " (" + e.Source + "): " + redact.String(msg)
}

// Unwrap возвращает исходную ошибку.
func (e *PhaseError) Unwrap() error { return e.Err }

// Kind — укрупнённый исход попытки.
type Kind int

// Виды исхода.
const (
	// KindOK — запрос обслужен (ответ не ошибочный).
	KindOK Kind = iota
	// KindTelegramError — ответ сформировал Telegram (в т.ч. 4xx/5xx): не
	// транспортная ошибка, на здоровье агента не влияет.
	KindTelegramError
	// KindTransport — отказ канала или самого агента.
	KindTransport
)

func (k Kind) String() string {
	switch k {
	case KindOK:
		return "ok"
	case KindTelegramError:
		return "telegram_error"
	case KindTransport:
		return "transport"
	}
	return "unknown"
}

// Outcome — результат классификации для решений о ретрае.
type Outcome struct {
	Kind     Kind
	Phase    string // только для KindTransport (пусто при Canceled)
	Source   string // tgapi.SourceAgent | SourceServerAgent | tgapi.SourceTelegram
	NotSent  bool   // tgapi.PhaseNotSent(Phase): в Telegram запрос точно не ушёл
	Canceled bool   // ctx отменён вызывающим: ретраев нет
	Err      error
}

// Classify объединяет ошибку соединения server→agent и ответ агента.
//
// bodyWritten — признак «запрос (заголовки/тело) ушёл в агента»; учитывается
// только для «сырых» ошибок. *PhaseError от Dial уже содержит точную фазу.
//
//   - err != nil, resp != nil: ошибка чтения тела ответа → read (timeout при
//     таймауте);
//   - err != nil, resp == nil: PhaseError → как есть; иначе TLS → tls, dial →
//     dial, после записи → write (timeout при таймауте), до записи → pre-send;
//   - err == nil: X-TGP-Source=telegram → OK/TelegramError по статусу;
//     X-TGP-Error-Phase от агента → Transport с этой фазой; ошибочный статус
//     без фазы (агент/посторонний) → Transport/read (консервативно: не NotSent).
func Classify(resp *http.Response, err error, bodyWritten bool) Outcome {
	if err != nil {
		return classifyErr(resp, err, bodyWritten)
	}
	if resp == nil {
		return Outcome{Kind: KindTransport, Phase: tgapi.PhaseRead, Source: SourceServerAgent,
			Err: errors.New("transport: nil response")}
	}
	src := resp.Header.Get(tgapi.HeaderSource)
	if src == tgapi.SourceTelegram {
		k := KindOK
		if resp.StatusCode >= http.StatusBadRequest {
			k = KindTelegramError
		}
		return Outcome{Kind: k, Source: tgapi.SourceTelegram}
	}
	if phase := resp.Header.Get(tgapi.HeaderErrorPhase); phase != "" {
		if !knownPhase(phase) {
			phase = tgapi.PhaseRead
		}
		return Outcome{Kind: KindTransport, Phase: phase, Source: tgapi.SourceAgent,
			NotSent: tgapi.PhaseNotSent(phase)}
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return Outcome{Kind: KindTransport, Phase: tgapi.PhaseRead, Source: tgapi.SourceAgent}
	}
	return Outcome{Kind: KindOK, Source: tgapi.SourceAgent}
}

func classifyErr(resp *http.Response, err error, bodyWritten bool) Outcome {
	if errors.Is(err, context.Canceled) {
		return Outcome{Kind: KindTransport, Source: SourceServerAgent, Canceled: true, Err: err}
	}
	var pe *PhaseError
	if errors.As(err, &pe) {
		return Outcome{Kind: KindTransport, Phase: pe.Phase, Source: pe.Source,
			NotSent: tgapi.PhaseNotSent(pe.Phase), Err: err}
	}
	var phase string
	switch {
	case resp != nil:
		phase = tgapi.PhaseRead
		if isTimeout(err) {
			phase = tgapi.PhaseTimeout
		}
	case isTLSErr(err):
		phase = tgapi.PhaseTLS
	case isDialErr(err):
		phase = tgapi.PhaseDial
	case bodyWritten && isTimeout(err):
		phase = tgapi.PhaseTimeout
	case bodyWritten:
		phase = tgapi.PhaseWrite
	default:
		phase = tgapi.PhasePreSend
	}
	return Outcome{Kind: KindTransport, Phase: phase, Source: SourceServerAgent,
		NotSent: tgapi.PhaseNotSent(phase), Err: err}
}

func knownPhase(p string) bool {
	switch p {
	case tgapi.PhaseDial, tgapi.PhaseTLS, tgapi.PhasePreSend, tgapi.PhaseWrite, tgapi.PhaseRead, tgapi.PhaseTimeout:
		return true
	}
	return false
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isDialErr(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return true
	}
	var de *net.DNSError
	return errors.As(err, &de)
}

// isTLSErr распознаёт ошибки проверки сертификатов и алерты рукопожатия.
// В TLS 1.3 отказ сервера по клиентскому сертификату приходит уже после
// «завершения» рукопожатия на клиенте — как remote error: tls: bad certificate.
func isTLSErr(err error) bool {
	var (
		cve *tls.CertificateVerificationError
		ua  x509.UnknownAuthorityError
		ci  x509.CertificateInvalidError
		rh  tls.RecordHeaderError
		al  tls.AlertError
	)
	if errors.As(err, &cve) || errors.As(err, &ua) || errors.As(err, &ci) || errors.As(err, &rh) {
		return true
	}
	if errors.As(err, &al) {
		return handshakeAlert(uint8(al))
	}
	return strings.Contains(err.Error(), "remote error: tls:") && !strings.Contains(err.Error(), "internal error")
}

// handshakeAlert — алерты, возможные только при установке соединения/отказе
// по сертификату: handshake_failure, bad/unsupported/revoked/expired/unknown
// certificate, unknown_ca, access_denied, protocol_version, certificate_required.
func handshakeAlert(code uint8) bool {
	switch code {
	case 40, 42, 43, 44, 45, 46, 48, 49, 70, 116:
		return true
	}
	return false
}
