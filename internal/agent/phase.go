package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// stage — монотонно растущая стадия исходящего запроса.
type stage int32

const (
	stageStart        stage = iota // ещё нет соединения (DNS/connect/TLS)
	stageConnected                 // соединение готово, заголовки не записаны
	stageWroteHeaders              // заголовки записаны, тело/запрос в пути
	stageWroteRequest              // запрос записан полностью, ждём ответ
	stageGotResponse               // получен первый байт ответа
)

type trackerKey struct{}

// phaseTracker размечает фазы исходящего запроса через httptrace и по ошибке
// RoundTrip определяет, на какой фазе он упал.
//
//	dial     — ошибка DNS/connect (запрос точно не ушёл)
//	tls      — ошибка TLS-рукопожатия (точно не ушёл)
//	pre-send — соединение есть, WroteHeaders ещё не было (точно не ушёл)
//	write    — после начала записи, до WroteRequest (Telegram мог получить)
//	read     — запрос записан, ждём/читаем заголовки ответа
//	timeout  — истёк дедлайн (X-TGP-Timeout-Ms); считается «мог уйти»
type phaseTracker struct {
	start     time.Time
	skipRTT   bool // getUpdates и файлы не учитываются в EWMA upstream RTT
	stage     atomic.Int32
	dialErr   atomic.Bool
	tlsErr    atomic.Bool
	writeErr  atomic.Bool
	firstByte atomic.Int64           // ns от start до первого байта ответа; 0 — не было
	errPhase  atomic.Pointer[string] // фаза отказа (errorHandler); nil — ответил Telegram
}

func newPhaseTracker(now time.Time) *phaseTracker { return &phaseTracker{start: now} }

func (t *phaseTracker) advance(s stage) {
	for {
		cur := t.stage.Load()
		if cur >= int32(s) || t.stage.CompareAndSwap(cur, int32(s)) {
			return
		}
	}
}

func (t *phaseTracker) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSDone: func(i httptrace.DNSDoneInfo) {
			if i.Err != nil {
				t.dialErr.Store(true)
			}
		},
		ConnectDone: func(_, _ string, err error) {
			if err != nil {
				t.dialErr.Store(true)
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				t.tlsErr.Store(true)
			}
		},
		GotConn:      func(httptrace.GotConnInfo) { t.advance(stageConnected) },
		WroteHeaders: func() { t.advance(stageWroteHeaders) },
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err != nil {
				t.writeErr.Store(true)
			}
			t.advance(stageWroteRequest)
		},
		GotFirstResponseByte: func() {
			t.firstByte.CompareAndSwap(0, int64(time.Since(t.start))+1)
			t.advance(stageGotResponse)
		},
	}
}

// classify возвращает фазу отказа по ошибке RoundTrip.
func (t *phaseTracker) classify(err error, ctxErr error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctxErr, context.DeadlineExceeded) {
		return tgapi.PhaseTimeout
	}
	switch s := stage(t.stage.Load()); {
	case s >= stageWroteHeaders:
		if s == stageWroteHeaders || t.writeErr.Load() {
			return tgapi.PhaseWrite
		}
		return tgapi.PhaseRead
	case s == stageConnected:
		return tgapi.PhasePreSend
	case t.tlsErr.Load():
		return tgapi.PhaseTLS
	default:
		return tgapi.PhaseDial
	}
}

// upstreamMs — время до первого байта ответа Telegram (или до сейчас).
func (t *phaseTracker) upstream() time.Duration {
	if fb := t.firstByte.Load(); fb > 0 {
		return time.Duration(fb - 1)
	}
	return time.Since(t.start)
}

func trackerFrom(ctx context.Context) *phaseTracker {
	t, _ := ctx.Value(trackerKey{}).(*phaseTracker)
	return t
}

// errorHandler — ReverseProxy.ErrorHandler: 502 (504 для timeout) в формате
// Telegram с X-TGP-Source: agent и X-TGP-Error-Phase.
func (a *Agent) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	phase := tgapi.PhaseDial
	t := trackerFrom(r.Context())
	if t != nil {
		phase = t.classify(err, r.Context().Err())
		t.errPhase.Store(&phase)
	}
	a.stats.recordError(phase)
	if phase == tgapi.PhaseDial || phase == tgapi.PhaseTLS ||
		(phase == tgapi.PhaseTimeout && (t == nil || stage(t.stage.Load()) == stageStart)) {
		a.rec.DialError(dialErrorKind(err, phase))
	}
	code := http.StatusBadGateway
	if phase == tgapi.PhaseTimeout {
		code = http.StatusGatewayTimeout
	}
	msg := redact.String(err.Error())
	a.logger.Warn("upstream request failed",
		"request_id", r.Header.Get(tgapi.HeaderRequestID),
		"phase", phase, "err", msg)
	writeAgentError(w, code, phase, "tgproxy: agent "+phase+" error: "+msg)
}
